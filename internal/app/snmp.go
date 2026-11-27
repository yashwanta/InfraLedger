package app

// SNMP network-device inventory and switch topology.
//
// IT Admins can save a read-only SNMP credential (v2c community or v3 user)
// per organization alongside the SSH and WinRM credentials; it is sealed with
// the vault key and never returned to the browser. A background sweep then
// polls every device of that organization that has a private IPv4 address
// inside its documented networks or discovery subnets (the same rule as
// remote inventory). Devices that answer get their name, model, serial and
// device type from SNMP. Switches additionally report their MAC address
// tables and LLDP neighbors, which are used to record which switch port each
// device is plugged into (uplinkAssetId / uplinkPort) and which switches are
// linked to each other (lldpNeighbors). Only GET requests are sent.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	snmpSweepInterval = 6 * time.Hour
	snmpMaxTargets    = 1024
	snmpWorkers       = 24
)

// snmpPoll queries one device; tests replace it.
var snmpPoll = pollSNMP

type snmpCredential struct {
	Version, Community, User, AuthPass, PrivPass string
	Port                                         int
}

type lldpEntry struct {
	LocalPort, RemoteName, RemotePort, RemoteMAC, RemoteIP string
}

type snmpDevice struct {
	SysName, SysDescr, SysObjectID, Location string
	Services                                 int
	Forwarding                               bool
	Model, Serial, Manufacturer              string
	IfNames                                  map[int]string
	MACs                                     []string
	FDB                                      map[string]string // MAC → port name
	FDBPortCount                             map[string]int    // port name → MACs learned
	LLDP                                     []lldpEntry
}

func validateSNMPCredential(input M) (M, M) {
	name := strings.TrimSpace(S(input, "name"))
	if name == "" || len(name) > 120 {
		fail(400, "Enter a credential name of up to 120 characters")
	}
	version := S(input, "snmpVersion")
	if version == "" {
		version = "v2c"
	}
	if version != "v2c" && version != "v3" {
		fail(400, "Choose SNMP v2c or v3")
	}
	port := int(N(input, "port"))
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		fail(400, "Port must be between 1 and 65535")
	}
	config := M{"name": name, "kind": "snmp", "snmpVersion": version, "port": port, "username": ""}
	secret := M{}
	if version == "v2c" {
		if c := S(input, "community"); c != "" {
			if len(c) > 200 || strings.ContainsAny(c, "\r\n") {
				fail(400, "Community string is too long")
			}
			secret["community"] = c
		}
	} else {
		user := strings.TrimSpace(S(input, "username"))
		if user == "" || len(user) > 200 || strings.ContainsAny(user, "\r\n\t") {
			fail(400, "Enter the SNMPv3 user name")
		}
		config["username"] = user
		auth, priv := S(input, "password"), S(input, "privPassword")
		if auth != "" || priv != "" {
			if len(auth) < 8 || len(priv) < 8 || len(auth) > 200 || len(priv) > 200 {
				fail(400, "SNMPv3 authentication and privacy passwords need at least 8 characters")
			}
			secret["password"], secret["privPassword"] = auth, priv
		}
	}
	return config, secret
}

func snmpCredentialFrom(config, secret M) snmpCredential {
	return snmpCredential{Version: S(config, "snmpVersion"), Port: int(N(config, "port")), User: S(config, "username"), Community: S(secret, "community"), AuthPass: S(secret, "password"), PrivPass: S(secret, "privPassword")}
}

// --- sweep scheduling -------------------------------------------------------

func snmpStateKey(org string) string { return "snmp_sweep:" + org }

func (a *App) snmpState(org string) M {
	if r := a.get("SELECT value FROM meta WHERE key=?", snmpStateKey(org)); r != nil {
		return decode(S(r, "value"))
	}
	return M{}
}

func (a *App) setSNMPState(org string, state M) {
	a.run("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", snmpStateKey(org), J(state))
}

// snmpOrgs returns the organizations that have at least one SNMP credential.
func (a *App) snmpOrgs() []string {
	orgs := []string{}
	for _, r := range a.q("SELECT org_id,config FROM remote_credentials ORDER BY created") {
		if S(decode(S(r, "config")), "kind") == "snmp" && !contains(orgs, S(r, "org_id")) {
			orgs = append(orgs, S(r, "org_id"))
		}
	}
	return orgs
}

func (a *App) snmpRoute(req *http.Request, u M, b M, rest string) result {
	switch {
	case rest == "snmp-sweep" && req.Method == "GET":
		rows := []M{}
		for _, org := range a.snmpOrgs() {
			state := a.snmpState(org)
			state["orgId"] = org
			rows = append(rows, state)
		}
		return out(200, rows)
	case rest == "snmp-sweep" && req.Method == "POST":
		requirePage(u, "integrations", "edit")
		org := S(b, "orgId")
		if !contains(a.snmpOrgs(), org) {
			fail(400, "Add an SNMP credential for this organization first")
		}
		state := a.snmpState(org)
		state["requestedAt"] = timestamp()
		a.setSNMPState(org, state)
		a.audit(u, "snmp_sweep_requested", org, "")
		return out(202, M{"status": "Queued", "message": "The SNMP sweep starts within a minute."})
	}
	fail(404, "Route not found")
	return result{}
}

func (a *App) startSNMPSweeps() {
	a.backgroundWG.Add(1)
	go func() {
		defer a.backgroundWG.Done()
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.backgroundCtx.Done():
				return
			case <-ticker.C:
				a.runDueSNMPSweeps()
			}
		}
	}()
}

func (a *App) runDueSNMPSweeps() {
	a.mu.Lock()
	due := []string{}
	for _, org := range a.snmpOrgs() {
		state := a.snmpState(org)
		started, _ := time.Parse(time.RFC3339Nano, S(state, "startedAt"))
		requested, _ := time.Parse(time.RFC3339Nano, S(state, "requestedAt"))
		if requested.After(started) || time.Since(started) >= snmpSweepInterval {
			due = append(due, org)
		}
	}
	a.mu.Unlock()
	for _, org := range due {
		if a.backgroundCtx.Err() != nil {
			return
		}
		a.runSNMPSweep(org)
	}
}

type snmpTarget struct{ AssetID, IP string }

func (a *App) runSNMPSweep(org string) {
	a.mu.Lock()
	state := a.snmpState(org)
	state["startedAt"] = timestamp()
	state["status"] = "Running"
	a.setSNMPState(org, state)
	credentials, targets, actor, setupErr := a.snmpSweepSetup(org)
	a.mu.Unlock()
	a.broadcast()
	finish := func(summary M) {
		a.mu.Lock()
		state := a.snmpState(org)
		state["status"], state["finishedAt"], state["summary"] = "Completed", timestamp(), summary
		if S(summary, "error") != "" {
			state["status"] = "Error"
		}
		a.setSNMPState(org, state)
		a.mu.Unlock()
		a.broadcast()
	}
	if setupErr != nil {
		finish(M{"error": setupErr.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 15*time.Minute)
	results := pollTargets(ctx, targets, credentials)
	cancel()
	if a.backgroundCtx.Err() != nil {
		return
	}
	var summary M
	err := func() (err error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		defer func() {
			if p := recover(); p != nil {
				a.db.Exec("ROLLBACK")
				err = fmt.Errorf("SNMP results could not be saved")
				if e, ok := p.(apiError); ok {
					err = fmt.Errorf("%s", e.Message)
				}
			}
		}()
		a.run("BEGIN IMMEDIATE")
		summary = a.applySNMPResults(org, actor, results)
		summary["targets"] = len(targets)
		a.audit(nil, "snmp_sweep_completed", org, fmt.Sprintf("%v of %d devices answered", summary["responded"], len(targets)))
		a.run("COMMIT")
		return nil
	}()
	if err != nil {
		finish(M{"error": err.Error(), "targets": len(targets)})
		return
	}
	finish(summary)
}

func (a *App) snmpSweepSetup(org string) (creds []snmpCredential, targets []snmpTarget, actor M, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.New("Saved SNMP credential could not be opened")
		}
	}()
	for _, r := range a.q("SELECT * FROM remote_credentials WHERE org_id=? ORDER BY created", org) {
		config := decode(S(r, "config"))
		if S(config, "kind") != "snmp" {
			continue
		}
		if actor == nil {
			actor = a.get("SELECT * FROM users WHERE id=? AND role='admin' AND active=1", r["user_id"])
		}
		creds = append(creds, snmpCredentialFrom(config, obj(a.unseal(S(r, "sealed")))))
	}
	if len(creds) == 0 {
		return nil, nil, nil, errors.New("No SNMP credential is saved for this organization")
	}
	if actor == nil {
		return nil, nil, nil, errors.New("The admin who saved the SNMP credential is no longer active. Save it again")
	}
	actor = clone(actor)
	actor["name"] = "SNMP inventory"
	for _, r := range a.q("SELECT id,data FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", org) {
		ip := S(decode(S(r, "data")), "ip")
		if ip != "" && a.remoteTargetAllowed(org, ip) == nil {
			targets = append(targets, snmpTarget{AssetID: S(r, "id"), IP: ip})
		}
		if len(targets) >= snmpMaxTargets {
			break
		}
	}
	return creds, targets, actor, nil
}

func pollTargets(ctx context.Context, targets []snmpTarget, creds []snmpCredential) map[string]*snmpDevice {
	results := map[string]*snmpDevice{}
	var mutex sync.Mutex
	jobs := make(chan snmpTarget)
	var workers sync.WaitGroup
	for n := 0; n < snmpWorkers; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range jobs {
				for _, c := range creds {
					if ctx.Err() != nil {
						break
					}
					if device, err := snmpPoll(ctx, t.IP, c); err == nil {
						mutex.Lock()
						results[t.AssetID] = device
						mutex.Unlock()
						break
					}
				}
			}
		}()
	}
	for _, t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

// --- SNMP polling -------------------------------------------------------------

const (
	oidSysDescr      = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID   = ".1.3.6.1.2.1.1.2.0"
	oidSysName       = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation   = ".1.3.6.1.2.1.1.6.0"
	oidSysServices   = ".1.3.6.1.2.1.1.7.0"
	oidIPForwarding  = ".1.3.6.1.2.1.4.1.0"
	oidIfDescr       = ".1.3.6.1.2.1.2.2.1.2"
	oidIfPhysAddress = ".1.3.6.1.2.1.2.2.1.6"
	oidIfName        = ".1.3.6.1.2.1.31.1.1.1.1"
	oidEntModel      = ".1.3.6.1.2.1.47.1.1.1.1.13"
	oidEntSerial     = ".1.3.6.1.2.1.47.1.1.1.1.11"
	oidEntMfg        = ".1.3.6.1.2.1.47.1.1.1.1.12"
	oidBridgeIfIndex = ".1.3.6.1.2.1.17.1.4.1.2"
	oidFdbPort       = ".1.3.6.1.2.1.17.4.3.1.2"
	oidQFdbPort      = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidLldpLocPortID = ".1.0.8802.1.1.2.1.3.7.1.3"
	oidLldpLocDesc   = ".1.0.8802.1.1.2.1.3.7.1.4"
	oidLldpChassis   = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLldpChassisTy = ".1.0.8802.1.1.2.1.4.1.1.4"
	oidLldpPortID    = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpSysName   = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLldpManAddr   = ".1.0.8802.1.1.2.1.4.2.1.3"
)

var errWalkLimit = errors.New("walk limit reached")

func pollSNMP(ctx context.Context, ip string, c snmpCredential) (*snmpDevice, error) {
	client := &gosnmp.GoSNMP{Target: ip, Port: uint16(c.Port), Transport: "udp", Context: ctx, Timeout: 1500 * time.Millisecond, Retries: 1, MaxOids: 8, MaxRepetitions: 25}
	if c.Version == "v3" {
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = gosnmp.AuthPriv
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: c.User, AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: c.AuthPass, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: c.PrivPass}
	} else {
		client.Version = gosnmp.Version2c
		client.Community = c.Community
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Conn.Close()
	system, err := client.Get([]string{oidSysDescr, oidSysObjectID, oidSysName, oidSysLocation, oidSysServices, oidIPForwarding})
	if err != nil {
		return nil, err
	}
	d := &snmpDevice{IfNames: map[int]string{}, FDB: map[string]string{}, FDBPortCount: map[string]int{}}
	for _, v := range system.Variables {
		switch v.Name {
		case oidSysDescr:
			d.SysDescr = snmpClip(snmpString(v), 500)
		case oidSysObjectID:
			d.SysObjectID = snmpClip(snmpString(v), 200)
		case oidSysName:
			d.SysName = snmpClip(snmpString(v), 180)
		case oidSysLocation:
			d.Location = snmpClip(snmpString(v), 200)
		case oidSysServices:
			d.Services = int(gosnmp.ToBigInt(v.Value).Int64())
		case oidIPForwarding:
			d.Forwarding = gosnmp.ToBigInt(v.Value).Int64() == 1
		}
	}
	if d.SysDescr == "" && d.SysName == "" && d.SysObjectID == "" {
		return nil, errors.New("no system information")
	}
	walk := func(root string, limit int, fn func(suffix string, v gosnmp.SnmpPDU)) {
		count := 0
		_ = client.BulkWalk(root, func(v gosnmp.SnmpPDU) error {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.EndOfMibView {
				return nil
			}
			fn(strings.TrimPrefix(strings.TrimPrefix(v.Name, root), "."), v)
			if count++; count >= limit {
				return errWalkLimit
			}
			return nil
		})
	}
	walk(oidIfName, 4096, func(s string, v gosnmp.SnmpPDU) {
		if i, err := strconv.Atoi(s); err == nil {
			d.IfNames[i] = snmpClip(snmpString(v), 100)
		}
	})
	if len(d.IfNames) == 0 {
		walk(oidIfDescr, 4096, func(s string, v gosnmp.SnmpPDU) {
			if i, err := strconv.Atoi(s); err == nil {
				d.IfNames[i] = snmpClip(snmpString(v), 100)
			}
		})
	}
	walk(oidIfPhysAddress, 4096, func(_ string, v gosnmp.SnmpPDU) {
		if b, ok := v.Value.([]byte); ok && len(b) == 6 {
			if mac := net.HardwareAddr(b).String(); mac != "00:00:00:00:00:00" && !contains(d.MACs, mac) {
				d.MACs = append(d.MACs, mac)
			}
		}
	})
	models, serials, makers := map[int]string{}, map[int]string{}, map[int]string{}
	for root, target := range map[string]map[int]string{oidEntModel: models, oidEntSerial: serials, oidEntMfg: makers} {
		walk(root, 64, func(s string, v gosnmp.SnmpPDU) {
			if i, err := strconv.Atoi(s); err == nil && strings.TrimSpace(snmpString(v)) != "" {
				target[i] = snmpClip(strings.TrimSpace(snmpString(v)), 120)
			}
		})
	}
	indexes := []int{}
	for i := range models {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	if len(indexes) > 0 {
		d.Model, d.Serial, d.Manufacturer = models[indexes[0]], serials[indexes[0]], makers[indexes[0]]
	}
	// Bridge MAC table: bridge port → ifIndex → interface name.
	bridgeIf := map[string]int{}
	walk(oidBridgeIfIndex, 4096, func(s string, v gosnmp.SnmpPDU) { bridgeIf[s] = int(gosnmp.ToBigInt(v.Value).Int64()) })
	portName := func(bridgePort string) string {
		if bridgePort == "0" {
			return ""
		}
		if name := d.IfNames[bridgeIf[bridgePort]]; name != "" {
			return name
		}
		return "Bridge port " + bridgePort
	}
	learn := func(macSuffix string, v gosnmp.SnmpPDU) {
		parts := strings.Split(macSuffix, ".")
		if len(parts) < 6 {
			return
		}
		b := make([]byte, 6)
		for i, p := range parts[len(parts)-6:] {
			n, err := strconv.Atoi(p)
			if err != nil || n > 255 {
				return
			}
			b[i] = byte(n)
		}
		name := portName(gosnmp.ToBigInt(v.Value).String())
		mac := net.HardwareAddr(b).String()
		if name == "" || d.FDB[mac] != "" {
			return
		}
		d.FDB[mac] = name
		d.FDBPortCount[name]++
	}
	walk(oidFdbPort, 16384, learn)
	if len(d.FDB) == 0 {
		walk(oidQFdbPort, 16384, learn)
	}
	// LLDP neighbors, indexed by timeMark.localPortNum.remIndex.
	localPorts := map[string]string{}
	walk(oidLldpLocDesc, 1024, func(s string, v gosnmp.SnmpPDU) { localPorts[s] = snmpClip(snmpString(v), 100) })
	walk(oidLldpLocPortID, 1024, func(s string, v gosnmp.SnmpPDU) {
		if localPorts[s] == "" {
			localPorts[s] = snmpClip(snmpString(v), 100)
		}
	})
	neighbors := map[string]*lldpEntry{}
	entry := func(s string) *lldpEntry {
		parts := strings.Split(s, ".")
		if len(parts) < 3 {
			return nil
		}
		key := strings.Join(parts[:3], ".")
		if neighbors[key] == nil {
			if len(neighbors) >= 512 {
				return nil
			}
			neighbors[key] = &lldpEntry{LocalPort: localPorts[parts[1]]}
			if neighbors[key].LocalPort == "" {
				neighbors[key].LocalPort = "Port " + parts[1]
			}
		}
		return neighbors[key]
	}
	chassisType := map[string]int64{}
	walk(oidLldpChassisTy, 512, func(s string, v gosnmp.SnmpPDU) { chassisType[s] = gosnmp.ToBigInt(v.Value).Int64() })
	walk(oidLldpChassis, 512, func(s string, v gosnmp.SnmpPDU) {
		if b, ok := v.Value.([]byte); ok && len(b) == 6 && chassisType[s] == 4 {
			if e := entry(s); e != nil {
				e.RemoteMAC = net.HardwareAddr(b).String()
			}
		}
	})
	walk(oidLldpSysName, 512, func(s string, v gosnmp.SnmpPDU) {
		if e := entry(s); e != nil {
			e.RemoteName = snmpClip(snmpString(v), 180)
		}
	})
	walk(oidLldpPortID, 512, func(s string, v gosnmp.SnmpPDU) {
		if e := entry(s); e != nil {
			e.RemotePort = snmpClip(snmpString(v), 100)
		}
	})
	// lldpRemManAddrTable index: timeMark.localPort.remIndex.addrSubtype.addrLen.address…
	walk(oidLldpManAddr, 512, func(s string, _ gosnmp.SnmpPDU) {
		parts := strings.Split(s, ".")
		if len(parts) == 9 && parts[3] == "1" && parts[4] == "4" {
			if e := entry(s); e != nil && e.RemoteIP == "" {
				e.RemoteIP = strings.Join(parts[5:9], ".")
			}
		}
	})
	for _, e := range neighbors {
		d.LLDP = append(d.LLDP, *e)
	}
	sort.Slice(d.LLDP, func(i, j int) bool { return d.LLDP[i].LocalPort < d.LLDP[j].LocalPort })
	return d, nil
}

func snmpString(v gosnmp.SnmpPDU) string {
	switch value := v.Value.(type) {
	case []byte:
		if len(value) == 6 && v.Name != "" && strings.Contains(v.Name, oidIfPhysAddress) {
			return net.HardwareAddr(value).String()
		}
		return strings.TrimRight(string(value), "\x00")
	case string:
		return value
	case nil:
		return ""
	default:
		return fmt.Sprint(value)
	}
}

func snmpClip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return ' '
		}
		return r
	}, s))
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --- classification and topology ---------------------------------------------

// enterpriseVendors maps the IANA private enterprise number in sysObjectID to a vendor.
var enterpriseVendors = map[string]string{"9": "Cisco", "2636": "Juniper Networks", "14988": "MikroTik", "41112": "Ubiquiti", "11": "HP", "12356": "Fortinet", "25461": "Palo Alto Networks", "8741": "SonicWall", "11863": "TP-Link", "4526": "NETGEAR", "171": "D-Link", "890": "Zyxel", "6574": "Synology", "24681": "QNAP", "674": "Dell", "2011": "Huawei", "30065": "Arista", "1916": "Extreme Networks", "14823": "Aruba", "25053": "Ruckus", "6876": "VMware", "3375": "F5"}

func enterpriseVendor(objectID string) string {
	parts := strings.Split(strings.TrimPrefix(objectID, "."), ".")
	if len(parts) > 6 && strings.Join(parts[:6], ".") == "1.3.6.1.4.1" {
		return enterpriseVendors[parts[6]]
	}
	return ""
}

// snmpCategory infers a device type from what the device reported about itself.
func snmpCategory(d *snmpDevice) (string, string) {
	text := strings.ToLower(d.SysDescr + " " + d.Model)
	vendor := enterpriseVendor(d.SysObjectID)
	switch {
	case strings.Contains(text, "printer") || strings.Contains(text, "laserjet") || strings.Contains(text, "jetdirect"):
		return "Printer", "SNMP system description identifies a printer"
	case contains([]string{"Fortinet", "Palo Alto Networks", "SonicWall"}, vendor) || strings.Contains(text, "pfsense") || strings.Contains(text, "opnsense") || strings.Contains(text, "fortigate"):
		return "Firewall", "SNMP identifies a firewall platform"
	case strings.Contains(text, "access point") || strings.Contains(text, "aironet") || strings.Contains(text, "uap") || strings.Contains(text, "wireless"):
		return "Access point", "SNMP system description identifies a wireless access point"
	case contains([]string{"Synology", "QNAP"}, vendor):
		return "Storage", "SNMP identifies a network storage system"
	}
	layer2, layer3 := d.Services&2 != 0, d.Services&4 != 0
	ports := 0
	for _, name := range d.IfNames {
		if !strings.Contains(strings.ToLower(name), "vlan") && !strings.HasPrefix(strings.ToLower(name), "lo") {
			ports++
		}
	}
	switch {
	case len(d.FDB) > 0 && (layer2 || ports > 8):
		return "Switch", fmt.Sprintf("SNMP bridge table with %d learned MAC addresses", len(d.FDB))
	case d.Forwarding && (layer3 || vendor != "") && !strings.Contains(text, "windows") && !strings.Contains(text, "linux"):
		return "Router", "SNMP reports IP forwarding enabled"
	case vendor != "" && contains(networkOnlyVendors, vendor):
		return "Network device", "SNMP enterprise ID registered to " + vendor
	}
	return "", ""
}

func (a *App) applySNMPResults(org string, actor M, results map[string]*snmpDevice) M {
	observed := timestamp()
	records := map[string]M{}
	data := map[string]M{}
	for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", org) {
		records[S(r, "id")] = r
		data[S(r, "id")] = decode(S(r, "data"))
	}
	before := map[string]string{}
	for id, d := range data {
		before[id] = J(d)
	}
	// Identity facts for every device that answered.
	for id, dev := range results {
		d := data[id]
		if d == nil {
			continue
		}
		d["lastSeen"] = observed
		d["snmpSysName"], d["snmpSysDescr"], d["snmpSysObjectId"], d["snmpLocation"] = dev.SysName, dev.SysDescr, dev.SysObjectID, dev.Location
		d["identityConfidence"] = "Authenticated SNMP inventory"
		if dev.Model != "" && (S(d, "model") == "" || d["modelFromSNMP"] == true) {
			d["model"], d["modelFromSNMP"] = dev.Model, true
		}
		if dev.Serial != "" && (S(d, "serial") == "" || d["serialFromSNMP"] == true) {
			d["serial"], d["serialFromSNMP"] = dev.Serial, true
		}
		maker := dev.Manufacturer
		if maker == "" {
			maker = enterpriseVendor(dev.SysObjectID)
		}
		if maker != "" && (S(d, "manufacturer") == "" || d["manufacturerFromMAC"] == true) {
			d["manufacturer"] = shortVendor(maker)
			delete(d, "manufacturerFromMAC")
		}
		if category, evidence := snmpCategory(dev); category != "" {
			classify(d, category, evidence)
		}
		if dev.SysName != "" && d["autoDiscovered"] == true && (S(d, "name") == S(d, "ip") || S(d, "name") == "") {
			d["name"] = dev.SysName
		}
		addEvidence(d, "SNMP sysDescr: "+snmpClip(dev.SysDescr, 200))
	}
	// Lookup tables for matching what switches report to documented devices.
	byMAC, byIP, byName := map[string]string{}, map[string]string{}, map[string]string{}
	for id, d := range data {
		if mac := normalMAC(S(d, "mac")); mac != "" {
			byMAC[mac] = id
		}
		if ip := S(d, "ip"); ip != "" {
			byIP[ip] = id
		}
		for _, n := range []string{S(d, "snmpSysName"), S(d, "name"), S(d, "observedHostname")} {
			if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
				if short, _, _ := strings.Cut(n, "."); byName[short] == "" {
					byName[short] = id
				}
			}
		}
	}
	for id, dev := range results {
		for _, mac := range dev.MACs {
			if byMAC[mac] == "" {
				byMAC[mac] = id
			}
		}
	}
	links, uplinks := 0, 0
	infraPorts := map[string]bool{} // switchID|port carrying an LLDP link
	for id, dev := range results {
		neighbors := []any{}
		for _, n := range dev.LLDP {
			target := byIP[n.RemoteIP]
			if target == "" {
				target = byMAC[normalMAC(n.RemoteMAC)]
			}
			if target == "" && n.RemoteName != "" {
				short, _, _ := strings.Cut(strings.ToLower(n.RemoteName), ".")
				target = byName[short]
			}
			if target == "" || target == id {
				continue
			}
			infraPorts[id+"|"+n.LocalPort] = true
			neighbors = append(neighbors, M{"assetId": target, "localPort": n.LocalPort, "remotePort": n.RemotePort, "remoteName": n.RemoteName})
			links++
		}
		if data[id] != nil {
			if len(neighbors) > 0 {
				data[id]["lldpNeighbors"] = neighbors
			} else {
				delete(data[id], "lldpNeighbors")
			}
		}
	}
	// Attach each device to the switch port where its MAC is learned with the
	// fewest other MACs: an access port, not an uplink that carries everyone.
	type seen struct {
		switchID, port string
		count          int
	}
	best := map[string]seen{}
	for id, dev := range results {
		for mac, port := range dev.FDB {
			owner := byMAC[mac]
			if owner == "" || owner == id || infraPorts[id+"|"+port] {
				continue
			}
			candidate := seen{id, port, dev.FDBPortCount[port]}
			if current, ok := best[owner]; !ok || candidate.count < current.count || candidate.count == current.count && candidate.switchID < current.switchID {
				best[owner] = candidate
			}
		}
	}
	for owner, s := range best {
		d := data[owner]
		d["uplinkAssetId"], d["uplinkPort"], d["uplinkSource"] = s.switchID, s.port, "Switch MAC table"
		uplinks++
	}
	updated := 0
	for id, d := range data {
		if J(d) == before[id] {
			continue
		}
		d["version"] = records[id]["version"]
		a.observedUpdate(actor, records[id], d)
		updated++
	}
	return M{"responded": len(results), "updated": updated, "switchLinks": links, "devicesPlaced": uplinks}
}

func normalMAC(mac string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}
