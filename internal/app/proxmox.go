package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var pveTokenID = regexp.MustCompile(`^[^\s=!]+@[^\s=!]+![A-Za-z0-9._-]+$`)
var pveNodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func validateProxmoxConfig(input M) M {
	endpoint, e := url.Parse(strings.TrimRight(strings.TrimSpace(S(input, "url")), "/"))
	if e != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
		fail(400, "Use a Proxmox HTTPS base URL, such as https://10.20.30.120:8006, without credentials or a path")
	}
	if !pveTokenID.MatchString(S(input, "tokenId")) || len(S(input, "tokenId")) > 200 {
		fail(400, "Token ID must use user@realm!token-name format")
	}
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(S(input, "fingerprint")), ":", ""))
	if pin != "" {
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != 32 {
			fail(400, "Certificate fingerprint must be a SHA-256 fingerprint (64 hexadecimal characters)")
		}
	}
	ca := S(input, "caPEM")
	if len(ca) > 65536 {
		fail(400, "CA certificate is too large")
	}
	if ca != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			fail(400, "Enter a PEM-encoded CA certificate")
		}
	}
	interval := int(N(input, "intervalSeconds"))
	if interval == 0 {
		interval = 300
	}
	if interval < 60 || interval > 86400 {
		fail(400, "Sync interval must be between 60 and 86400 seconds")
	}
	name := strings.TrimSpace(S(input, "name"))
	if name == "" || len(name) > 120 {
		fail(400, "Enter a connection name of up to 120 characters")
	}
	return M{"name": name, "url": endpoint.String(), "tokenId": S(input, "tokenId"), "fingerprint": pin, "caPEM": ca, "intervalSeconds": interval, "enabled": input["enabled"] != false, "hostAssetId": S(input, "hostAssetId")}
}

func publicProxmox(r M) M {
	config := decode(S(r, "config"))
	config["id"] = r["id"]
	config["orgId"] = r["org_id"]
	config["hasToken"] = S(r, "sealed") != ""
	config["status"] = r["status"]
	config["lastSync"] = r["last_sync"]
	config["summary"] = decode(S(r, "summary"))
	return config
}

func (a *App) proxmoxRoute(req *http.Request, u, b M) result {
	requirePage(u, "integrations", "view")
	if S(u, "role") != "admin" {
		fail(403, "IT Admin manages Proxmox connections")
	}
	rest := strings.Trim(strings.TrimPrefix(req.URL.Path, "/api/integrations/proxmox"), "/")
	parts := strings.Split(rest, "/")
	if rest == "" && req.Method == "GET" {
		rows := []M{}
		for _, r := range a.q("SELECT * FROM proxmox_connections ORDER BY created") {
			rows = append(rows, publicProxmox(r))
		}
		return out(200, rows)
	}
	if rest == "" && req.Method == "POST" || rest != "" && len(parts) == 1 && req.Method == "PUT" {
		requirePage(u, "integrations", "edit")
		previous := M(nil)
		connectionID := id()
		if rest != "" {
			previous = a.get("SELECT * FROM proxmox_connections WHERE id=?", rest)
			if previous == nil {
				fail(404, "Connection not found")
			}
			connectionID = rest
		}
		org := S(b, "orgId")
		if a.get("SELECT id FROM records WHERE id=? AND type='organizations' AND deleted IS NULL", org) == nil {
			fail(400, "Select an organization")
		}
		if previous != nil && S(previous, "org_id") != org {
			fail(400, "A connection's organization cannot be changed; create a separate connection")
		}
		config := validateProxmoxConfig(b)
		if S(config, "hostAssetId") != "" {
			a.sameOrg(S(config, "hostAssetId"), org, "assets")
		}
		secret := strings.TrimSpace(S(b, "tokenSecret"))
		sealed := ""
		if previous != nil {
			sealed = S(previous, "sealed")
		}
		if secret != "" {
			if len(secret) > 500 || strings.ContainsAny(secret, "\r\n\t ") {
				fail(400, "Invalid API token secret")
			}
			sealed = a.seal(M{"secret": secret})
		}
		if sealed == "" {
			fail(400, "Enter the Proxmox API token secret")
		}
		if previous != nil && secret == "" {
			old := decode(S(previous, "config"))
			if S(old, "url") != S(config, "url") || S(old, "tokenId") != S(config, "tokenId") {
				fail(400, "Re-enter the token secret when changing endpoint or token identity")
			}
		}
		status := "Queued"
		if config["enabled"] == false {
			status = "Paused"
		}
		if previous == nil {
			a.run("INSERT INTO proxmox_connections(id,org_id,user_id,config,sealed,status,created) VALUES(?,?,?,?,?,?,?)", connectionID, org, u["id"], J(config), sealed, status, timestamp())
		} else {
			a.run("UPDATE proxmox_connections SET user_id=?,config=?,sealed=?,status=?,next_run=0,revision=revision+1 WHERE id=?", u["id"], J(config), sealed, status, connectionID)
		}
		a.audit(u, "proxmox_configured", connectionID, "Read-only Proxmox inventory connection")
		return out(200, publicProxmox(a.get("SELECT * FROM proxmox_connections WHERE id=?", connectionID)))
	}
	r := a.get("SELECT * FROM proxmox_connections WHERE id=?", parts[0])
	if r == nil {
		fail(404, "Connection not found")
	}
	if len(parts) == 2 && parts[1] == "sync" && req.Method == "POST" {
		requirePage(u, "integrations", "edit")
		if decode(S(r, "config"))["enabled"] == false {
			fail(409, "Resume the connection before syncing")
		}
		a.run("UPDATE proxmox_connections SET next_run=0,status='Queued',revision=revision+1 WHERE id=?", r["id"])
		a.audit(u, "proxmox_sync_requested", S(r, "id"), "")
		return out(202, M{"queued": true})
	}
	if len(parts) == 1 && req.Method == "DELETE" {
		requirePage(u, "integrations", "edit")
		a.run("DELETE FROM proxmox_connections WHERE id=?", r["id"])
		a.audit(u, "proxmox_disconnected", S(r, "id"), "Saved credentials removed; imported documentation retained")
		return out(200, M{"ok": true})
	}
	fail(404, "Route not found")
	return result{}
}

func proxmoxHTTPClient(config M) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := S(config, "caPEM"); ca != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, fmt.Errorf("Invalid CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if pin := S(config, "fingerprint"); pin != "" {
		expected, err := hex.DecodeString(pin)
		if err != nil || len(expected) != 32 {
			return nil, fmt.Errorf("Invalid certificate fingerprint")
		}
		// Exact certificate pinning replaces CA/hostname trust; identity is still
		// verified before any token is transmitted. There is no accept-any-cert mode.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("No server certificate")
			}
			cert := state.PeerCertificates[0]
			digest := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
				return fmt.Errorf("Certificate fingerprint mismatch")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return fmt.Errorf("Pinned certificate is outside its validity period")
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type proxmoxInventory struct {
	Resources []M
	Configs   map[string]M
	// Agents holds read-only QEMU guest agent observations keyed like Configs.
	Agents   map[string]M
	Warnings []string
}

// proxmoxAgentEnabled reports whether a QEMU config enables the guest agent
// ("agent: 1" or "agent: enabled=1,…").
func proxmoxAgentEnabled(details M) bool {
	value := strings.TrimSpace(fmt.Sprint(details["agent"]))
	if value == "" || value == "<nil>" {
		return false
	}
	first := strings.Split(value, ",")[0]
	return first == "1" || first == "enabled=1" || strings.Contains(value, "enabled=1")
}

// parseAgentInterfaces turns a network-get-interfaces result into interfaces and
// usable IPv4 addresses (loopback and link-local excluded).
func parseAgentInterfaces(value any) ([]M, []string) {
	interfaces, addresses := []M{}, []string{}
	for _, raw := range anyList(obj(value)["result"]) {
		item := obj(raw)
		name := S(item, "name")
		if name == "" || name == "lo" || strings.HasPrefix(strings.ToLower(name), "loopback") {
			continue
		}
		ips := []string{}
		for _, rawIP := range anyList(item["ip-addresses"]) {
			ip := obj(rawIP)
			if S(ip, "ip-address-type") != "ipv4" {
				continue
			}
			addr, err := netip.ParseAddr(S(ip, "ip-address"))
			if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
				continue
			}
			ips = append(ips, addr.String())
			if len(addresses) < 32 {
				addresses = append(addresses, addr.String())
			}
		}
		if len(interfaces) < 32 {
			interfaces = append(interfaces, M{"name": truncate(name, 80), "mac": truncate(S(item, "hardware-address"), 40), "addresses": ips})
		}
	}
	return interfaces, addresses
}

func anyList(value any) []any {
	if list, ok := value.([]any); ok {
		return list
	}
	return nil
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func fetchProxmox(ctx context.Context, config M, secret string) (proxmoxInventory, error) {
	inventory := proxmoxInventory{Configs: map[string]M{}, Agents: map[string]M{}, Warnings: []string{}}
	client, err := proxmoxHTTPClient(config)
	if err != nil {
		return inventory, err
	}
	defer client.CloseIdleConnections()
	getStatus := func(path string) (any, int, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", S(config, "url")+"/api2/json"+path, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("Invalid Proxmox endpoint")
		}
		req.Header.Set("Authorization", "PVEAPIToken="+S(config, "tokenId")+"="+secret)
		response, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("Cannot connect to Proxmox. Check network access, HTTPS certificate trust or fingerprint, and endpoint availability")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			if response.StatusCode == 401 || response.StatusCode == 403 {
				return nil, response.StatusCode, fmt.Errorf("Proxmox denied read access. Check token validity and PVEAuditor permissions for both the user and token")
			}
			return nil, response.StatusCode, fmt.Errorf("Proxmox returned HTTP %d", response.StatusCode)
		}
		var envelope M
		if err = json.NewDecoder(io.LimitReader(response.Body, 8*1024*1024)).Decode(&envelope); err != nil {
			return nil, 200, fmt.Errorf("Proxmox returned an invalid inventory response")
		}
		return envelope["data"], 200, nil
	}
	get := func(path string) (any, error) {
		data, _, err := getStatus(path)
		return data, err
	}
	data, err := get("/cluster/resources")
	if err != nil {
		return inventory, err
	}
	resources, ok := data.([]any)
	if !ok || len(resources) > 10000 {
		return inventory, fmt.Errorf("Invalid or oversized Proxmox resource list")
	}
	guests := []M{}
	for _, value := range resources {
		r := obj(value)
		kind := S(r, "type")
		if kind != "node" && kind != "qemu" && kind != "lxc" {
			continue
		}
		if !pveNodeName.MatchString(S(r, "node")) {
			return inventory, fmt.Errorf("Invalid Proxmox node name")
		}
		if kind != "node" {
			vmid := N(r, "vmid")
			if vmid < 1 || vmid != float64(int(vmid)) {
				return inventory, fmt.Errorf("Invalid Proxmox VM identifier")
			}
			guests = append(guests, r)
		}
		inventory.Resources = append(inventory.Resources, r)
	}
	// Bounded details fetch: every guest remains in inventory even when its config
	// is unavailable; never invent an OS or IP from a name or VM number.
	failures := 0
	for _, guest := range guests {
		if ctx.Err() != nil {
			failures++
			continue
		}
		path := "/nodes/" + S(guest, "node") + "/" + S(guest, "type") + "/" + strconv.Itoa(int(N(guest, "vmid"))) + "/config"
		value, e := get(path)
		if e != nil {
			failures++
			continue
		}
		inventory.Configs[S(guest, "type")+"/"+strconv.Itoa(int(N(guest, "vmid")))] = obj(value)
	}
	if failures > 0 {
		inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("Configuration details unavailable for %d guests; their inventory entries are still imported", failures))
	}
	// QEMU guest agent: live IPs, OS release and hostname reported by the running
	// guest. Read-only GET calls; any failure leaves the guest's other data intact.
	agentDenied, agentSilent := false, 0
	for _, guest := range guests {
		if agentDenied || ctx.Err() != nil {
			break
		}
		key := S(guest, "type") + "/" + strconv.Itoa(int(N(guest, "vmid")))
		details, ok := inventory.Configs[key]
		if S(guest, "type") != "qemu" || S(guest, "status") != "running" || N(guest, "template") == 1 || !ok || !proxmoxAgentEnabled(details) {
			continue
		}
		base := "/nodes/" + S(guest, "node") + "/qemu/" + strconv.Itoa(int(N(guest, "vmid"))) + "/agent/"
		networks, status, e := getStatus(base + "network-get-interfaces")
		if status == 401 || status == 403 {
			agentDenied = true
			break
		}
		if e != nil {
			agentSilent++
			inventory.Agents[key] = M{"status": "Not responding"}
			continue
		}
		interfaces, addresses := parseAgentInterfaces(networks)
		observation := M{"status": "Running", "interfaces": interfaces, "addresses": addresses}
		if info, err := get(base + "get-osinfo"); err == nil {
			result := obj(obj(info)["result"])
			observation["osName"] = truncate(firstNonEmpty(S(result, "pretty-name"), S(result, "name")), 120)
			observation["osVersion"] = truncate(S(result, "version"), 80)
			observation["kernel"] = truncate(S(result, "kernel-release"), 80)
			observation["osId"] = truncate(S(result, "id"), 40)
		}
		if host, err := get(base + "get-host-name"); err == nil {
			observation["hostname"] = truncate(S(obj(obj(host)["result"]), "host-name"), 120)
		}
		inventory.Agents[key] = observation
	}
	if agentDenied {
		inventory.Warnings = append(inventory.Warnings, "Guest agent details need an extra read permission: VM.GuestAgent.Audit (Proxmox VE 9) or VM.Monitor (Proxmox VE 8) on the token. Other inventory was imported")
	}
	if agentSilent > 0 {
		inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("QEMU guest agent enabled but not responding in %d running VMs; install or start qemu-guest-agent inside those guests", agentSilent))
	}
	inventory.Warnings = append(inventory.Warnings, "Only resources visible to this token are returned. Use cluster-wide read-only permissions to include all nodes and guests.")
	return inventory, nil
}

func proxmoxGuestOS(config M, kind string) string {
	value := strings.ToLower(S(config, "ostype"))
	if strings.HasPrefix(value, "win") {
		return "Windows"
	}
	if value == "l26" || value == "l24" || contains([]string{"debian", "ubuntu", "centos", "alpine", "archlinux", "fedora", "opensuse", "gentoo", "nixos", "rocky", "almalinux", "devuan", "amazonlinux"}, value) {
		return "Linux"
	}
	if kind == "lxc" && value != "" && value != "unmanaged" {
		return "Linux"
	}
	return ""
}

func (a *App) importProxmox(connection M, inventory proxmoxInventory) M {
	org, cid := S(connection, "org_id"), S(connection, "id")
	seen := timestamp()
	actor := M{"role": "admin", "name": "Proxmox inventory"}
	config := decode(S(connection, "config"))
	existing := map[string]M{}
	assets := a.q("SELECT * FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", org)
	for _, r := range assets {
		d := decode(S(r, "data"))
		if S(d, "proxmoxConnectionId") == cid {
			existing[S(d, "proxmoxKey")] = r
		}
	}
	upsert := func(key string, fields M, reuse M) M {
		raw := existing[key]
		if raw == nil {
			raw = reuse
		}
		fields["orgId"] = org
		fields["proxmoxConnectionId"] = cid
		fields["proxmoxKey"] = key
		fields["lastSeen"] = seen
		fields["inventoryState"] = "Reported by Proxmox"
		fields["discoverySource"] = "Proxmox authenticated API"
		fields["identityConfidence"] = "Authenticated Proxmox inventory"
		if raw != nil {
			d := decode(S(raw, "data"))
			for k, v := range fields {
				d[k] = v
			}
			return a.observedUpdate(actor, raw, d)
		}
		fields["visibility"] = "internal"
		fields["autoDiscovered"] = true
		return a.insert(actor, "assets", fields)
	}
	hosts := map[string]M{}
	nodes := map[string]M{}
	for _, r := range inventory.Resources {
		node := S(r, "node")
		if _, ok := nodes[node]; !ok {
			nodes[node] = M{"node": node, "status": "Unknown"}
		}
		if S(r, "type") == "node" {
			nodes[node] = r
		}
	}
	for node, r := range nodes {
		var reuse M
		for _, asset := range assets {
			d := decode(S(asset, "data"))
			bound := S(d, "proxmoxConnectionId")
			if bound != "" && bound != cid {
				continue
			}
			if S(d, "proxmoxVMID") != "" {
				continue
			}
			if strings.EqualFold(S(d, "observedHostname"), node) || strings.EqualFold(strings.Split(S(d, "name"), " — ")[0], node) {
				reuse = asset
				break
			}
		}
		if reuse == nil && len(nodes) == 1 && S(config, "hostAssetId") != "" {
			reuse = a.get("SELECT * FROM records WHERE id=? AND type='assets' AND org_id=? AND deleted IS NULL", config["hostAssetId"], org)
		}
		fields := M{"name": node, "category": "Server", "os": "Linux", "platform": "Proxmox VE", "proxmoxNode": node, "status": S(r, "status"), "serverCandidate": false}
		if reuse != nil {
			fields["name"] = decode(S(reuse, "data"))["name"]
		}
		hosts[node] = upsert("node/"+node, fields, reuse)
	}
	count, templates := 0, 0
	seenGuests := map[string]bool{}
	for _, guest := range inventory.Resources {
		kind := S(guest, "type")
		if kind != "qemu" && kind != "lxc" {
			continue
		}
		vmid := strconv.Itoa(int(N(guest, "vmid")))
		key := kind + "/" + vmid
		seenGuests[key] = true
		details, hasDetails := inventory.Configs[key]
		name := S(guest, "name")
		if name == "" {
			name = kind + " " + vmid
		}
		if len(name) > 180 {
			name = name[:180]
		}
		guestKind := "QEMU VM"
		category := "Virtual machine"
		if kind == "lxc" {
			guestKind = "LXC container"
			category = "Container"
		}
		template := N(guest, "template") == 1 || guest["template"] == true
		if template {
			templates++
		}
		fields := M{"name": name, "category": category, "platform": "Proxmox VE", "guestKind": guestKind, "proxmoxVMID": vmid, "proxmoxNode": S(guest, "node"), "hostId": hosts[S(guest, "node")]["id"], "status": S(guest, "status"), "template": template, "vCPU": N(guest, "maxcpu"), "memoryBytes": N(guest, "maxmem"), "diskBytes": N(guest, "maxdisk"), "uptimeSeconds": N(guest, "uptime"), "serverCandidate": false}
		if hasDetails {
			fields["guestOSType"] = S(details, "ostype")
			if os := proxmoxGuestOS(details, kind); os != "" {
				fields["os"] = os
				fields["osSource"] = "Proxmox configured guest type; guest OS not independently verified"
			}
			if ip := proxmoxConfiguredIP(details, kind); ip != "" {
				fields["configuredIP"] = ip
			}
			if kind == "qemu" {
				fields["guestAgentStatus"] = "Not enabled"
				if proxmoxAgentEnabled(details) {
					fields["guestAgentStatus"] = "Enabled; guest not running"
					if S(guest, "status") == "running" {
						fields["guestAgentStatus"] = "Not queried"
					}
				}
			}
		}
		var old M
		if previous := existing[key]; previous != nil {
			old = decode(S(previous, "data"))
			if S(old, "category") != "Virtual machine" && S(old, "category") != "Container" {
				fields["category"] = old["category"]
			}
		}
		if agent, ok := inventory.Agents[key]; ok {
			fields["guestAgentStatus"] = agent["status"]
			if S(agent, "status") == "Running" {
				addresses, _ := agent["addresses"].([]string)
				fields["guestAgentIPs"] = addresses
				fields["guestAgentInterfaces"] = agent["interfaces"]
				fields["guestAgentSeen"] = seen
				primary := ""
				if len(addresses) > 0 {
					primary = addresses[0]
				}
				fields["guestAgentIP"] = primary
				// Only fill the inventory IP when it is empty or was set by the agent
				// before, so manually documented addresses are never overwritten.
				if primary != "" && (old == nil || S(old, "ip") == "" || S(old, "ipSource") == "QEMU guest agent") {
					fields["ip"] = primary
					fields["ipSource"] = "QEMU guest agent"
				}
				if host := S(agent, "hostname"); host != "" {
					fields["observedHostname"] = host
				}
				if osName := S(agent, "osName"); osName != "" {
					fields["osName"] = osName
					fields["osVersion"] = agent["osVersion"]
					fields["kernel"] = agent["kernel"]
					if S(agent, "osId") == "mswindows" || strings.Contains(strings.ToLower(osName), "windows") {
						fields["os"] = "Windows"
					} else {
						fields["os"] = "Linux"
					}
					fields["osSource"] = "Reported by the running guest (QEMU guest agent)"
				}
			}
		}
		upsert(key, fields, nil)
		count++
	}
	for key, r := range existing {
		if !strings.HasPrefix(key, "node/") && !seenGuests[key] {
			d := decode(S(r, "data"))
			d["inventoryState"] = "Not reported in latest Proxmox response"
			a.observedUpdate(actor, r, d)
		}
	}
	return M{"nodes": len(hosts), "guests": count, "templates": templates, "warnings": inventory.Warnings}
}

func proxmoxConfiguredIP(details M, kind string) string {
	key := "ipconfig0"
	if kind == "lxc" {
		key = "net0"
	}
	for _, field := range strings.Split(S(details, key), ",") {
		if strings.HasPrefix(field, "ip=") {
			value := strings.TrimPrefix(field, "ip=")
			if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
				return prefix.Addr().String()
			}
			if addr, err := netip.ParseAddr(value); err == nil && addr.Is4() {
				return addr.String()
			}
		}
	}
	return ""
}

func (a *App) startProxmox() {
	a.backgroundWG.Add(1)
	go func() {
		defer a.backgroundWG.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.backgroundCtx.Done():
				return
			case <-ticker.C:
				a.pollProxmox()
			}
		}
	}()
}

func (a *App) pollProxmox() {
	a.mu.Lock()
	profiles := a.q("SELECT * FROM proxmox_connections WHERE json_extract(config,'$.enabled')=1 AND next_run<=? ORDER BY next_run LIMIT 4", time.Now().Unix())
	a.mu.Unlock()
	for _, profile := range profiles {
		if a.backgroundCtx.Err() != nil {
			return
		}
		a.syncProxmox(profile)
	}
}

func (a *App) syncProxmox(profile M) {
	config := decode(S(profile, "config"))
	if config["enabled"] == false {
		return
	}
	cid := S(profile, "id")
	revision := N(profile, "revision")
	a.mu.Lock()
	if a.get("SELECT id FROM proxmox_connections WHERE id=? AND revision=?", cid, revision) == nil {
		a.mu.Unlock()
		return
	}
	owner := a.get("SELECT id FROM users WHERE id=? AND role='admin' AND active=1", profile["user_id"])
	if owner == nil {
		a.run("UPDATE proxmox_connections SET status='Owner access unavailable',next_run=? WHERE id=?", time.Now().Add(5*time.Minute).Unix(), cid)
		a.mu.Unlock()
		return
	}
	a.run("UPDATE proxmox_connections SET status='Syncing',next_run=? WHERE id=? AND revision=?", time.Now().Add(time.Duration(N(config, "intervalSeconds"))*time.Second).Unix(), cid, revision)
	var secret string
	func() {
		defer func() {
			if recover() != nil {
				secret = ""
			}
		}()
		secret = S(obj(a.unseal(S(profile, "sealed"))), "secret")
	}()
	a.mu.Unlock()
	a.broadcast()
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 75*time.Second)
	inventory, err := fetchProxmox(ctx, config, secret)
	cancel()
	if a.backgroundCtx.Err() != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.get("SELECT * FROM proxmox_connections WHERE id=? AND revision=?", cid, revision)
	if current == nil || decode(S(current, "config"))["enabled"] == false {
		return
	}
	if err != nil {
		a.run("UPDATE proxmox_connections SET status='Error',summary=? WHERE id=?", J(M{"error": err.Error()}), cid)
		a.broadcast()
		return
	}
	defer func() {
		if recover() != nil {
			a.db.Exec("ROLLBACK")
			a.run("UPDATE proxmox_connections SET status='Error',summary=? WHERE id=?", J(M{"error": "Inventory import failed. Check the organization and linked inventory records"}), cid)
			a.broadcast()
		}
	}()
	if a.get("SELECT id FROM users WHERE id=? AND role='admin' AND active=1", profile["user_id"]) == nil {
		return
	}
	if a.get("SELECT id FROM records WHERE id=? AND type='organizations' AND deleted IS NULL", profile["org_id"]) == nil {
		return
	}
	a.run("BEGIN IMMEDIATE")
	summary := a.importProxmox(current, inventory)
	a.run("UPDATE proxmox_connections SET status='Connected',last_sync=?,summary=? WHERE id=?", timestamp(), J(summary), cid)
	a.audit(nil, "proxmox_synced", cid, fmt.Sprintf("Imported %v nodes and %v guests", summary["nodes"], summary["guests"]))
	a.run("COMMIT")
	a.broadcast()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
