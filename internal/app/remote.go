package app

// Authenticated remote inventory for devices without a collector.
//
// IT Admins save SSH (Linux) or WinRM (Windows) credentials per organization.
// Credentials are sealed with the vault key and never returned to the browser.
// A scan request only queues work; a background worker connects, runs read-only
// inventory commands, then ingests the result through the same path as the
// endpoint collector. Targets must be private IPv4 addresses inside the
// organization's documented networks or discovery subnets. SSH host keys are
// pinned on first use and a changed key blocks further scans until an admin
// resets trust.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"
)

const maxRemoteBatch = 256

// remoteDial opens the TCP connection for SSH inventory; tests replace it.
var remoteDial = func(ctx context.Context, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 15 * time.Second}
	return dialer.DialContext(ctx, "tcp", address)
}

func validateRemoteCredential(input M) M {
	name := strings.TrimSpace(S(input, "name"))
	if name == "" || len(name) > 120 {
		fail(400, "Enter a credential name of up to 120 characters")
	}
	kind := S(input, "kind")
	if kind != "ssh" && kind != "winrm" {
		fail(400, "Choose SSH (Linux) or WinRM (Windows)")
	}
	user := strings.TrimSpace(S(input, "username"))
	if user == "" || len(user) > 200 || strings.ContainsAny(user, "\r\n\t") {
		fail(400, "Enter the user name")
	}
	port := int(N(input, "port"))
	if port == 0 {
		port = 22
		if kind == "winrm" {
			port = 5985
		}
	}
	if port < 1 || port > 65535 {
		fail(400, "Port must be between 1 and 65535")
	}
	return M{"name": name, "kind": kind, "username": user, "port": port}
}

func publicRemoteCredential(r M) M {
	config := decode(S(r, "config"))
	config["id"] = r["id"]
	config["orgId"] = r["org_id"]
	config["created"] = r["created"]
	config["hasSecret"] = S(r, "sealed") != ""
	return config
}

// remoteTargetAllowed checks that ip is a private IPv4 address inside the
// organization's documented networks or configured discovery subnets.
func (a *App) remoteTargetAllowed(org, ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.IsLoopback() {
		return fmt.Errorf("Remote inventory targets must have a private IPv4 address")
	}
	cidrs := []string{}
	for _, n := range a.q("SELECT data FROM records WHERE type='networks' AND org_id=? AND deleted IS NULL", org) {
		if cidr := S(decode(S(n, "data")), "cidr"); cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	cidrs = append(cidrs, strArray(a.workspaceDiscoveryDefaults()["cidrs"])...)
	for _, c := range a.q("SELECT id FROM collectors WHERE org_id=?", org) {
		cidrs = append(cidrs, strArray(obj(a.discoveryProfile(S(c, "id"))["config"])["cidrs"])...)
	}
	if !withinRanges(addr, cidrs) {
		return fmt.Errorf("%s is outside this organization's documented networks and discovery subnets", ip)
	}
	return nil
}

func (a *App) remoteRoute(req *http.Request, u, b M) result {
	requirePage(u, "integrations", "view")
	if S(u, "role") != "admin" {
		fail(403, "IT Admin manages remote inventory credentials")
	}
	rest := strings.Trim(strings.TrimPrefix(req.URL.Path, "/api/remote-inventory"), "/")
	parts := strings.Split(rest, "/")
	if rest == "snmp-sweep" {
		return a.snmpRoute(req, u, b, rest)
	}
	switch {
	case rest == "credentials" && req.Method == "GET":
		rows := []M{}
		for _, r := range a.q("SELECT * FROM remote_credentials ORDER BY created") {
			rows = append(rows, publicRemoteCredential(r))
		}
		return out(200, rows)
	case rest == "credentials" && req.Method == "POST", len(parts) == 2 && parts[0] == "credentials" && req.Method == "PUT":
		requirePage(u, "integrations", "edit")
		var previous M
		cid := id()
		if req.Method == "PUT" {
			previous = a.get("SELECT * FROM remote_credentials WHERE id=?", parts[1])
			if previous == nil {
				fail(404, "Credential not found")
			}
			cid = parts[1]
		}
		org := S(b, "orgId")
		if previous != nil {
			org = S(previous, "org_id")
		}
		if a.get("SELECT id FROM records WHERE id=? AND type='organizations' AND deleted IS NULL", org) == nil {
			fail(400, "Select an organization")
		}
		if S(b, "kind") == "snmp" || previous != nil && S(decode(S(previous, "config")), "kind") == "snmp" {
			config, secret := validateSNMPCredential(b)
			sealed := ""
			if len(secret) > 0 {
				sealed = a.seal(secret)
			} else if previous != nil {
				old := decode(S(previous, "config"))
				if S(old, "kind") != "snmp" || S(old, "snmpVersion") != S(config, "snmpVersion") || S(old, "username") != S(config, "username") {
					fail(400, "Re-enter the SNMP secret when changing the version or user name")
				}
				sealed = S(previous, "sealed")
			}
			if sealed == "" {
				fail(400, "Enter the community string or the SNMPv3 passwords")
			}
			return a.saveRemoteCredential(u, previous, cid, org, config, sealed)
		}
		config := validateRemoteCredential(b)
		secret := M{}
		if p := S(b, "password"); p != "" {
			if len(p) > 1000 {
				fail(400, "Password is too long")
			}
			secret["password"] = p
		}
		if key := strings.TrimSpace(S(b, "privateKey")); key != "" {
			if config["kind"] != "ssh" {
				fail(400, "Private keys are only used with SSH")
			}
			if len(key) > 20000 {
				fail(400, "Private key is too large")
			}
			if _, err := ssh.ParsePrivateKey([]byte(key)); err != nil {
				fail(400, "Enter an unencrypted OpenSSH or PEM private key")
			}
			secret["privateKey"] = key
		}
		sealed := ""
		if len(secret) > 0 {
			sealed = a.seal(secret)
		} else if previous != nil {
			old := decode(S(previous, "config"))
			if S(old, "kind") != S(config, "kind") || S(old, "username") != S(config, "username") {
				fail(400, "Re-enter the password or key when changing the type or user name")
			}
			sealed = S(previous, "sealed")
		}
		if sealed == "" {
			fail(400, "Enter a password or private key")
		}
		return a.saveRemoteCredential(u, previous, cid, org, config, sealed)
	case len(parts) == 2 && parts[0] == "credentials" && req.Method == "DELETE":
		requirePage(u, "integrations", "edit")
		if a.get("SELECT id FROM remote_credentials WHERE id=?", parts[1]) == nil {
			fail(404, "Credential not found")
		}
		a.run("DELETE FROM remote_credentials WHERE id=?", parts[1])
		a.run("UPDATE remote_scans SET status='Cancelled',finished=? WHERE credential_id=? AND status='Queued'", timestamp(), parts[1])
		a.audit(u, "remote_credential_deleted", parts[1], "")
		return out(200, M{"ok": true})
	case rest == "scan" && req.Method == "POST":
		requirePage(u, "integrations", "edit")
		credential := a.get("SELECT * FROM remote_credentials WHERE id=?", S(b, "credentialId"))
		if credential == nil {
			fail(400, "Select a saved credential")
		}
		if S(decode(S(credential, "config")), "kind") == "snmp" {
			fail(400, "SNMP credentials are used by the automatic network sweep. Use Run SNMP sweep instead")
		}
		ids := strArray(b["assetIds"])
		if len(ids) == 0 || len(ids) > maxRemoteBatch {
			fail(400, fmt.Sprintf("Select between 1 and %d devices", maxRemoteBatch))
		}
		queued, rejected := []string{}, []M{}
		for _, assetID := range ids {
			asset := a.get("SELECT * FROM records WHERE id=? AND type='assets' AND deleted IS NULL", assetID)
			if asset == nil || S(asset, "org_id") != S(credential, "org_id") {
				rejected = append(rejected, M{"assetId": assetID, "error": "Device not found in the credential's organization"})
				continue
			}
			if err := a.remoteTargetAllowed(S(credential, "org_id"), S(decode(S(asset, "data")), "ip")); err != nil {
				rejected = append(rejected, M{"assetId": assetID, "error": err.Error()})
				continue
			}
			if a.get("SELECT id FROM remote_scans WHERE asset_id=? AND status IN ('Queued','Running')", assetID) != nil {
				rejected = append(rejected, M{"assetId": assetID, "error": "A remote scan is already queued for this device"})
				continue
			}
			scanID := id()
			a.run("INSERT INTO remote_scans(id,asset_id,credential_id,org_id,user_id,status,requested) VALUES(?,?,?,?,?,'Queued',?)", scanID, assetID, credential["id"], credential["org_id"], u["id"], timestamp())
			queued = append(queued, scanID)
		}
		a.audit(u, "remote_scan_requested", S(credential, "id"), fmt.Sprintf("%d queued, %d rejected", len(queued), len(rejected)))
		return out(202, M{"queued": len(queued), "rejected": rejected})
	case rest == "scans" && req.Method == "GET":
		rows := []M{}
		query := "SELECT * FROM remote_scans ORDER BY requested DESC LIMIT 200"
		args := []any{}
		if asset := req.URL.Query().Get("assetId"); asset != "" {
			query = "SELECT * FROM remote_scans WHERE asset_id=? ORDER BY requested DESC LIMIT 20"
			args = append(args, asset)
		}
		for _, r := range a.q(query, args...) {
			rows = append(rows, M{"id": r["id"], "assetId": r["asset_id"], "credentialId": r["credential_id"], "status": r["status"], "requested": r["requested"], "finished": r["finished"], "summary": decode(S(r, "summary"))})
		}
		return out(200, rows)
	case len(parts) == 2 && parts[0] == "trust" && req.Method == "DELETE":
		requirePage(u, "integrations", "edit")
		a.run("DELETE FROM remote_trust WHERE asset_id=?", parts[1])
		a.audit(u, "remote_trust_reset", parts[1], "Pinned remote host identity cleared")
		return out(200, M{"ok": true})
	}
	fail(404, "Route not found")
	return result{}
}

func (a *App) saveRemoteCredential(u, previous M, cid, org string, config M, sealed string) result {
	if previous == nil {
		a.run("INSERT INTO remote_credentials(id,org_id,user_id,config,sealed,created) VALUES(?,?,?,?,?,?)", cid, org, u["id"], J(config), sealed, timestamp())
	} else {
		a.run("UPDATE remote_credentials SET user_id=?,config=?,sealed=? WHERE id=?", u["id"], J(config), sealed, cid)
	}
	a.audit(u, "remote_credential_saved", cid, S(config, "kind")+" credential "+S(config, "name"))
	return out(200, publicRemoteCredential(a.get("SELECT * FROM remote_credentials WHERE id=?", cid)))
}

func (a *App) startRemoteInventory() {
	a.backgroundWG.Add(1)
	go func() {
		defer a.backgroundWG.Done()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.backgroundCtx.Done():
				return
			case <-ticker.C:
				a.pollRemoteInventory()
			}
		}
	}()
}

func (a *App) pollRemoteInventory() {
	a.mu.Lock()
	jobs := a.q("SELECT * FROM remote_scans WHERE status='Queued' ORDER BY requested LIMIT 4")
	for _, job := range jobs {
		a.run("UPDATE remote_scans SET status='Running' WHERE id=?", job["id"])
	}
	a.mu.Unlock()
	for _, job := range jobs {
		if a.backgroundCtx.Err() != nil {
			return
		}
		a.runRemoteScan(job)
	}
}

type remoteTarget struct {
	IP, Kind, User, Password, Key string
	Port                          int
	PinnedKey                     string
}

func (a *App) runRemoteScan(job M) {
	finish := func(status string, summary M) {
		a.mu.Lock()
		a.run("UPDATE remote_scans SET status=?,summary=?,finished=? WHERE id=?", status, J(summary), timestamp(), job["id"])
		a.mu.Unlock()
		a.broadcast()
	}
	a.mu.Lock()
	var target remoteTarget
	setupErr := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("Saved credential could not be opened")
			}
		}()
		credential := a.get("SELECT * FROM remote_credentials WHERE id=?", job["credential_id"])
		owner := a.get("SELECT id FROM users WHERE id=? AND role='admin' AND active=1", job["user_id"])
		asset := a.get("SELECT * FROM records WHERE id=? AND type='assets' AND deleted IS NULL", job["asset_id"])
		if credential == nil || owner == nil || asset == nil || S(asset, "org_id") != S(credential, "org_id") {
			return fmt.Errorf("Credential, requesting admin or device is no longer available")
		}
		ip := S(decode(S(asset, "data")), "ip")
		if err := a.remoteTargetAllowed(S(credential, "org_id"), ip); err != nil {
			return err
		}
		config := decode(S(credential, "config"))
		secret := obj(a.unseal(S(credential, "sealed")))
		target = remoteTarget{IP: ip, Kind: S(config, "kind"), User: S(config, "username"), Password: S(secret, "password"), Key: S(secret, "privateKey"), Port: int(N(config, "port"))}
		if pin := a.get("SELECT fingerprint FROM remote_trust WHERE asset_id=? AND kind=?", job["asset_id"], target.Kind); pin != nil {
			target.PinnedKey = S(pin, "fingerprint")
		}
		return nil
	}()
	a.mu.Unlock()
	if setupErr != nil {
		finish("Error", M{"error": setupErr.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(a.backgroundCtx, 90*time.Second)
	snapshot, hostKey, err := collectRemote(ctx, target)
	cancel()
	if a.backgroundCtx.Err() != nil {
		return
	}
	if err != nil {
		finish("Error", M{"error": err.Error()})
		return
	}
	var summary M
	ingestErr := func() (err error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		defer func() {
			if p := recover(); p != nil {
				a.db.Exec("ROLLBACK")
				if e, ok := p.(apiError); ok {
					err = fmt.Errorf("%s", e.Message)
				} else {
					err = fmt.Errorf("Inventory could not be saved")
				}
			}
		}()
		a.run("BEGIN IMMEDIATE")
		if hostKey != "" && target.PinnedKey == "" {
			a.run("INSERT OR REPLACE INTO remote_trust(asset_id,kind,fingerprint,first_seen) VALUES(?,?,?,?)", job["asset_id"], target.Kind, hostKey, timestamp())
		}
		summary = a.ingestRemote(job, target, snapshot)
		a.audit(nil, "remote_scan_completed", S(job, "asset_id"), fmt.Sprintf("%v software, %v services", summary["software"], summary["services"]))
		a.run("COMMIT")
		return nil
	}()
	if ingestErr != nil {
		finish("Error", M{"error": ingestErr.Error()})
		return
	}
	finish("Completed", summary)
}

// ingestRemote records the snapshot on the target asset using the collector
// ingestion path, scoped to a per-device source so results never mix.
func (a *App) ingestRemote(job M, target remoteTarget, snapshot M) M {
	u := a.get("SELECT * FROM users WHERE id=?", job["user_id"])
	actor := clone(u)
	source := "SSH"
	if target.Kind == "winrm" {
		source = "WinRM"
	}
	actor["name"] = "Remote inventory (" + source + ")"
	oid := S(job, "org_id")
	sourceID := "remote:" + S(job, "asset_id")
	observed := timestamp()
	existing := map[string]M{}
	for _, r := range a.q("SELECT * FROM records WHERE org_id=? AND deleted IS NULL", oid) {
		if d := decode(S(r, "data")); S(d, "collectorId") == sourceID {
			existing[S(d, "sourceKey")] = r
		}
	}
	upsert := func(kind, key string, d M) M {
		d["orgId"], d["collectorId"], d["sourceKey"], d["visibility"], d["observed"], d["lastSeen"] = oid, sourceID, key, "internal", true, observed
		if r := existing[key]; r != nil {
			previous := decode(S(r, "data"))
			for _, field := range []string{"approvalStatus", "approvedAt", "approvedBy", "listeningPorts", "servicePort", "notes", "customFields", "relatedIds"} {
				if _, present := d[field]; (!present || field == "notes") && previous[field] != nil {
					d[field] = previous[field]
				}
			}
			d["version"] = r["version"]
			result := a.update(actor, r, d)
			existing[key] = a.get("SELECT * FROM records WHERE id=?", S(result, "id"))
			return result
		}
		result := a.insert(actor, kind, d)
		existing[key] = a.get("SELECT * FROM records WHERE id=?", S(result, "id"))
		return result
	}
	host := a.get("SELECT * FROM records WHERE id=?", job["asset_id"])
	before := decode(S(host, "data"))
	keepName := before["autoDiscovered"] != true
	a.ingestDiscovery(M{"org_id": oid, "id": sourceID}, actor, host, snapshot, observed, upsert)
	host = a.get("SELECT * FROM records WHERE id=?", job["asset_id"])
	d := decode(S(host, "data"))
	facts := obj(snapshot["host"])
	d["discoverySource"] = "Remote inventory (" + source + ")"
	d["remoteInventoryAt"] = observed
	d["identityConfidence"] = "Authenticated remote inventory"
	if keepName {
		d["name"] = before["name"]
	}
	if d["category"] == "Network endpoint" || d["category"] == "Endpoint" {
		if category := S(facts, "deviceType"); category != "" {
			d["category"] = category
		} else {
			d["category"] = "Computer"
		}
		d["categoryAutoDetected"] = true
	}
	for _, key := range []string{"kernel", "cpus", "memoryBytes", "domain"} {
		if facts[key] != nil && S(facts, key) != "" {
			d[key] = facts[key]
		}
	}
	d["version"] = host["version"]
	a.observedUpdate(actor, host, d)
	return M{"hostname": S(facts, "hostname"), "os": S(facts, "osVersion"), "software": len(A(snapshot["software"])), "services": len(A(snapshot["services"])), "interfaces": len(A(snapshot["interfaces"]))}
}

// collectRemote connects to the target and returns a discovery snapshot plus the
// identity fingerprint observed for trust-on-first-use pinning.
func collectRemote(ctx context.Context, t remoteTarget) (M, string, error) {
	if t.Kind == "ssh" {
		return collectSSH(ctx, t)
	}
	return collectWinRM(ctx, t)
}

func sshFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func collectSSH(ctx context.Context, t remoteTarget) (M, string, error) {
	auth := []ssh.AuthMethod{}
	if t.Key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(t.Key))
		if err != nil {
			return nil, "", fmt.Errorf("Saved private key is invalid")
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		password := t.Password
		auth = append(auth, ssh.Password(password), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}))
	}
	seen := ""
	config := &ssh.ClientConfig{User: t.User, Auth: auth, Timeout: 15 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		seen = sshFingerprint(key)
		if t.PinnedKey != "" && seen != t.PinnedKey {
			return fmt.Errorf("host key changed")
		}
		return nil
	}}
	address := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
	conn, err := remoteDial(ctx, address)
	if err != nil {
		return nil, "", fmt.Errorf("Cannot reach %s. Check that SSH is enabled and reachable", address)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "host key changed") {
			return nil, "", fmt.Errorf("SSH host key changed since the first scan (now %s). If the device was rebuilt, reset its trusted identity; otherwise investigate before scanning again", seen)
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, "", fmt.Errorf("SSH sign-in failed. Check the user name, password or key")
		}
		return nil, "", fmt.Errorf("SSH connection failed")
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, "", fmt.Errorf("SSH session could not be opened")
	}
	defer session.Close()
	var stdout bytes.Buffer
	session.Stdout = &limitedBuffer{buf: &stdout, max: 16 << 20}
	// The script goes to a POSIX shell on stdin so the user's login shell does not matter.
	session.Stdin = strings.NewReader(linuxInventoryScript)
	if err := session.Run("/bin/sh -s"); err != nil && stdout.Len() == 0 {
		return nil, "", fmt.Errorf("Remote inventory commands failed")
	}
	snapshot, err := parseLinuxInventory(stdout.String())
	return snapshot, seen, err
}

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		return 0, fmt.Errorf("remote output too large")
	}
	return l.buf.Write(p)
}

func collectWinRM(ctx context.Context, t remoteTarget) (M, string, error) {
	endpoint := winrm.NewEndpoint(t.IP, t.Port, false, false, nil, nil, nil, 60*time.Second)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		// NTLM with message-level encryption: credentials and output are not sent in clear text over HTTP.
		enc, _ := winrm.NewEncryption("ntlm")
		return enc
	}
	client, err := winrm.NewClientWithParameters(endpoint, t.User, t.Password, params)
	if err != nil {
		return nil, "", fmt.Errorf("WinRM client could not be created")
	}
	stdout, _, code, err := client.RunWithContextWithString(ctx, winrm.Powershell(windowsInventoryScript), "")
	if err != nil {
		message := err.Error()
		switch {
		case strings.Contains(message, "401"):
			return nil, "", fmt.Errorf("WinRM sign-in failed. Check the user name (DOMAIN\\user or .\\user) and password")
		case strings.Contains(message, "connect") || strings.Contains(message, "timeout") || strings.Contains(message, "refused"):
			return nil, "", fmt.Errorf("Cannot reach WinRM on %s:%d. Run 'winrm quickconfig' on the device and allow TCP %d", t.IP, t.Port, t.Port)
		}
		return nil, "", fmt.Errorf("WinRM request failed")
	}
	if code != 0 && strings.TrimSpace(stdout) == "" {
		return nil, "", fmt.Errorf("Remote PowerShell inventory failed (exit code %d)", code)
	}
	snapshot, err := parseWindowsInventory(stdout)
	return snapshot, "", err
}
