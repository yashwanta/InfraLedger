package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const sampleLinuxOutput = `##HOSTNAME
web01
##OSRELEASE
NAME="Ubuntu"
PRETTY_NAME="Ubuntu 24.04.1 LTS"
##KERNEL
6.8.0-45-generic
##DMI
sys_vendor=Dell Inc.
product_name=PowerEdge R650
product_serial=ABC1234
chassis_type=23
##ADDR
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.50.30/24 brd 192.168.50.255 scope global eth0\       valid_lft forever preferred_lft forever
##LINK
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
##ROUTE
default via 192.168.50.1 dev eth0 proto static
##DNS
nameserver 192.168.50.1
##CPU
8
##MEM
MemTotal:       16318412 kB
##PKG
source=dpkg
nginx	1.24.0-2ubuntu7	Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
openssh-server	1:9.6p1-3ubuntu13	Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
##SERVICES
nginx.service loaded active running A high performance web server and a reverse proxy server
ssh.service   loaded active running OpenBSD Secure Shell server
##END
`

func TestParseLinuxInventory(t *testing.T) {
	s, err := parseLinuxInventory(sampleLinuxOutput)
	if err != nil {
		t.Fatal(err)
	}
	host := obj(s["host"])
	if S(host, "hostname") != "web01" || S(host, "osVersion") != "Ubuntu 24.04.1 LTS" || S(host, "serial") != "ABC1234" || S(host, "deviceType") != "Server" || N(host, "cpus") != 8 {
		t.Fatal(host)
	}
	ifaces := A(s["interfaces"])
	if len(ifaces) != 1 || S(obj(ifaces[0]), "mac") != "52:54:00:12:34:56" || S(obj(ifaces[0]), "gateway") != "192.168.50.1" || strArray(obj(ifaces[0])["addresses"])[0] != "192.168.50.30/24" {
		t.Fatal(ifaces)
	}
	if len(A(s["software"])) != 2 || S(obj(A(s["software"])[0]), "key") != "dpkg:nginx" || len(A(s["services"])) != 2 {
		t.Fatal(s["software"], s["services"])
	}
	if _, err := parseLinuxInventory("##HOSTNAME\nweb01\n"); err == nil {
		t.Fatal("truncated output accepted")
	}
}

func TestParseWindowsInventory(t *testing.T) {
	out := `#< CLIXML noise
{"hostname":"PC-042","domain":"corp.example","manufacturer":"LENOVO","model":"ThinkPad T14","serial":"PF1234","chassis":10,"productType":1,"os":"Microsoft Windows 11 Pro","osVersion":"10.0.22631","cpus":8,"memoryBytes":17179869184,
"interfaces":{"name":"Intel Wi-Fi","index":12,"mac":"AA-BB-CC-DD-EE-FF","addresses":"10.1.2.3/24","gateway":"10.1.2.1","dns":["10.1.2.1"]},
"software":[{"key":"{GUID-1}","name":"7-Zip 23.01","version":"23.01","publisher":"Igor Pavlov"}],
"services":{"key":"Spooler","name":"Print Spooler","state":"Running","startMode":"Auto","account":"LocalSystem","executablePath":"C:\\Windows\\System32\\spoolsv.exe","pid":"1234"}}`
	s, err := parseWindowsInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	host := obj(s["host"])
	if S(host, "deviceType") != "Laptop" || S(host, "serial") != "PF1234" || S(host, "os") != "Windows" {
		t.Fatal(host)
	}
	iface := obj(A(s["interfaces"])[0])
	if S(iface, "mac") != "aa:bb:cc:dd:ee:ff" || strArray(iface["addresses"])[0] != "10.1.2.3/24" {
		t.Fatal(iface)
	}
	if len(A(s["software"])) != 1 || len(A(s["services"])) != 1 {
		t.Fatal(s)
	}
}

// --- end-to-end with an in-process SSH server --------------------------------

type testSSHServer struct {
	addr     string
	config   *ssh.ServerConfig
	commands []string
}

func newTestSSHServer(t *testing.T, output string) *testSSHServer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv := &testSSHServer{config: &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == "inventory" && string(p) == "correct-horse" {
			return nil, nil
		}
		return nil, io.EOF
	}}}
	srv.config.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv.addr = l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, srv.config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					channel, requests, _ := ch.Accept()
					go func() {
						for req := range requests {
							if req.Type == "exec" {
								srv.commands = append(srv.commands, string(req.Payload[4:]))
								req.Reply(true, nil)
								io.Copy(io.Discard, io.LimitReader(channel, int64(len(linuxInventoryScript))))
								channel.Write([]byte(output))
								channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								channel.Close()
								return
							}
							req.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return srv
}

type apiClient struct {
	t      *testing.T
	a      *App
	cookie string
	csrf   string
}

func (c *apiClient) call(method, path string, body any) (int, M, []any) {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, reader)
	r.RemoteAddr, r.Host = "127.0.0.1:40000", "127.0.0.1:5173"
	r.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		r.Header.Set("Cookie", c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	w := httptest.NewRecorder()
	c.a.ServeHTTP(w, r)
	if set := w.Result().Header.Get("Set-Cookie"); set != "" {
		c.cookie = strings.Split(set, ";")[0]
	}
	var m M
	var list []any
	raw := w.Body.Bytes()
	if json.Unmarshal(raw, &m) != nil {
		json.Unmarshal(raw, &list)
	}
	return w.Code, m, list
}

func TestRemoteInventorySSHEndToEnd(t *testing.T) {
	server := newTestSSHServer(t, sampleLinuxOutput)
	original := remoteDial
	remoteDial = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.addr)
	}
	defer func() { remoteDial = original }()

	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.backgroundCancel() // drive the worker manually
	a.backgroundWG.Wait()
	a.backgroundCtx = context.Background()
	c := &apiClient{t: t, a: a}
	if code, m, _ := c.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase", "samples": false}); code != 201 {
		t.Fatal(code, m)
	}
	_, me, _ := c.call("GET", "/api/me", nil)
	c.csrf = S(me, "csrf")
	_, org, _ := c.call("POST", "/api/records", M{"type": "organizations", "name": "Plant A"})
	c.call("POST", "/api/records", M{"type": "networks", "name": "Servers", "orgId": org["id"], "cidr": "192.168.50.0/24"})
	_, asset, _ := c.call("POST", "/api/records", M{"type": "assets", "name": "Unknown device", "orgId": org["id"], "ip": "192.168.50.30", "category": "Network endpoint"})
	_, outside, _ := c.call("POST", "/api/records", M{"type": "assets", "name": "Outside", "orgId": org["id"], "ip": "192.168.99.5"})

	code, cred, _ := c.call("POST", "/api/remote-inventory/credentials", M{"orgId": org["id"], "name": "Linux servers", "kind": "ssh", "username": "inventory", "password": "correct-horse"})
	if code != 200 || cred["hasSecret"] != true {
		t.Fatal(code, cred)
	}
	_, _, list := c.call("GET", "/api/remote-inventory/credentials", nil)
	if strings.Contains(J(list), "correct-horse") {
		t.Fatal("credential secret returned to the browser")
	}
	if strings.Contains(J(a.q("SELECT config FROM remote_credentials")), "correct-horse") {
		t.Fatal("secret stored outside the sealed field")
	}
	code, queued, _ := c.call("POST", "/api/remote-inventory/scan", M{"credentialId": cred["id"], "assetIds": []string{S(asset, "id"), S(outside, "id")}})
	if code != 202 || N(queued, "queued") != 1 || !strings.Contains(J(queued["rejected"]), "outside this organization") {
		t.Fatal(code, queued)
	}
	a.pollRemoteInventory()
	_, _, scans := c.call("GET", "/api/remote-inventory/scans?assetId="+S(asset, "id"), nil)
	if S(obj(scans[0]), "status") != "Completed" {
		t.Fatal(scans)
	}
	_, record, _ := c.call("GET", "/api/records/"+S(asset, "id"), nil)
	if S(record, "serial") != "ABC1234" || S(record, "category") != "Server" || S(record, "osVersion") != "Ubuntu 24.04.1 LTS" || S(record, "name") != "Unknown device" || S(record, "discoverySource") != "Remote inventory (SSH)" {
		t.Fatal(record)
	}
	_, _, records := c.call("GET", "/api/records", nil)
	apps, services := 0, 0
	for _, r := range records {
		switch S(obj(r), "type") {
		case "applications":
			if S(obj(r), "assetId") == S(asset, "id") {
				apps++
			}
		case "services":
			if S(obj(r), "assetId") == S(asset, "id") {
				services++
			}
		}
	}
	if apps != 2 || services != 2 {
		t.Fatal("software/services not recorded", apps, services)
	}
	if a.get("SELECT fingerprint FROM remote_trust WHERE asset_id=?", asset["id"]) == nil {
		t.Fatal("host key not pinned")
	}

	// Re-scan updates in place without duplicates.
	c.call("POST", "/api/remote-inventory/scan", M{"credentialId": cred["id"], "assetIds": []string{S(asset, "id")}})
	a.pollRemoteInventory()
	if n := len(a.q("SELECT id FROM records WHERE type='applications' AND deleted IS NULL")); n != 2 {
		t.Fatal("duplicate applications after rescan:", n)
	}

	// A different host key at the same address is refused.
	impostor := newTestSSHServer(t, sampleLinuxOutput)
	remoteDial = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", impostor.addr)
	}
	c.call("POST", "/api/remote-inventory/scan", M{"credentialId": cred["id"], "assetIds": []string{S(asset, "id")}})
	a.pollRemoteInventory()
	_, _, scans = c.call("GET", "/api/remote-inventory/scans?assetId="+S(asset, "id"), nil)
	if S(obj(scans[0]), "status") != "Error" || !strings.Contains(J(scans[0]), "host key changed") {
		t.Fatal(scans[0])
	}
	if len(impostor.commands) != 0 {
		t.Fatal("commands ran on a host with a changed key")
	}

	// Wrong password gives a clear error.
	c.call("DELETE", "/api/remote-inventory/trust/"+S(asset, "id"), M{})
	remoteDial = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.addr)
	}
	_, bad, _ := c.call("POST", "/api/remote-inventory/credentials", M{"orgId": org["id"], "name": "Wrong", "kind": "ssh", "username": "inventory", "password": "nope"})
	c.call("POST", "/api/remote-inventory/scan", M{"credentialId": bad["id"], "assetIds": []string{S(asset, "id")}})
	a.pollRemoteInventory()
	_, _, scans = c.call("GET", "/api/remote-inventory/scans?assetId="+S(asset, "id"), nil)
	if !strings.Contains(J(scans[0]), "sign-in failed") {
		t.Fatal(scans[0])
	}
}

func TestRemoteInventoryRequiresAdmin(t *testing.T) {
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	admin := &apiClient{t: t, a: a}
	admin.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase", "samples": false})
	_, me, _ := admin.call("GET", "/api/me", nil)
	admin.csrf = S(me, "csrf")
	code, created, _ := admin.call("POST", "/api/users", M{"name": "Analyst", "email": "analyst@example.test", "password": "another-long-passphrase", "role": "it_analyst"})
	if code != 201 && code != 200 {
		t.Fatal(code, created)
	}
	analyst := &apiClient{t: t, a: a}
	if code, m, _ := analyst.call("POST", "/api/login", M{"email": "analyst@example.test", "password": "another-long-passphrase"}); code != 200 {
		t.Fatal(code, m)
	}
	_, me, _ = analyst.call("GET", "/api/me", nil)
	analyst.csrf = S(me, "csrf")
	if code, _, _ := analyst.call("GET", "/api/remote-inventory/credentials", nil); code != 403 {
		t.Fatal("non-admin read credentials:", code)
	}
}
