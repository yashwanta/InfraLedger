package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProxmoxSyncImportsGuestsPendingAndPreservesApproval(t *testing.T) {
	var unauthorized atomic.Bool
	var migrated atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "PVEAPIToken=inventory@pve!readonly=fake-proxmox-secret" {
			unauthorized.Store(true)
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var data any
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			node := "pve-a"
			if migrated.Load() {
				node = "pve-b"
			}
			data = []M{{"type": "node", "node": node, "status": "online"}, {"type": "qemu", "vmid": 100, "node": node, "name": "Windows guest", "status": "running", "maxcpu": 4, "maxmem": 8589934592, "maxdisk": 68719476736}, {"type": "lxc", "vmid": 101, "node": node, "name": "Linux container", "status": "stopped", "template": 1, "maxcpu": 2, "maxmem": 2147483648}}
		default:
			if strings.HasSuffix(r.URL.Path, "/qemu/100/config") {
				data = M{"ostype": "win11", "cipassword": "DO-NOT-PERSIST-CONFIG-SECRETS"}
			} else if strings.HasSuffix(r.URL.Path, "/lxc/101/config") {
				data = M{"ostype": "debian", "net0": "name=eth0,bridge=vmbr0,ip=10.20.30.50/24"}
			} else {
				w.WriteHeader(404)
				return
			}
		}
		json.NewEncoder(w).Encode(M{"data": data})
	}))
	defer server.Close()
	digest := sha256.Sum256(server.Certificate().Raw)
	pin := hex.EncodeToString(digest[:])
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// Disable the timed worker for this deterministic sync test.
	a.backgroundCancel()
	a.backgroundWG.Wait()
	a.backgroundCtx = context.Background()
	a.run("INSERT INTO users(id,email,name,password,role,created) VALUES('owner','fixture@example.test','Fixture','unused','admin',?)", timestamp())
	actor := M{"role": "admin", "name": "Fixture"}
	org := a.insert(actor, "organizations", M{"name": "Fixture organization"})
	host := a.insert(actor, "assets", M{"name": "pve-a", "orgId": org["id"], "category": "Server", "notes": "Keep manual host notes"})
	config := validateProxmoxConfig(M{"name": "Fixture Proxmox", "url": server.URL, "tokenId": "inventory@pve!readonly", "fingerprint": pin, "intervalSeconds": 300})
	a.run("INSERT INTO proxmox_connections(id,org_id,user_id,config,sealed,created) VALUES('pve-fixture',?,'owner',?,?,?)", org["id"], J(config), a.seal(M{"secret": "fake-proxmox-secret"}), timestamp())
	profile := a.get("SELECT * FROM proxmox_connections WHERE id='pve-fixture'")
	a.syncProxmox(profile)
	state := a.get("SELECT * FROM proxmox_connections WHERE id='pve-fixture'")
	if S(state, "status") != "Connected" {
		t.Fatal(publicProxmox(state))
	}
	if strings.Contains(J(publicProxmox(state)), "fake-proxmox-secret") {
		t.Fatal("secret leaked")
	}
	var vm, container M
	for _, r := range a.q("SELECT * FROM records WHERE type='assets'") {
		d := a.safe(r)
		if S(d, "proxmoxVMID") == "100" {
			vm = d
		}
		if S(d, "proxmoxVMID") == "101" {
			container = d
		}
	}
	if vm == nil || S(vm, "approvalStatus") != "Pending" || S(vm, "os") != "Windows" || S(vm, "hostId") != S(host, "id") {
		t.Fatal(vm)
	}
	if S(container, "os") != "Linux" || S(container, "configuredIP") != "10.20.30.50" || container["template"] != true {
		t.Fatal(container)
	}
	if strings.Contains(J(a.q("SELECT data FROM records")), "DO-NOT-PERSIST-CONFIG-SECRETS") {
		t.Fatal("guest config secret persisted")
	}
	raw := a.get("SELECT * FROM records WHERE id=?", vm["id"])
	d := decode(S(raw, "data"))
	d["approvalStatus"] = "Approved"
	d["notes"] = "Keep VM documentation"
	d["version"] = raw["version"]
	a.update(actor, raw, d)
	migrated.Store(true)
	profile = a.get("SELECT * FROM proxmox_connections WHERE id='pve-fixture'")
	a.syncProxmox(profile)
	current := a.safe(a.get("SELECT * FROM records WHERE id=?", vm["id"]))
	if S(current, "approvalStatus") != "Approved" || S(current, "notes") != "Keep VM documentation" || S(current, "proxmoxNode") != "pve-b" {
		t.Fatal(current)
	}
	if N(a.get("SELECT count(*) AS total FROM records WHERE json_extract(data,'$.proxmoxVMID')='100'"), "total") != 1 {
		t.Fatal("VM duplicated after migration")
	}
	if unauthorized.Load() {
		t.Fatal("connector attempted a non-GET request or incorrect authentication")
	}
}

func TestProxmoxTLSRejectsUntrustedAndMismatchedCertificates(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		json.NewEncoder(w).Encode(M{"data": []M{}})
	}))
	defer server.Close()
	config := M{"url": server.URL, "tokenId": "fixture@pve!token"}
	if _, err := fetchProxmox(context.Background(), config, "fake-secret"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	config["fingerprint"] = strings.Repeat("00", 32)
	if _, err := fetchProxmox(context.Background(), config, "fake-secret"); err == nil {
		t.Fatal("wrong certificate pin accepted")
	}
	if received.Load() != 0 {
		t.Fatal("credentials reached HTTP before certificate verification")
	}
}
