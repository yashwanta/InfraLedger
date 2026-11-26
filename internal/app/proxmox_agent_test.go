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

// fakeAgentProxmox serves three running QEMU VMs: one with a responding guest
// agent, one whose agent is enabled but silent, and one without the agent.
func fakeAgentProxmox(t *testing.T, deny bool, nonGET *atomic.Bool) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			nonGET.Store(true)
		}
		var data any
		p := r.URL.Path
		switch {
		case p == "/api2/json/cluster/resources":
			data = []M{{"type": "node", "node": "pve01", "status": "online"},
				{"type": "qemu", "vmid": 100, "node": "pve01", "name": "app01", "status": "running"},
				{"type": "qemu", "vmid": 101, "node": "pve01", "name": "silent01", "status": "running"},
				{"type": "qemu", "vmid": 102, "node": "pve01", "name": "noagent01", "status": "running"}}
		case strings.HasSuffix(p, "/qemu/100/config"):
			data = M{"ostype": "l26", "agent": "1,fstrim_cloned_disks=1"}
		case strings.HasSuffix(p, "/qemu/101/config"):
			data = M{"ostype": "win11", "agent": 1}
		case strings.HasSuffix(p, "/qemu/102/config"):
			data = M{"ostype": "l26"}
		case strings.Contains(p, "/agent/") && deny:
			w.WriteHeader(403)
			return
		case strings.HasSuffix(p, "/qemu/100/agent/network-get-interfaces"):
			data = M{"result": []M{
				{"name": "lo", "ip-addresses": []M{{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}}},
				{"name": "eth0", "hardware-address": "bc:24:11:00:00:01", "ip-addresses": []M{
					{"ip-address-type": "ipv4", "ip-address": "10.20.0.15", "prefix": 24},
					{"ip-address-type": "ipv6", "ip-address": "fe80::1", "prefix": 64},
					{"ip-address-type": "ipv4", "ip-address": "169.254.10.10", "prefix": 16}}}}}
		case strings.HasSuffix(p, "/qemu/100/agent/get-osinfo"):
			data = M{"result": M{"id": "ubuntu", "pretty-name": "Ubuntu 24.04.1 LTS", "version": "24.04", "kernel-release": "6.8.0-45-generic"}}
		case strings.HasSuffix(p, "/qemu/100/agent/get-host-name"):
			data = M{"result": M{"host-name": "app01.example.test"}}
		case strings.HasSuffix(p, "/qemu/101/agent/network-get-interfaces"):
			w.WriteHeader(500) // "QEMU guest agent is not running"
			return
		default:
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(M{"data": data})
	}))
}

func TestProxmoxGuestAgentDetails(t *testing.T) {
	var nonGET atomic.Bool
	server := fakeAgentProxmox(t, false, &nonGET)
	defer server.Close()
	pin := certPin(server)
	inventory, err := fetchProxmox(context.Background(), M{"url": server.URL, "tokenId": "inventory@pve!readonly", "fingerprint": pin}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if nonGET.Load() {
		t.Fatal("non-GET request sent to Proxmox")
	}
	agent := inventory.Agents["qemu/100"]
	if S(agent, "status") != "Running" || S(agent, "osName") != "Ubuntu 24.04.1 LTS" || S(agent, "hostname") != "app01.example.test" {
		t.Fatal(agent)
	}
	if addrs := agent["addresses"].([]string); len(addrs) != 1 || addrs[0] != "10.20.0.15" {
		t.Fatal("loopback/link-local/IPv6 not filtered:", addrs)
	}
	if S(inventory.Agents["qemu/101"], "status") != "Not responding" {
		t.Fatal(inventory.Agents["qemu/101"])
	}
	if _, queried := inventory.Agents["qemu/102"]; queried {
		t.Fatal("agent queried for a VM without the agent enabled")
	}
	if !strings.Contains(strings.Join(inventory.Warnings, " "), "not responding in 1 running VMs") {
		t.Fatal(inventory.Warnings)
	}

	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.backgroundCancel()
	a.backgroundWG.Wait()
	a.run("INSERT INTO users(id,email,name,password,role,created) VALUES('owner','fixture@example.test','Fixture','unused','admin',?)", timestamp())
	actor := M{"role": "admin", "name": "Fixture"}
	org := a.insert(actor, "organizations", M{"name": "Fixture organization"})
	connection := M{"id": "pve-agent", "org_id": org["id"], "config": J(M{"name": "Fixture"})}
	a.importProxmox(connection, inventory)
	find := func(vmid string) M {
		for _, r := range a.q("SELECT * FROM records WHERE type='assets'") {
			if d := a.safe(r); S(d, "proxmoxVMID") == vmid {
				return d
			}
		}
		return nil
	}
	vm := find("100")
	if S(vm, "ip") != "10.20.0.15" || S(vm, "ipSource") != "QEMU guest agent" || S(vm, "os") != "Linux" || S(vm, "osName") != "Ubuntu 24.04.1 LTS" || S(vm, "observedHostname") != "app01.example.test" || S(vm, "guestAgentStatus") != "Running" {
		t.Fatal(vm)
	}
	if S(find("101"), "guestAgentStatus") != "Not responding" || S(find("102"), "guestAgentStatus") != "Not enabled" {
		t.Fatal(find("101"), find("102"))
	}

	// A manually documented IP is never overwritten by the agent.
	raw := a.get("SELECT * FROM records WHERE id=?", vm["id"])
	d := decode(S(raw, "data"))
	d["ip"], d["ipSource"], d["version"] = "10.20.0.99", "", raw["version"]
	a.update(actor, raw, d)
	connection["id"] = "pve-agent"
	a.importProxmox(connection, inventory)
	vm = find("100")
	if S(vm, "ip") != "10.20.0.99" || S(vm, "guestAgentIP") != "10.20.0.15" {
		t.Fatal("manual IP overwritten:", vm)
	}
}

func TestProxmoxGuestAgentPermissionDenied(t *testing.T) {
	var nonGET atomic.Bool
	server := fakeAgentProxmox(t, true, &nonGET)
	defer server.Close()
	inventory, err := fetchProxmox(context.Background(), M{"url": server.URL, "tokenId": "inventory@pve!readonly", "fingerprint": certPin(server)}, "secret")
	if err != nil {
		t.Fatal("agent permission problem must not fail the whole sync:", err)
	}
	if len(inventory.Resources) != 4 || len(inventory.Agents) != 0 {
		t.Fatal(inventory.Resources, inventory.Agents)
	}
	if !strings.Contains(strings.Join(inventory.Warnings, " "), "VM.GuestAgent.Audit") {
		t.Fatal(inventory.Warnings)
	}
}

func certPin(server *httptest.Server) string {
	sum := sha256.Sum256(server.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}
