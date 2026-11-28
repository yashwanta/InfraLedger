package app

import (
	"strings"
	"testing"
)

func TestIdentifyLocalDevice(t *testing.T) {
	cases := []struct {
		name               string
		d, obs             M
		wantOS, wantCat    string
		wantVendorContains string
	}{
		{"windows pc by netbios and ttl", M{"mac": "00:11:22:33:44:55"}, M{"ttl": 128, "netbiosName": "OFFICE-PC"}, "Windows", "Network endpoint", ""},
		{"iphone hostname", M{"mac": "da:a1:19:00:00:01"}, M{"hostname": "Janes-iPhone.local", "ttl": 64}, "iOS", categoryPhone, "Private"},
		{"private address only", M{"mac": "da:a1:19:00:00:02"}, M{"ttl": 64}, "iOS or Android (private Wi-Fi address)", categoryPhone, "Private"},
		{"private address windows laptop", M{"mac": "da:a1:19:00:00:03"}, M{"ttl": 128}, "Windows", "Laptop", "Private"},
		{"epson printer", M{"mac": "64:eb:8c:00:00:01"}, M{}, "Printer firmware", "Printer", "Epson"},
		{"proxmox vm linux", M{"mac": "bc:24:11:00:00:01"}, M{"ttl": 64}, "Linux (Proxmox VM)", "Virtual machine", "Proxmox"},
		{"proxmox vm without ttl", M{"mac": "bc:24:11:00:00:02"}, M{}, "", "Virtual machine", "Proxmox"},
		{"network ttl", M{"mac": "00:11:22:33:44:56"}, M{"ttl": 255}, "Network device firmware", "Network endpoint", ""},
		{"nothing known", M{"mac": "00:11:22:33:44:57"}, M{}, "", "Network endpoint", ""},
	}
	for _, c := range cases {
		d := M{"category": "Network endpoint", "ip": "10.20.30.9"}
		for k, v := range c.d {
			d[k] = v
		}
		identifyLocalDevice(d, c.obs)
		if S(d, "os") != c.wantOS || S(d, "category") != c.wantCat {
			t.Fatalf("%s: got os %q category %q, want %q %q (%v)", c.name, S(d, "os"), S(d, "category"), c.wantOS, c.wantCat, d)
		}
		if c.wantOS != "" && (d["osInferred"] != true || S(d, "osEvidence") == "") {
			t.Fatalf("%s: estimate not marked with evidence: %v", c.name, d)
		}
		if c.wantVendorContains != "" && !strings.Contains(S(d, "macVendor"), c.wantVendorContains) {
			t.Fatalf("%s: vendor missing: %v", c.name, d)
		}
	}

	documented := M{"category": "Server", "os": "Ubuntu 24.04", "mac": "bc:24:11:00:00:03"}
	identifyLocalDevice(documented, M{"ttl": 128})
	if S(documented, "os") != "Ubuntu 24.04" || documented["osInferred"] == true {
		t.Fatal("a documented OS was replaced by an estimate", documented)
	}
	// A stronger signal later replaces an estimate.
	d := M{"category": "Network endpoint", "mac": "00:11:22:33:44:58"}
	identifyLocalDevice(d, M{"ttl": 64})
	identifyLocalDevice(d, M{"hostname": "Pixel-8", "ttl": 64})
	if S(d, "os") != "Android" {
		t.Fatal("estimate not refined", d)
	}
}
