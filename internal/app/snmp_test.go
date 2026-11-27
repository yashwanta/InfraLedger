package app

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMACVendorAndClassification(t *testing.T) {
	if v := macVendor("24:a4:3c:01:02:03"); !strings.Contains(v, "Ubiquiti") {
		t.Fatalf("expected Ubiquiti, got %q", v)
	}
	if v := macVendor("26:a4:3c:01:02:03"); v != "" {
		t.Fatalf("locally administered MAC must have no vendor, got %q", v)
	}
	d := M{"mac": "24-A4-3C-01-02-03", "category": "Network endpoint"}
	applyMACVendor(d)
	if S(d, "manufacturer") != "Ubiquiti" || S(d, "category") != "Network device" {
		t.Fatal(d)
	}
	manual := M{"mac": "24:a4:3c:01:02:03", "category": "Server", "manufacturer": "Acme"}
	applyMACVendor(manual)
	if S(manual, "category") != "Server" || S(manual, "manufacturer") != "Acme" {
		t.Fatal("hand-entered type or manufacturer was overwritten", manual)
	}
	if c, p := matchWebSignature("RouterOS router configuration page", ""); c != "Router" || p != "MikroTik RouterOS" {
		t.Fatal(c, p)
	}
	if c, _ := matchWebSignature("", "HP HTTP Server; HP LaserJet"); c != "Printer" {
		t.Fatal(c)
	}
}

func snmpTestApp(t *testing.T) (*App, *apiClient, M) {
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	a.backgroundCancel()
	a.backgroundWG.Wait()
	a.backgroundCtx = context.Background()
	c := &apiClient{t: t, a: a}
	if code, m, _ := c.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase", "samples": false}); code != 201 {
		t.Fatal(code, m)
	}
	_, me, _ := c.call("GET", "/api/me", nil)
	c.csrf = S(me, "csrf")
	_, org, _ := c.call("POST", "/api/records", M{"type": "organizations", "name": "Plant A"})
	c.call("POST", "/api/records", M{"type": "networks", "name": "LAN", "orgId": org["id"], "cidr": "10.20.30.0/24", "gateway": "10.20.30.1"})
	return a, c, org
}

func TestSNMPCredentialIsSealedAndNotUsableForRemoteScans(t *testing.T) {
	_, c, org := snmpTestApp(t)
	code, cred, _ := c.call("POST", "/api/remote-inventory/credentials", M{"orgId": org["id"], "name": "Switches", "kind": "snmp", "snmpVersion": "v2c", "community": "s3cret-community"})
	if code != 200 || cred["hasSecret"] != true || S(cred, "kind") != "snmp" || N(cred, "port") != 161 {
		t.Fatal(code, cred)
	}
	_, _, list := c.call("GET", "/api/remote-inventory/credentials", nil)
	if strings.Contains(J(list), "s3cret-community") {
		t.Fatal("community string returned to the browser")
	}
	if code, m, _ := c.call("POST", "/api/remote-inventory/credentials", M{"orgId": org["id"], "name": "v3", "kind": "snmp", "snmpVersion": "v3", "username": "monitor", "password": "short", "privPassword": "short"}); code != 400 {
		t.Fatal("weak SNMPv3 passwords accepted", code, m)
	}
	_, asset, _ := c.call("POST", "/api/records", M{"type": "assets", "name": "sw1", "orgId": org["id"], "ip": "10.20.30.2"})
	if code, m, _ := c.call("POST", "/api/remote-inventory/scan", M{"credentialId": cred["id"], "assetIds": []string{S(asset, "id")}}); code != 400 || !strings.Contains(S(m, "error"), "SNMP sweep") {
		t.Fatal(code, m)
	}
	if code, m, _ := c.call("POST", "/api/remote-inventory/snmp-sweep", M{"orgId": org["id"]}); code != 202 {
		t.Fatal(code, m)
	}
}

func TestSNMPSweepClassifiesAndBuildsTopology(t *testing.T) {
	a, c, org := snmpTestApp(t)
	c.call("POST", "/api/remote-inventory/credentials", M{"orgId": org["id"], "name": "Switches", "kind": "snmp", "community": "public"})
	add := func(name, ip, mac string) M {
		_, r, _ := c.call("POST", "/api/records", M{"type": "assets", "name": ip, "orgId": org["id"], "ip": ip, "mac": mac, "category": "Network endpoint", "autoDiscovered": true})
		return r
	}
	router := add("router", "10.20.30.1", "00:11:22:00:00:01")
	core := add("core", "10.20.30.2", "00:11:22:00:00:02")
	edge := add("edge", "10.20.30.3", "00:11:22:00:00:03")
	pc := add("pc", "10.20.30.50", "00:11:22:00:00:50")
	printer := add("printer", "10.20.30.60", "00:11:22:00:00:60")

	original := snmpPoll
	defer func() { snmpPoll = original }()
	snmpPoll = func(_ context.Context, ip string, cred snmpCredential) (*snmpDevice, error) {
		if cred.Community != "public" {
			t.Fatal("credential not unsealed")
		}
		switch ip {
		case "10.20.30.1":
			return &snmpDevice{SysName: "gw", SysDescr: "RouterOS RB5009", SysObjectID: ".1.3.6.1.4.1.14988.1", Services: 78, Forwarding: true, IfNames: map[int]string{1: "ether1"}}, nil
		case "10.20.30.2":
			// Core switch: uplink to the router on Gi0/1, edge switch on Gi0/24 (LLDP), PC behind edge.
			return &snmpDevice{SysName: "core", SysDescr: "Cisco IOS Software, C2960", SysObjectID: ".1.3.6.1.4.1.9.1.1", Services: 2, Model: "WS-C2960X-24", Serial: "FOC123",
				IfNames:      map[int]string{1: "Gi0/1", 24: "Gi0/24"},
				FDB:          map[string]string{"00:11:22:00:00:01": "Gi0/1", "00:11:22:00:00:03": "Gi0/24", "00:11:22:00:00:50": "Gi0/24", "00:11:22:00:00:60": "Gi0/24"},
				FDBPortCount: map[string]int{"Gi0/1": 1, "Gi0/24": 3},
				LLDP:         []lldpEntry{{LocalPort: "Gi0/24", RemoteName: "edge.example.local", RemotePort: "Gi0/1"}}}, nil
		case "10.20.30.3":
			return &snmpDevice{SysName: "edge", SysDescr: "Cisco IOS Software, C1000", SysObjectID: ".1.3.6.1.4.1.9.1.2", Services: 2,
				IfNames:      map[int]string{1: "Gi0/1", 5: "Gi0/5", 7: "Gi0/7"},
				FDB:          map[string]string{"00:11:22:00:00:02": "Gi0/1", "00:11:22:00:00:50": "Gi0/5", "00:11:22:00:00:60": "Gi0/7"},
				FDBPortCount: map[string]int{"Gi0/1": 2, "Gi0/5": 1, "Gi0/7": 1}}, nil
		case "10.20.30.60":
			return &snmpDevice{SysName: "PRN-1", SysDescr: "HP ETHERNET MULTI-ENVIRONMENT, LaserJet M404", IfNames: map[int]string{}}, nil
		}
		return nil, errors.New("timeout")
	}
	a.runSNMPSweep(S(org, "id"))
	state := a.snmpState(S(org, "id"))
	if S(state, "status") != "Completed" || N(obj(state["summary"]), "responded") != 4 {
		t.Fatal(state)
	}
	get := func(r M) M { return a.parsed(a.get("SELECT * FROM records WHERE id=?", S(r, "id"))) }
	if r := get(router); S(r, "category") != "Router" || S(r, "manufacturer") != "MikroTik" || S(r, "name") != "gw" {
		t.Fatal("router", r)
	}
	if s := get(core); S(s, "category") != "Switch" || S(s, "model") != "WS-C2960X-24" || S(s, "serial") != "FOC123" || !strings.Contains(J(s["lldpNeighbors"]), S(edge, "id")) {
		t.Fatal("core", s)
	}
	if p := get(pc); S(p, "uplinkAssetId") != S(edge, "id") || S(p, "uplinkPort") != "Gi0/5" {
		t.Fatal("PC should hang off the edge access port, not the core uplink", p)
	}
	if p := get(printer); S(p, "category") != "Printer" || S(p, "uplinkAssetId") != S(edge, "id") {
		t.Fatal("printer", p)
	}
	if r := get(router); S(r, "uplinkAssetId") != S(core, "id") || S(r, "uplinkPort") != "Gi0/1" {
		t.Fatal("router uplink", r)
	}
	// A second identical sweep must not create new record versions.
	version := N(get(pc), "version")
	a.runSNMPSweep(S(org, "id"))
	if N(get(pc), "version") != version {
		t.Fatal("unchanged SNMP results created a new version")
	}
}

func TestSNMPCategory(t *testing.T) {
	cases := []struct {
		d    snmpDevice
		want string
	}{
		{snmpDevice{SysDescr: "FortiGate-60F v7.2", SysObjectID: ".1.3.6.1.4.1.12356.101"}, "Firewall"},
		{snmpDevice{SysDescr: "Linux nas 5.10", SysObjectID: ".1.3.6.1.4.1.6574.1"}, "Storage"},
		{snmpDevice{SysDescr: "Linux server 6.1", SysObjectID: ".1.3.6.1.4.1.8072.3.2.10", Forwarding: true, Services: 72}, ""},
	}
	for _, c := range cases {
		if got, _ := snmpCategory(&c.d); got != c.want {
			t.Fatalf("%s: got %q want %q", c.d.SysDescr, got, c.want)
		}
	}
}
