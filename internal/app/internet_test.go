package app

import "testing"

func TestIsInternetAddress(t *testing.T) {
	for ip, want := range map[string]bool{"140.82.112.3": true, "52.96.173.146": true, "2606:4700::1111": true,
		"192.168.50.10": false, "10.0.0.5": false, "172.20.1.1": false, "100.101.102.103": false, "127.0.0.1": false,
		"169.254.10.1": false, "224.0.0.251": false, "fd00::1": false, "::1": false, "not-an-ip": false} {
		if got := isInternetAddress(ip); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

func TestMigrateInternetEndpointsKeepsHistoryAndManualRecords(t *testing.T) {
	a, _, org := snmpTestApp(t)
	admin := a.get("SELECT * FROM users WHERE role='admin' LIMIT 1")
	oid := S(org, "id")
	host := a.insert(admin, "assets", M{"orgId": oid, "name": "pc-01", "ip": "10.20.30.41"})
	app := a.insert(admin, "applications", M{"orgId": oid, "name": "OUTLOOK.EXE", "assetId": host["id"]})
	endpoint := func(ip, name string, extra M) M {
		d := M{"orgId": oid, "name": name, "ip": ip, "category": "Endpoint", "status": "Discovered", "collectorId": "c1", "sourceKey": "remote:" + ip, "observed": true}
		for k, v := range extra {
			d[k] = v
		}
		return a.insert(admin, "assets", d)
	}
	ms1 := endpoint("52.96.1.1", "52.96.1.1", nil)
	ms2 := endpoint("52.96.1.2", "52.96.1.2", nil)
	named := endpoint("140.82.112.3", "GitHub API", nil) // renamed by a person: keep
	lan := endpoint("10.20.30.99", "10.20.30.99", nil)   // private address: keep
	for _, e := range []M{ms1, ms2, named} {
		a.insert(admin, "dependencies", M{"orgId": oid, "name": "OUTLOOK.EXE → " + S(e, "ip") + ":443", "sourceId": app["id"], "targetId": e["id"], "targetPort": 443, "protocol": "TCP", "collectorId": "c1", "sourceKey": "flow:x:" + S(e, "id"), "observed": true})
	}
	a.run("DELETE FROM meta WHERE key='migration_internet_endpoints'")
	a.migrateInternetEndpoints()

	deleted := func(r M) bool { return S(a.get("SELECT deleted FROM records WHERE id=?", S(r, "id")), "deleted") != "" }
	if !deleted(ms1) || !deleted(ms2) {
		t.Fatal("internet endpoints were not moved to the recycle bin")
	}
	if deleted(named) || deleted(lan) || deleted(host) {
		t.Fatal("a named, private or host record was removed")
	}
	var internet M
	for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND deleted IS NULL") {
		if d := a.parsed(r); d["internetNode"] == true {
			internet = d
		}
	}
	if internet == nil {
		t.Fatal("Internet record not created")
	}
	flows := 0
	for _, r := range a.q("SELECT * FROM records WHERE type='dependencies' AND deleted IS NULL") {
		d := a.parsed(r)
		if S(d, "targetId") == S(internet, "id") {
			flows++
			if N(d, "remoteAddressCount") != 2 || !contains(strArray(d["remoteAddresses"]), "52.96.1.2") {
				t.Fatal("connection history lost", d)
			}
		}
	}
	if flows != 1 {
		t.Fatalf("expected one merged Internet connection, got %d", flows)
	}
	// Runs once.
	before := len(a.q("SELECT id FROM records WHERE deleted IS NOT NULL"))
	a.migrateInternetEndpoints()
	if len(a.q("SELECT id FROM records WHERE deleted IS NOT NULL")) != before {
		t.Fatal("migration ran twice")
	}
}
