package app

// Connections to the public internet.
//
// Collectors report every connection their host makes. Connections to public
// internet addresses (Microsoft 365, GitHub, CDNs, update servers...) are
// recorded against one "Internet" record per organization, with the addresses
// listed on each connection, instead of creating a device record per address.
// Older versions created a device for every address; migrateInternetEndpoints
// moves those to the recycle bin once and keeps their connection history.

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
)

const maxRemoteAddresses = 50

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isInternetAddress reports whether ip is a public internet address rather
// than a private, loopback, link-local, multicast or carrier-grade NAT one.
func isInternetAddress(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !cgnat.Contains(addr)
}

// internetNode returns the organization's Internet record, creating it once.
func (a *App) internetNode(actor M, org string) M {
	for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", org) {
		if decode(S(r, "data"))["internetNode"] == true {
			return a.safe(r)
		}
	}
	return a.insert(actor, "assets", M{"orgId": org, "name": "Internet", "category": "Internet", "status": "Active", "internetNode": true, "visibility": "internal",
		"notes": "Public internet services that devices connect to (for example Microsoft 365 or GitHub). Each connection lists the addresses seen. This is not a device."})
}

// mergeAddresses appends new addresses to an existing list, keeping the first
// maxRemoteAddresses and counting the rest, so repeated reports do not churn.
func mergeAddresses(previous M, add ...string) ([]string, int) {
	list := strArray(previous["remoteAddresses"])
	count := int(N(previous, "remoteAddressCount"))
	if count < len(list) {
		count = len(list)
	}
	for _, ip := range add {
		if contains(list, ip) {
			continue
		}
		if len(list) < maxRemoteAddresses {
			list = append(list, ip)
		}
		count++
	}
	return list, count
}

// migrateInternetEndpoints moves the per-address internet "devices" created by
// older versions to the recycle bin, after folding their connections into
// Internet connections. It runs once. Records a person has named, approved or
// linked to anything other than a connection are left alone.
func (a *App) migrateInternetEndpoints() {
	if a.get("SELECT value FROM meta WHERE key='migration_internet_endpoints'") != nil {
		return
	}
	actor := a.get("SELECT * FROM users WHERE role='admin' AND active=1 ORDER BY created LIMIT 1")
	if actor == nil {
		return // nothing to migrate before setup
	}
	actor = clone(actor)
	actor["name"] = "InfraLedger maintenance"
	moved, merged := 0, 0
	func() {
		defer func() {
			if p := recover(); p != nil {
				a.db.Exec("ROLLBACK")
				log.Printf("Internet endpoint cleanup skipped: %v", p)
				moved, merged = -1, 0
			}
		}()
		a.run("BEGIN IMMEDIATE")
		candidates := map[string]M{}
		for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND deleted IS NULL") {
			d := decode(S(r, "data"))
			ip := S(d, "ip")
			if S(d, "category") == "Endpoint" && strings.HasPrefix(S(d, "sourceKey"), "remote:") && isInternetAddress(ip) &&
				S(d, "name") == ip && S(d, "approvalStatus") != "Approved" && len(strArray(d["relatedIds"])) == 0 {
				candidates[S(r, "id")] = r
			}
		}
		dependencies := []M{}
		for _, r := range a.q("SELECT * FROM records WHERE deleted IS NULL") {
			d := decode(S(r, "data"))
			for id := range candidates {
				if !linksTo(d, id) {
					continue
				}
				if S(r, "type") == "dependencies" && S(d, "targetId") == id {
					dependencies = append(dependencies, r)
				} else {
					delete(candidates, id) // linked from something a person may care about
				}
			}
		}
		if len(candidates) == 0 {
			a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('migration_internet_endpoints',?)", J(M{"at": timestamp(), "moved": 0}))
			a.run("COMMIT")
			return
		}
		now := timestamp()
		flows := map[string]M{}
		for _, dep := range dependencies {
			d := decode(S(dep, "data"))
			target := candidates[S(d, "targetId")]
			if target == nil {
				continue
			}
			node := a.internetNode(actor, S(dep, "org_id"))
			key := fmt.Sprintf("internet:%s:%v:%s", S(d, "sourceId"), d["targetPort"], strings.ToUpper(S(d, "protocol")))
			flow := flows[S(d, "collectorId")+"|"+key]
			if flow == nil {
				for _, r := range a.q("SELECT * FROM records WHERE type='dependencies' AND org_id=? AND deleted IS NULL", S(dep, "org_id")) {
					if x := decode(S(r, "data")); S(x, "sourceKey") == key && S(x, "collectorId") == S(d, "collectorId") {
						flow = r
					}
				}
			}
			process := strings.SplitN(S(d, "name"), " → ", 2)[0]
			fields := M{"orgId": dep["org_id"], "name": fmt.Sprintf("%s → Internet :%v", process, d["targetPort"]), "sourceId": d["sourceId"], "targetId": node["id"], "targetPort": d["targetPort"], "sourcePort": d["sourcePort"], "protocol": d["protocol"], "status": "Observed", "purpose": "Connections to public internet services",
				"collectorId": d["collectorId"], "sourceKey": key, "visibility": "internal", "observed": true, "lastSeen": d["lastSeen"]}
			if flow == nil {
				fields["remoteAddresses"], fields["remoteAddressCount"] = mergeAddresses(M{}, S(decode(S(target, "data")), "ip"))
				flow = a.get("SELECT * FROM records WHERE id=?", S(a.insert(actor, "dependencies", fields), "id"))
			} else {
				previous := decode(S(flow, "data"))
				fields["remoteAddresses"], fields["remoteAddressCount"] = mergeAddresses(previous, S(decode(S(target, "data")), "ip"))
				fields["version"] = flow["version"]
				flow = a.get("SELECT * FROM records WHERE id=?", S(a.update(actor, flow, fields), "id"))
			}
			flows[S(d, "collectorId")+"|"+key] = flow
			a.run("UPDATE records SET deleted=? WHERE id=?", now, dep["id"])
			a.audit(actor, "delete", S(dep, "id"), "dependencies: merged into Internet connection")
			merged++
		}
		for id := range candidates {
			a.run("UPDATE records SET deleted=? WHERE id=?", now, id)
			a.audit(actor, "delete", id, "assets: internet address, not a device")
			moved++
		}
		a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('migration_internet_endpoints',?)", J(M{"at": now, "moved": moved, "connectionsMerged": merged}))
		a.run("COMMIT")
	}()
	if moved > 0 {
		log.Printf("Moved %d internet addresses recorded as devices to the recycle bin; %d connections merged into Internet connections", moved, merged)
	}
}
