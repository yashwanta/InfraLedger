package app

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func defaultDiscovery() M {
	return M{"enabled": true, "activeScan": false, "cidrs": []string{}, "ports": []int{22, 23, 53, 80, 135, 139, 443, 445, 631, 3389, 5432, 8006, 8080, 8291, 8443, 9100}, "intervalSeconds": 900}
}
func validateDiscovery(input M) M {
	d := defaultDiscovery()
	d["enabled"] = input["enabled"] != false
	d["activeScan"] = input["activeScan"] == true
	cidrs := []string{}
	size := 0
	for _, raw := range strArray(input["cidrs"]) {
		p, e := netip.ParsePrefix(strings.TrimSpace(raw))
		if e != nil || !p.Addr().Is4() {
			fail(400, "Discovery ranges must be IPv4 CIDR subnets")
		}
		p = p.Masked()
		count := uint64(1) << uint(32-p.Bits())
		if count > 1024 {
			fail(400, "Limit discovery ranges to 1,024 addresses in total")
		}
		last := p.Addr()
		for n := uint64(1); n < count; n++ {
			last = last.Next()
		}
		if !p.Addr().IsPrivate() || !last.IsPrivate() {
			fail(400, "Active discovery only supports private IPv4 ranges")
		}
		if !contains(cidrs, p.String()) {
			size += int(count)
			cidrs = append(cidrs, p.String())
		}
	}
	if size > 1024 {
		fail(400, "Limit discovery ranges to 1,024 addresses in total")
	}
	if d["activeScan"] == true && len(cidrs) == 0 {
		fail(400, "Select at least one subnet before enabling active discovery")
	}
	d["cidrs"] = cidrs
	ports := []int{}
	for _, value := range A(input["ports"]) {
		n := N(M{"n": value}, "n")
		if n < 1 || n > 65535 || float64(int(n)) != n {
			fail(400, "Discovery ports must be integers between 1 and 65535")
		}
		found := false
		for _, old := range ports {
			if old == int(n) {
				found = true
			}
		}
		if !found {
			ports = append(ports, int(n))
		}
	}
	if len(ports) == 0 {
		for _, n := range []int{22, 23, 53, 80, 135, 139, 443, 445, 631, 3389, 5432, 8006, 8080, 8291, 8443, 9100} {
			ports = append(ports, n)
		}
	}
	if len(ports) > 32 {
		fail(400, "Select up to 32 TCP ports for active discovery")
	}
	sort.Ints(ports)
	d["ports"] = ports
	seconds := N(input, "intervalSeconds")
	if seconds == 0 {
		seconds = 900
	}
	if seconds < 300 || seconds > 86400 || float64(int(seconds)) != seconds {
		fail(400, "Scan interval must be between 5 minutes and 24 hours")
	}
	d["intervalSeconds"] = seconds
	return d
}
func (a *App) collectorAuth(req *http.Request) (M, M, M) {
	rawToken := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	collector := a.get("SELECT * FROM collectors WHERE hash=? AND expires>?", digest(rawToken), time.Now().UnixMilli())
	if collector == nil {
		fail(401, "Invalid or expired collector token")
	}
	u := a.get("SELECT * FROM users WHERE id=? AND active=1", S(collector, "user_id"))
	if u == nil {
		fail(401, "Collector owner is inactive")
	}
	requireWrite(u)
	host := a.raw(u, S(collector, "asset_id"), false)
	if S(host, "org_id") != S(collector, "org_id") {
		fail(409, "Collector device moved organizations; register the collector again")
	}
	return collector, u, host
}
func (a *App) discoveryProfile(cid string) M {
	r := a.get("SELECT * FROM discovery_profiles WHERE collector_id=?", cid)
	if r == nil {
		return M{"config": a.workspaceDiscoveryDefaults(), "requestedAt": nil, "lastScanAt": nil, "lastDiscoveryAt": nil, "summary": M{}}
	}
	return M{"config": decode(S(r, "config")), "requestedAt": r["requested_at"], "lastScanAt": r["last_scan_at"], "lastDiscoveryAt": r["last_discovery_at"], "summary": decode(S(r, "summary"))}
}
func (a *App) discoveryRoute(req *http.Request, u, b M) result {
	path, method := req.URL.Path, req.Method
	if path == "/api/discovery/validate" && method == "POST" {
		requireAdmin(u)
		return out(200, validateDiscovery(b))
	}
	if path == "/api/discovery/defaults" {
		requireAdmin(u)
		if method == "GET" {
			return out(200, a.workspaceDiscoveryDefaults())
		}
		if method == "PUT" {
			config := validateDiscovery(b)
			a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('discovery_defaults',?)", J(config))
			a.audit(u, "discovery_defaults_updated", "", "")
			return out(200, config)
		}
	}

	if path == "/api/discovery" && method == "GET" {
		requirePage(u, "discovery", "view")
		if S(u, "role") == "client" {
			fail(403, "Discovery is available to internal users only")
		}
		rows := []M{}
		for _, c := range a.q("SELECT id,name,org_id AS orgId,asset_id AS assetId,last_seen AS lastSeen,expires FROM collectors ORDER BY created DESC") {
			host := a.get("SELECT * FROM records WHERE id=? AND deleted IS NULL", S(c, "assetId"))
			if a.canRead(u, host) {
				c["discovery"] = a.discoveryProfile(S(c, "id"))
				rows = append(rows, c)
			}
		}
		return out(200, rows)
	}
	requireAdmin(u)
	parts := strings.Split(strings.TrimPrefix(path, "/api/discovery/"), "/")
	cid := parts[0]
	collector := a.get("SELECT * FROM collectors WHERE id=?", cid)
	if collector == nil {
		fail(404, "Collector not found")
	}
	profile := a.discoveryProfile(cid)
	config := obj(profile["config"])
	if len(parts) == 1 && method == "PUT" {
		config = validateDiscovery(b)
		a.run("INSERT INTO discovery_profiles(collector_id,config,summary) VALUES(?,?,'{}') ON CONFLICT(collector_id) DO UPDATE SET config=excluded.config", cid, J(config))
		a.audit(u, "discovery_configured", cid, J(M{"activeScan": config["activeScan"], "cidrs": config["cidrs"]}))
		return out(200, a.discoveryProfile(cid))
	}
	if len(parts) == 2 && parts[1] == "scan" && method == "POST" {
		if config["enabled"] == false {
			fail(409, "Enable discovery before requesting a scan")
		}
		requested := timestamp()
		a.run("INSERT INTO discovery_profiles(collector_id,config,requested_at,summary) VALUES(?,?,?,'{}') ON CONFLICT(collector_id) DO UPDATE SET requested_at=excluded.requested_at", cid, J(config), requested)
		a.audit(u, "discovery_requested", cid, "")
		return out(202, M{"status": "Queued", "requestedAt": requested, "message": "The collector will run discovery when it next connects."})
	}
	fail(405, "Method not allowed")
	return result{}
}

type discoveryUpsert func(kind, key string, d M) M

func (a *App) ingestDiscovery(collector, u, host, snapshot M, observed string, upsert discoveryUpsert) M {
	oid, cid := S(collector, "org_id"), S(collector, "id")
	interfaces, neighbors, devices := A(snapshot["interfaces"]), A(snapshot["neighbors"]), A(obj(snapshot["networkScan"])["devices"])
	if len(interfaces) > 64 || len(neighbors) > 512 || len(devices) > 1024 {
		fail(400, "Discovery snapshot exceeds the interface or device limit")
	}
	facts := obj(snapshot["host"])
	if len(J(facts)) > 20000 {
		fail(400, "Host facts are too large")
	}
	d := decode(S(host, "data"))
	d["lastSeen"] = observed
	d["discoveredFacts"] = facts
	if warnings, ok := snapshot["inventoryWarnings"].([]any); ok && len(warnings) <= 10 {
		d["inventoryWarnings"] = warnings
	}
	d["discoverySource"] = "Endpoint collector"
	d["observedHostname"] = S(facts, "hostname")
	d["status"] = "Active"
	if d["autoDiscovered"] == true && S(facts, "hostname") != "" {
		d["name"] = S(facts, "hostname")
	}
	for _, key := range []string{"manufacturer", "model", "serial", "os", "osVersion"} {
		if S(d, key) == "" && S(facts, key) != "" {
			d[key] = facts[key]
		}
	}
	if category := S(facts, "deviceType"); contains([]string{"Laptop", "Desktop", "Server"}, category) && (S(d, "category") == "Computer" || S(d, "category") == "" || d["categoryAutoDetected"] == true) {
		d["category"] = category
		d["categoryAutoDetected"] = true
	}
	if software, ok := snapshot["software"].([]any); ok {
		if len(software) > 5000 {
			fail(400, "Software inventory exceeds 5000 items")
		}
		seenSoftware := map[string]bool{}
		for _, value := range software {
			item := obj(value)
			name := S(item, "name")
			if name == "" || len(name) > 180 {
				continue
			}
			key := S(item, "key")
			if key == "" || len(key) > 500 {
				continue
			}
			seenSoftware["software:"+key] = true
			upsert("applications", "software:"+key, M{"name": name, "assetId": host["id"], "softwareVersion": S(item, "version"), "publisher": S(item, "publisher"), "installLocation": S(item, "installLocation"), "status": "Installed", "inventorySource": S(snapshot, "softwareSource"), "autoDiscovered": true})
		}
		if len(seenSoftware) == len(software) && len(software) < 5000 && S(snapshot, "softwareSource") != "" {
			for _, record := range a.q("SELECT * FROM records WHERE type='applications' AND org_id=? AND deleted IS NULL", oid) {
				old := decode(S(record, "data"))
				if S(old, "collectorId") == cid && strings.HasPrefix(S(old, "sourceKey"), "software:") && !seenSoftware[S(old, "sourceKey")] {
					old["status"] = "Not present"
					old["inventoryCheckedAt"] = observed
					a.observedUpdate(u, record, old)
				}
			}
		}
		d["softwareInventoryAt"] = observed
		d["softwareInventoryCount"] = len(software)
	}
	if services, ok := snapshot["services"].([]any); ok {
		if len(services) > 2000 {
			fail(400, "Service inventory exceeds 2000 items")
		}
		for _, value := range services {
			service := obj(value)
			key, name := S(service, "key"), S(service, "name")
			if key == "" || len(key) > 500 || name == "" || len(name) > 180 {
				continue
			}
			description := S(service, "description")
			if len(description) > 8000 {
				description = description[:8000]
			}
			details := M{"name": name + " @ " + S(d, "name"), "assetId": host["id"], "serviceName": key, "description": description, "pid": S(service, "pid"), "status": S(service, "state"), "executablePath": S(service, "executablePath"), "startMode": S(service, "startMode"), "account": S(service, "account"), "serviceKind": "Managed service", "inventorySource": S(snapshot, "serviceSource"), "reviewStatus": "Identity unverified"}
			path := strings.ToLower(S(service, "executablePath"))
			if strings.Contains(path, `\users\`) || strings.Contains(path, `\temp\`) || strings.HasPrefix(path, "/tmp/") {
				details["reviewStatus"] = "Needs review"
				details["reviewReasons"] = []string{"Executable path includes a user profile or temporary directory. Confirm the owner and expected installation location."}
			}
			upsert("services", "managed-service:"+key, details)
		}
		d["serviceInventoryAt"] = observed
	}
	networkCount, addressCount, interfaceCount := 0, 0, 0
	for _, value := range interfaces {
		iface := obj(value)
		name := S(iface, "name")
		if name == "" || len(name) > 160 {
			continue
		}
		mac := S(iface, "mac")
		if len(mac) > 100 {
			fail(400, "Invalid interface MAC address")
		}
		port := upsert("ports", "interface:"+name, M{"name": name + " @ " + S(d, "name"), "assetId": host["id"], "port": name, "mac": mac, "status": "Discovered", "interfaceIndex": iface["index"], "autoDiscovered": true, "discoverySource": "Local interface"})
		interfaceCount++
		for _, raw := range strArray(iface["addresses"]) {
			p, e := netip.ParsePrefix(raw)
			if e != nil || !p.Addr().Is4() || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().IsUnspecified() {
				continue
			}
			if S(d, "ip") == "" {
				d["ip"] = p.Addr().String()
			}
			network := a.findNetwork(oid, p.Masked().String())
			if network == nil {
				network = upsert("networks", "network:"+p.Masked().String(), M{"name": p.Masked().String(), "cidr": p.Masked().String(), "gateway": validGateway(S(iface, "gateway"), p.Masked()), "dns": strings.Join(strArray(iface["dns"]), ", "), "purpose": "Auto-discovered local subnet", "autoDiscovered": true, "discoverySource": "Local interface"})
				networkCount++
			} else {
				a.touchObservation(u, S(network, "id"), observed)
			}
			if a.findAddress(S(network, "id"), p.Addr().String()) == nil {
				upsert("addresses", "address:"+S(host, "id")+":"+p.Addr().String(), M{"name": S(d, "name") + " / " + name, "networkId": network["id"], "address": p.Addr().String(), "assetId": host["id"], "mac": mac, "hostname": S(facts, "hostname"), "status": "Assigned", "autoDiscovered": true, "discoverySource": "Local interface"})
				addressCount++
			} else {
				existingAddress := a.findAddress(S(network, "id"), p.Addr().String())
				if S(existingAddress, "assetId") == S(host, "id") {
					a.touchObservation(u, S(existingAddress, "id"), observed)
				}
			}
			_ = port
		}
	}
	d["version"] = host["version"]
	host = a.observedUpdate(u, host, d)
	updateEndpoint := func(observation M, source string) M {
		ip := S(observation, "ip")
		address, e := netip.ParseAddr(ip)
		if e != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() || address.IsMulticast() {
			return nil
		}
		if S(host, "ip") == ip {
			return host
		}
		asset := a.findAsset(oid, ip)
		name := S(observation, "hostname")
		if name == "" {
			name = ip
		}
		if len(name) > 180 {
			name = ip
		}
		fields := M{"name": name, "ip": ip, "category": "Network endpoint", "status": "Discovered", "autoDiscovered": true, "discoverySource": source, "mac": S(observation, "mac")}
		if asset == nil {
			applyMACVendor(fields)
			asset = upsert("assets", "remote:"+ip, fields)
		} else {
			raw := a.get("SELECT * FROM records WHERE id=?", S(asset, "id"))
			current := decode(S(raw, "data"))
			current["lastSeen"] = observed
			current["autoDiscovered"] = true
			if S(current, "approvalStatus") == "" && contains([]string{"Network endpoint", "Endpoint"}, S(current, "category")) {
				current["approvalStatus"] = "Pending"
			}

			current["observedHostname"] = S(observation, "hostname")
			if S(current, "mac") == "" {
				current["mac"] = S(observation, "mac")
			}
			applyMACVendor(current)
			if current["autoDiscovered"] == true {
				current["status"] = "Discovered"
			}
			current["version"] = raw["version"]
			asset = a.observedUpdate(u, raw, current)
		}
		for _, n := range a.q("SELECT * FROM records WHERE type='networks' AND org_id=? AND deleted IS NULL", oid) {
			network := a.parsed(n)
			p, e := netip.ParsePrefix(S(network, "cidr"))
			if e == nil && p.Contains(address) && a.findAddress(S(network, "id"), ip) == nil {
				upsert("addresses", "address:"+S(asset, "id")+":"+ip, M{"name": name, "networkId": network["id"], "address": ip, "assetId": asset["id"], "mac": fields["mac"], "status": "Assigned", "autoDiscovered": true, "discoverySource": source})
				addressCount++
				break
			}
		}
		return asset
	}
	for _, n := range neighbors {
		updateEndpoint(obj(n), "Neighbor cache")
	}
	for _, value := range interfaces {
		gateway := S(obj(value), "gateway")
		if gateway == "" || gateway == S(host, "ip") {
			continue
		}
		if raw := a.findAsset(oid, gateway); raw != nil {
			record := a.get("SELECT * FROM records WHERE id=?", S(raw, "id"))
			current := decode(S(record, "data"))
			before := J(current)
			classify(current, "Router", "Default gateway of "+S(d, "name"))
			current["defaultGateway"] = true
			if J(current) != before {
				current["version"] = record["version"]
				a.observedUpdate(u, record, current)
			}
		}
	}
	scan := obj(snapshot["networkScan"])
	profile := a.discoveryProfile(cid)
	config := obj(profile["config"])
	if len(devices) > 0 && config["activeScan"] != true {
		fail(403, "Active network discovery is not enabled for this collector")
	}
	if len(scan) > 0 && config["activeScan"] == true {
		for _, cidr := range strArray(config["cidrs"]) {
			if a.findNetwork(oid, cidr) == nil {
				upsert("networks", "network:"+cidr, M{"name": cidr, "cidr": cidr, "purpose": "Configured discovery subnet", "autoDiscovered": true, "discoverySource": "Configured TCP scan"})
				networkCount++
			}
		}
	}
	for _, value := range devices {
		device := obj(value)
		ip, e := netip.ParseAddr(S(device, "ip"))
		if e != nil || !withinRanges(ip, strArray(config["cidrs"])) {
			fail(403, "Discovered device is outside configured scan ranges")
		}
		asset := updateEndpoint(device, "Configured TCP scan")
		if asset == nil {
			continue
		}
		// Keep service-derived identity separate from authenticated hardware facts.
		rawAsset := a.get("SELECT * FROM records WHERE id=?", S(asset, "id"))
		identity := decode(S(rawAsset, "data"))
		evidence := strArray(device["identityEvidence"])
		proxmoxListener := false
		for _, port := range A(device["openPorts"]) {
			if N(M{"p": port}, "p") == 8006 {
				proxmoxListener = true
			}
		}
		if len(evidence) > 10 || len(J(evidence)) > 10000 {
			fail(400, "Device identity evidence is too large")
		}
		before := J(identity)
		category, product := S(device, "deviceType"), S(device, "product")
		if !contains(networkCategories, category) {
			category, product = matchWebSignature(S(device, "webTitle"), S(device, "serverHeader"))
		}
		if category != "" {
			source := S(device, "webTitle")
			if source == "" {
				source = S(device, "serverHeader")
			}
			classify(identity, category, "Web interface identifies "+product+" ("+source+")")
			if product != "" && identity["categoryAutoDetected"] == true && S(identity, "category") == category {
				identity["platform"] = product
			}
		}
		for _, port := range A(device["openPorts"]) {
			switch int(N(M{"p": port}, "p")) {
			case 9100:
				classify(identity, "Printer", "Raw printing port TCP 9100 (JetDirect) responds")
			case 8291:
				classify(identity, "Router", "MikroTik Winbox port TCP 8291 responds")
				if identity["categoryAutoDetected"] == true && S(identity, "platform") == "" {
					identity["platform"] = "MikroTik RouterOS"
				}
			}
		}
		if len(evidence) > 0 || J(identity) != before {
			for _, item := range evidence {
				addEvidence(identity, item)
			}
			identity["identityConfidence"] = "Unauthenticated service fingerprint"
			identity["sshBanner"] = S(device, "sshBanner")
			if S(device, "os") == "Linux" && contains([]string{"Network endpoint", "Endpoint", "Computer", "Unknown", "Unclassified", ""}, S(identity, "category")) {
				identity["serverCandidate"] = true
				identity["candidateReason"] = "Distribution-specific SSH banner identifies a Linux host. Its server or desktop role has not been verified."
			}

			if S(identity, "os") == "" && S(device, "os") == "Linux" {
				identity["os"] = "Linux"
			}
			if proxmoxListener && S(device, "product") == "Proxmox Virtual Environment" && S(device, "deviceType") == "Server" && strings.Contains(strings.ToLower(S(device, "webTitle")), "proxmox virtual environment") && (contains([]string{"Network endpoint", "Endpoint", "Computer", ""}, S(identity, "category")) || identity["categoryAutoDetected"] == true) {
				identity["category"] = "Server"
				identity["categoryAutoDetected"] = true
				identity["platform"] = "Proxmox Virtual Environment"
				identity["serverCandidate"] = false
			}
			if S(identity, "name") == S(identity, "ip") && S(device, "hostname") != "" {
				identity["name"] = device["hostname"]
			}
			identity["lastSeen"] = observed
			asset = a.observedUpdate(u, rawAsset, identity)
		}
		for _, rawPort := range A(device["openPorts"]) {
			port := int(N(M{"port": rawPort}, "port"))
			allowed := false
			for _, n := range A(config["ports"]) {
				if int(N(M{"p": n}, "p")) == port {
					allowed = true
				}
			}
			if !allowed {
				fail(403, "Discovered service port is outside configured scan ports")
			}
			service := serviceLabel(port)
			application := upsert("services", fmt.Sprintf("service:%s:%d", S(asset, "id"), port), M{"name": fmt.Sprintf("%s :%d @ %s", service, port, S(asset, "name")), "assetId": asset["id"], "servicePort": port, "protocol": "TCP", "status": "Active", "autoDiscovered": true, "discoverySource": "TCP port response", "description": "TCP listener detected. Service identity is inferred from its port and needs confirmation.", "reviewStatus": "Identity unverified", "notes": "Service name inferred from the TCP port number; application identity is unverified."})
			upsert("dependencies", fmt.Sprintf("service-link:%s:%d", S(asset, "id"), port), M{"name": fmt.Sprintf("%s listens on TCP %d", S(asset, "name"), port), "sourceId": asset["id"], "targetId": application["id"], "targetPort": port, "protocol": "TCP", "status": "Observed", "purpose": "Discovered listening service", "autoDiscovered": true, "discoverySource": "TCP port response"})
			upsert("ports", fmt.Sprintf("service-port:%s:%d", S(asset, "id"), port), M{"name": fmt.Sprintf("TCP %d @ %s", port, S(asset, "name")), "assetId": asset["id"], "port": fmt.Sprint(port), "protocol": "TCP", "status": "Discovered", "autoDiscovered": true, "discoverySource": "TCP port response"})
		}
	}
	summary := M{"interfaces": interfaceCount, "neighbors": len(neighbors), "networksCreated": networkCount, "addressesCreated": addressCount, "devicesResponding": len(devices), "lastError": S(scan, "error"), "scanTargets": scan["targets"], "activeScanCompleted": len(scan) > 0}
	lastScan := profile["lastScanAt"]
	if len(scan) > 0 || S(snapshot, "requestedAt") != "" && S(snapshot, "requestedAt") == S(profile, "requestedAt") {
		lastScan = observed
	}
	a.run("INSERT INTO discovery_profiles(collector_id,config,last_scan_at,last_discovery_at,summary) VALUES(?,?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET last_scan_at=excluded.last_scan_at,last_discovery_at=excluded.last_discovery_at,summary=excluded.summary", cid, J(config), lastScan, observed, J(summary))
	return summary
}
func validGateway(gateway string, p netip.Prefix) string {
	ip, e := netip.ParseAddr(gateway)
	if e == nil && p.Contains(ip) {
		return gateway
	}
	return ""
}
func withinRanges(ip netip.Addr, cidrs []string) bool {
	for _, s := range cidrs {
		p, e := netip.ParsePrefix(s)
		if e == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *App) findNetwork(org, cidr string) M {
	for _, r := range a.q("SELECT * FROM records WHERE type='networks' AND org_id=? AND deleted IS NULL", org) {
		d := a.parsed(r)
		if S(d, "cidr") == cidr {
			return d
		}
	}
	return nil
}
func (a *App) findAddress(network, address string) M {
	for _, r := range a.q("SELECT * FROM records WHERE type='addresses' AND deleted IS NULL") {
		d := a.parsed(r)
		if S(d, "networkId") == network && S(d, "address") == address {
			return d
		}
	}
	return nil
}
func (a *App) findAsset(org, ip string) M {
	for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", org) {
		d := a.parsed(r)
		if S(d, "ip") == ip {
			return d
		}
	}
	return nil
}
func serviceLabel(port int) string {
	names := map[int]string{22: "SSH", 53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS", 389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS", 1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 6379: "Redis", 8006: "Proxmox HTTPS", 8080: "HTTP alternate", 8443: "HTTPS alternate"}
	if s := names[port]; s != "" {
		return s
	}
	return "TCP service"
}

func (a *App) observedUpdate(u, r, input M) M {
	d := clone(input)
	delete(d, "version")
	before := decode(S(r, "data"))
	compare := clone(d)
	delete(before, "lastSeen")
	delete(before, "uptimeSeconds")
	delete(compare, "lastSeen")
	delete(compare, "uptimeSeconds")
	if J(before) == J(compare) {
		a.run("UPDATE records SET data=?,updated=? WHERE id=?", J(d), timestamp(), S(r, "id"))
		return a.safe(a.get("SELECT * FROM records WHERE id=?", S(r, "id")))
	}
	d["version"] = r["version"]
	return a.update(u, r, d)
}

func (a *App) workspaceDiscoveryDefaults() M {
	if r := a.get("SELECT value FROM meta WHERE key='discovery_defaults'"); r != nil {
		return decode(S(r, "value"))
	}
	return decode(J(defaultDiscovery()))
}

func (a *App) touchObservation(u M, id, seen string) {
	r := a.get("SELECT * FROM records WHERE id=? AND deleted IS NULL", id)
	if r == nil {
		return
	}
	d := decode(S(r, "data"))
	if d["autoDiscovered"] != true {
		return
	}
	d["lastSeen"] = seen
	a.observedUpdate(u, r, d)
}
