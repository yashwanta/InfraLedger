package app

import "time"

func (a *App) seed(u M) {
	if a.get("SELECT id FROM records LIMIT 1") != nil {
		return
	}
	org := a.insert(u, "organizations", M{"name": "Acme Corporation", "domain": "acme.example", "industry": "Technology", "status": "Active", "notes": "Fictional sample organization"})
	oid := S(org, "id")
	add := func(kind, name string, fields M) M {
		fields["name"] = name
		fields["orgId"] = oid
		return a.insert(u, kind, fields)
	}
	location := add("locations", "Headquarters", M{"address": "100 Example Avenue", "city": "New York", "country": "United States"})
	rack := add("racks", "HQ — Server rack A", M{"units": 24, "locationId": location["id"], "notes": "Fictional example rack"})
	firewall := add("assets", "ACME-FW01", M{"category": "Firewall", "model": "NGFW-100", "ip": "10.10.1.1", "serial": "DEMO-FW-001", "status": "Active", "rackId": rack["id"], "rackStart": 22, "rackUnits": 1, "locationId": location["id"]})
	sw := add("assets", "ACME-SW01", M{"category": "Switch", "model": "48-port PoE", "ip": "10.10.1.2", "status": "Active", "rackId": rack["id"], "rackStart": 20, "rackUnits": 1})
	server := add("assets", "ACME-DC01", M{"category": "Server", "model": "Virtualization host", "ip": "10.10.1.10", "status": "Active", "rackId": rack["id"], "rackStart": 15, "rackUnits": 2})
	network := add("networks", "HQ management", M{"cidr": "10.10.1.0/24", "vlan": 10, "gateway": "10.10.1.1", "dns": "10.10.1.10"})
	add("addresses", "Firewall management", M{"networkId": network["id"], "address": "10.10.1.1", "assetId": firewall["id"], "status": "Assigned"})
	add("ports", "Port 1 — Core uplink", M{"assetId": firewall["id"], "port": "LAN1", "connectedAssetId": sw["id"], "connectedPort": "Gi1/0/48", "speed": "1 Gbps", "vlan": "10", "cable": "CAT6-001", "status": "Connected"})
	add("articles", "New employee onboarding", M{"category": "Operations", "content": "# New employee onboarding\n\n1. Confirm approval and start date.\n2. Create the user account and assign licenses.\n3. Enroll the device and register MFA.\n4. Verify access and record the handover.", "status": "Published", "reviewDate": time.Now().In(a.zone).AddDate(0, 3, 0).Format("2006-01-02"), "visibility": "client", "relatedIds": []string{S(server, "id")}})
	add("procedures", "Quarterly restore verification", M{"owner": S(u, "name"), "steps": []M{{"text": "Select a recent backup", "done": false}, {"text": "Restore in an isolated environment", "done": false}, {"text": "Verify application and file integrity", "done": false}}, "status": "In progress"})
	add("passwords", "Sample firewall administrator", M{"username": "demo-admin", "password": "Fictional-Example-Only!", "url": "https://firewall.example", "relatedIds": []string{S(firewall, "id")}, "notes": "Fictional credential for exploring the vault. Replace samples before operational use."})
	expires := time.Now().In(a.zone).AddDate(0, 0, 20).Format("2006-01-02")
	add("certificates", "acme.example wildcard", M{"issuer": "Example CA", "expires": expires, "status": "Active"})
	add("licenses", "Productivity suite", M{"quantity": 25, "assigned": 22, "expires": expires, "status": "Active"})
	vendor := a.insert(u, "vendors", M{"name": "Example Hardware Supplier", "email": "sales@supplier.example", "website": "https://supplier.example"})
	add("purchases", "PO-2026-001 · Workstations", M{"vendorId": vendor["id"], "deviceName": "ACME-LAPTOP", "category": "Laptop", "model": "Business 14", "quantity": 3, "unitCost": 1200, "currency": "USD", "status": "Draft"})
	add("diagrams", "HQ network flow", M{"kind": "Network flow", "nodes": []M{{"id": "internet", "label": "Internet", "kind": "cloud", "x": 80, "y": 180}, {"id": "firewall", "label": "ACME-FW01", "kind": "firewall", "x": 360, "y": 180, "assetId": firewall["id"]}, {"id": "switch", "label": "ACME-SW01", "kind": "switch", "x": 640, "y": 180, "assetId": sw["id"]}, {"id": "server", "label": "ACME-DC01", "kind": "server", "x": 920, "y": 180, "assetId": server["id"]}}, "edges": []M{{"from": "internet", "to": "firewall", "label": "WAN · HTTPS"}, {"from": "firewall", "to": "switch", "label": "LAN · VLAN 10"}, {"from": "switch", "to": "server", "label": "1 Gbps"}}})
	a.insert(u, "templates", M{"name": "Managed workstation", "fields": []string{"Operating system", "CPU", "Memory", "Disk encryption", "RMM agent"}})
}
