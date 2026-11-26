package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type M = map[string]any
type apiError struct {
	Status  int
	Message string
}

func fail(status int, message string) { panic(apiError{status, message}) }
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func S(m M, k string) string {
	v := m[k]
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func N(m M, k string) float64 { v, _ := strconv.ParseFloat(S(m, k), 64); return v }
func A(v any) []any {
	if out, ok := v.([]any); ok {
		return out
	}
	return []any{}
}
func obj(v any) M {
	if out, ok := v.(map[string]any); ok {
		return out
	}
	return M{}
}
func strArray(v any) []string {
	out := []string{}
	for _, s := range A(v) {
		if text, ok := s.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
func J(v any) string       { b, e := json.Marshal(v); must(e); return string(b) }
func decode(s string) M    { var m M; must(json.Unmarshal([]byte(s), &m)); return m }
func clone(m M) M          { return decode(J(m)) }
func timestamp() string    { return time.Now().UTC().Format(time.RFC3339Nano) }
func (a *App) day() string { return time.Now().In(a.zone).Format("2006-01-02") }
func (a *App) q(query string, args ...any) []M {
	rows, e := a.db.Query(query, args...)
	must(e)
	defer rows.Close()
	cols, e := rows.Columns()
	must(e)
	out := []M{}
	for rows.Next() {
		values := make([]any, len(cols))
		pointers := make([]any, len(cols))
		for i := range values {
			pointers[i] = &values[i]
		}
		must(rows.Scan(pointers...))
		m := M{}
		for i, k := range cols {
			m[k] = values[i]
		}
		out = append(out, m)
	}
	must(rows.Err())
	return out
}
func (a *App) get(query string, args ...any) M {
	rows := a.q(query, args...)
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}
func (a *App) run(query string, args ...any) sql.Result {
	result, e := a.db.Exec(query, args...)
	must(e)
	return result
}
func (a *App) audit(u M, action, target, details string) {
	name := "System"
	var userID any
	if u != nil {
		name = S(u, "name")
		userID = u["id"]
	}
	a.run("INSERT INTO audit(user_id,actor,action,target,time,details) VALUES(?,?,?,?,?,?)", userID, name, action, target, timestamp(), details)
}
func (a *App) publicUser(u M) M {
	var orgs []any
	must(json.Unmarshal([]byte(S(u, "orgs")), &orgs))
	return M{"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "orgs": orgs, "active": N(u, "active") == 1, "mfa": S(u, "mfa") != "", "permissions": func() M {
		if S(u, "permissions") != "" {
			return decode(S(u, "permissions"))
		}
		return M{}
	}(), "pageAccess": publicAccess(u)}
}
func (a *App) parsed(r M) M {
	out := clone(r)
	for k, v := range decode(S(r, "data")) {
		out[k] = v
	}
	delete(out, "data")
	return out
}
func (a *App) safe(r M) M {
	out := a.parsed(r)
	if S(r, "type") == "passwords" {
		for _, k := range []string{"sealed", "password", "totpSeed"} {
			delete(out, k)
		}
		out["hasPassword"] = true
	}
	return out
}
func userOrgs(u M) []string {
	var orgs []any
	must(json.Unmarshal([]byte(S(u, "orgs")), &orgs))
	return strArray(orgs)
}
func (a *App) canRead(u, r M) bool {
	if r == nil {
		return false
	}
	if access(u, S(r, "type")) == "none" {
		return false
	}
	if S(u, "role") == "admin" {
		return true
	}
	orgs := userOrgs(u)
	scope := S(r, "org_id")
	if S(r, "type") == "organizations" {
		scope = S(r, "id")
	}
	if len(orgs) > 0 && !contains(orgs, scope) {
		return false
	}
	if S(u, "role") == "client" {
		if scope == "" || !contains(orgs, scope) {
			return false
		}
		if S(r, "type") == "organizations" {
			return true
		}
		if contains([]string{"passwords", "purchases", "vendors", "templates"}, S(r, "type")) {
			return false
		}
		return S(decode(S(r, "data")), "visibility") == "client"
	}
	return true
}
func requireWrite(u M) {
	for _, page := range permissionPages {
		if access(u, page) == "edit" {
			return
		}
	}
	fail(403, "Edit access required")
}
func requireAdmin(u M) {
	if S(u, "role") != "admin" {
		fail(403, "Administrator access required")
	}
}
func (a *App) raw(u M, id string, deleted bool) M {
	r := a.get("SELECT * FROM records WHERE id=?", id)
	if r == nil || !deleted && S(r, "deleted") != "" || !a.canRead(u, r) {
		fail(404, "Record not found")
	}
	return r
}
func (a *App) sameOrg(id, org, kind string) M {
	r := a.get("SELECT * FROM records WHERE id=? AND deleted IS NULL", id)
	if r == nil || kind != "" && S(r, "type") != kind {
		fail(400, "Linked record is unavailable")
	}
	if S(r, "type") == "organizations" && id != org || S(r, "org_id") != "" && S(r, "org_id") != org {
		fail(400, "Linked records must belong to the same organization")
	}
	return a.parsed(r)
}

var Types = []string{"services", "applications", "dependencies", "organizations", "locations", "contacts", "assets", "passwords", "networks", "addresses", "ports", "racks", "diagrams", "articles", "procedures", "purchases", "vendors", "licenses", "domains", "certificates", "agreements", "templates"}
var roles = []string{"admin", "editor", "viewer", "client", "it_analyst", "plant_it", "user"}
var emailPattern = regexp.MustCompile(`^\S+@\S+\.\S+$`)

func prefix(cidr string) netip.Prefix {
	p, e := netip.ParsePrefix(cidr)
	if e != nil || !p.Addr().Is4() {
		fail(400, "Enter an IPv4 subnet in CIDR notation, for example 10.0.0.0/24")
	}
	return p.Masked()
}
func (a *App) validate(u M, kind string, input M, recordID string) M {
	if !contains(Types, kind) {
		fail(400, "Unknown record type")
	}
	d := clone(input)
	for _, k := range []string{"id", "type", "data", "created", "updated", "deleted", "version", "org_id", "sealed", "hasPassword", "attachments", "comments", "favorite"} {
		delete(d, k)
	}
	name, ok := d["name"].(string)
	if !ok || strings.TrimSpace(name) == "" || len(name) > 200 {
		fail(400, "A name of up to 200 characters is required")
	}
	d["name"] = strings.TrimSpace(name)
	if kind == "organizations" {
		d["orgId"] = nil
	} else if kind == "templates" || kind == "vendors" {
		if S(d, "orgId") == "" {
			d["orgId"] = nil
		}
	} else if S(d, "orgId") == "" {
		fail(400, "Select an organization")
	}
	org := S(d, "orgId")
	if org != "" {
		r := a.get("SELECT * FROM records WHERE id=? AND type='organizations' AND deleted IS NULL", org)
		if r == nil || !withinOrgScope(u, r) {
			fail(400, "Organization unavailable")
		}
	}
	if !contains([]string{"internal", "client"}, S(d, "visibility")) {
		d["visibility"] = "internal"
	}
	switch kind {
	case "applications", "services":
		a.sameOrg(S(d, "assetId"), org, "assets")
		if S(d, "servicePort") != "" && (N(d, "servicePort") < 1 || N(d, "servicePort") > 65535 || float64(int(N(d, "servicePort"))) != N(d, "servicePort")) {
			fail(400, "Port must be between 1 and 65535")
		}
	case "dependencies":
		for _, k := range []string{"sourceId", "targetId"} {
			endpoint := a.sameOrg(S(d, k), org, "")
			if !contains([]string{"assets", "applications", "services"}, S(endpoint, "type")) {
				fail(400, "A dependency endpoint must be a device or application")
			}
		}
		if S(d, "sourceId") == S(d, "targetId") {
			fail(400, "Choose two different dependency endpoints")
		}
		if S(d, "targetPort") != "" && (N(d, "targetPort") < 1 || N(d, "targetPort") > 65535 || float64(int(N(d, "targetPort"))) != N(d, "targetPort")) {
			fail(400, "Port must be between 1 and 65535")
		}
	case "passwords":
		if _, exists := d["password"]; exists {
			if _, ok := d["password"].(string); !ok {
				fail(400, "Invalid password")
			}
		}
		if S(d, "totpSeed") != "" && totp(S(d, "totpSeed"), time.Now()) == "" {
			fail(400, "Invalid TOTP seed")
		}
		if S(d, "url") != "" && !strings.HasPrefix(S(d, "url"), "https://") && !strings.HasPrefix(S(d, "url"), "http://") {
			fail(400, "Credential URL must use http or https")
		}
		d["visibility"] = "internal"
	case "networks":
		p := prefix(S(d, "cidr"))
		if S(d, "gateway") != "" {
			addr, e := netip.ParseAddr(S(d, "gateway"))
			if e != nil || !p.Contains(addr) {
				fail(400, "Gateway must be inside the subnet")
			}
		}
		if S(d, "vlan") != "" && (N(d, "vlan") < 1 || N(d, "vlan") > 4094 || float64(int(N(d, "vlan"))) != N(d, "vlan")) {
			fail(400, "VLAN must be between 1 and 4094")
		}
		if recordID != "" {
			for _, r := range a.q("SELECT data FROM records WHERE type='addresses' AND deleted IS NULL") {
				v := decode(S(r, "data"))
				addr, _ := netip.ParseAddr(S(v, "address"))
				if S(v, "networkId") == recordID && !p.Contains(addr) {
					fail(409, "Subnet change would exclude an allocated address")
				}
			}
		}
	case "addresses":
		n := a.sameOrg(S(d, "networkId"), org, "networks")
		p := prefix(S(n, "cidr"))
		addr, e := netip.ParseAddr(S(d, "address"))
		if e != nil || !addr.Is4() {
			fail(400, "Enter a valid IPv4 address")
		}
		if !p.Contains(addr) {
			fail(400, "IP address is outside the network")
		}
		for _, r := range a.q("SELECT data FROM records WHERE type='addresses' AND deleted IS NULL AND id<>?", recordID) {
			v := decode(S(r, "data"))
			if S(v, "networkId") == S(d, "networkId") && S(v, "address") == S(d, "address") {
				fail(409, "IP address is already allocated")
			}
		}
		if S(d, "assetId") != "" {
			a.sameOrg(S(d, "assetId"), org, "assets")
		}
	case "racks":
		units := N(d, "units")
		if units < 1 || units > 60 || float64(int(units)) != units {
			fail(400, "Rack capacity must be 1–60 units")
		}
		d["units"] = units
		for _, r := range a.q("SELECT data FROM records WHERE type='assets' AND deleted IS NULL") {
			v := decode(S(r, "data"))
			if S(v, "rackId") == recordID && recordID != "" && N(v, "rackStart")+N(v, "rackUnits")-1 > units {
				fail(409, "Rack cannot be smaller than an installed device")
			}
		}
	case "assets":
		if S(d, "hostId") != "" {
			if S(d, "hostId") == recordID {
				fail(400, "A device cannot host itself")
			}
			a.sameOrg(S(d, "hostId"), org, "assets")
		}
		if S(d, "ip") != "" {
			if _, e := netip.ParseAddr(S(d, "ip")); e != nil {
				fail(400, "Invalid IP address")
			}
		}
		if S(d, "rackId") != "" {
			r := a.sameOrg(S(d, "rackId"), org, "racks")
			start, height := N(d, "rackStart"), N(d, "rackUnits")
			if start < 1 || height < 1 || float64(int(start)) != start || float64(int(height)) != height || start+height-1 > N(r, "units") {
				fail(400, "Device placement is outside rack capacity")
			}
			d["rackStart"] = start
			d["rackUnits"] = height
			for _, other := range a.q("SELECT data FROM records WHERE type='assets' AND deleted IS NULL AND id<>?", recordID) {
				v := decode(S(other, "data"))
				if S(v, "rackId") == S(d, "rackId") && start <= N(v, "rackStart")+N(v, "rackUnits")-1 && start+height-1 >= N(v, "rackStart") {
					fail(409, "Rack units overlap another device")
				}
			}
		}
		if S(d, "templateId") != "" {
			t := a.get("SELECT * FROM records WHERE id=? AND type='templates' AND deleted IS NULL", S(d, "templateId"))
			if t == nil || !a.canRead(u, t) {
				fail(400, "Template unavailable")
			}
		}
	case "ports":
		a.sameOrg(S(d, "assetId"), org, "assets")
		if S(d, "connectedAssetId") != "" {
			a.sameOrg(S(d, "connectedAssetId"), org, "assets")
		}
	case "purchases":
		if recordID == "" && S(d, "status") != "" && S(d, "status") != "Draft" {
			fail(400, "New purchase orders start as Draft")
		}
		if S(d, "status") == "" {
			d["status"] = "Draft"
		}
		quantity, cost := N(d, "quantity"), N(d, "unitCost")
		if quantity < 1 || quantity > 500 || float64(int(quantity)) != quantity || cost < 0 {
			fail(400, "Enter a valid quantity and unit cost")
		}
		d["quantity"] = quantity
		d["unitCost"] = cost
		if S(d, "currency") == "" {
			d["currency"] = "USD"
		}
		if !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(S(d, "currency")) {
			fail(400, "Use a three-letter currency code")
		}
		if S(d, "vendorId") != "" {
			v := a.get("SELECT * FROM records WHERE id=? AND type='vendors' AND deleted IS NULL", S(d, "vendorId"))
			if v == nil || !a.canRead(u, v) {
				fail(400, "Vendor unavailable")
			}
		}
	case "procedures":
		steps, ok := d["steps"].([]any)
		if !ok || len(steps) > 100 {
			fail(400, "A procedure needs a list of up to 100 steps")
		}
		for i, s := range steps {
			v := obj(s)
			text := S(v, "text")
			if len(text) > 1000 {
				fail(400, "Checklist step is too long")
			}
			steps[i] = M{"text": text, "done": v["done"] == true}
		}
		d["steps"] = steps
	case "templates":
		fields, ok := d["fields"].([]any)
		if !ok || len(fields) > 50 {
			fail(400, "Template fields must be a list of up to 50 field names")
		}
		out := []string{}
		for _, v := range fields {
			s, ok := v.(string)
			if !ok || len(s) > 200 {
				fail(400, "Invalid template field")
			}
			if s = strings.TrimSpace(s); s != "" && !contains(out, s) {
				out = append(out, s)
			}
		}
		d["fields"] = out
	case "diagrams":
		nodes, nok := d["nodes"].([]any)
		edges, eok := d["edges"].([]any)
		if !nok || !eok || len(nodes) > 200 || len(edges) > 500 {
			fail(400, "Diagram limit is 200 nodes and 500 connections")
		}
		ids := []string{}
		for _, v := range nodes {
			n := obj(v)
			nid := S(n, "id")
			if nid == "" || contains(ids, nid) {
				fail(400, "Invalid diagram node")
			}
			if _, ok := n["x"].(float64); !ok {
				fail(400, "Invalid node position")
			}
			if _, ok := n["y"].(float64); !ok {
				fail(400, "Invalid node position")
			}
			n["x"] = max(0, min(1800, N(n, "x")))
			n["y"] = max(0, min(1200, N(n, "y")))
			ids = append(ids, nid)
			if S(n, "assetId") != "" {
				a.sameOrg(S(n, "assetId"), org, "assets")
			}
		}
		for _, v := range edges {
			e := obj(v)
			if !contains(ids, S(e, "from")) || !contains(ids, S(e, "to")) || S(e, "from") == S(e, "to") {
				fail(400, "Invalid diagram connection")
			}
		}
	case "licenses":
		if N(d, "quantity") < 0 || N(d, "assigned") < 0 || N(d, "assigned") > N(d, "quantity") {
			fail(400, "Assigned seats cannot exceed purchased seats")
		}
	}
	if S(d, "locationId") != "" {
		a.sameOrg(S(d, "locationId"), org, "locations")
	}
	if related, ok := d["relatedIds"]; ok {
		links, ok := related.([]any)
		if !ok || len(links) > 100 {
			fail(400, "Too many related records")
		}
		unique := []string{}
		for _, link := range strArray(links) {
			if link == recordID || contains(unique, link) {
				continue
			}
			r := a.raw(u, link, false)
			if S(r, "org_id") != "" && S(r, "org_id") != org {
				fail(400, "Related records must belong to the same organization")
			}
			unique = append(unique, link)
		}
		d["relatedIds"] = unique
	}
	for _, k := range []string{"expires", "reviewDate", "purchaseDate"} {
		if S(d, k) != "" {
			v, e := time.Parse("2006-01-02", S(d, k))
			if e != nil || v.Format("2006-01-02") != S(d, k) {
				fail(400, "Dates must use valid YYYY-MM-DD calendar dates")
			}
		}
	}
	if len(J(d)) > 500000 {
		fail(400, "Record is too large")
	}
	return d
}
func (a *App) insert(u M, kind string, input M) M {
	requirePage(u, kind, "edit")
	if kind == "organizations" && S(u, "role") != "admin" && len(userOrgs(u)) > 0 {
		fail(403, "Only an administrator can add organizations for a scoped account")
	}
	d := a.validate(u, kind, input, "")
	if kind == "assets" {
		if d["autoDiscovered"] == true || d["observed"] == true {
			d["approvalStatus"] = "Pending"
		} else {
			d["approvalStatus"] = "Approved"
		}
	}
	recordID := id()
	if kind == "passwords" {
		d["sealed"] = a.seal(M{"password": S(d, "password"), "totpSeed": S(d, "totpSeed")})
		delete(d, "password")
		delete(d, "totpSeed")
	}
	time := timestamp()
	a.run("INSERT INTO records(id,type,org_id,data,created,updated) VALUES(?,?,?,?,?,?)", recordID, kind, d["orgId"], J(d), time, time)
	a.run("INSERT INTO versions VALUES(?,?,?,?,?)", recordID, 1, J(d), S(u, "name"), time)
	a.audit(u, "create", recordID, kind)
	return a.safe(a.get("SELECT * FROM records WHERE id=?", recordID))
}

var linkKeys = []string{"hostId", "sourceId", "targetId", "rackId", "networkId", "assetId", "connectedAssetId", "locationId", "templateId", "vendorId", "purchaseId"}

func linksTo(d M, target string) bool {
	for _, k := range linkKeys {
		if S(d, k) == target {
			return true
		}
	}
	return contains(strArray(d["relatedIds"]), target)
}
func (a *App) update(u, r, input M) M {
	a.recordWritable(u, r)
	if N(input, "version") != N(r, "version") {
		fail(409, "This record changed. Reload it before saving")
	}
	old := decode(S(r, "data"))
	d := a.validate(u, S(r, "type"), input, S(r, "id"))
	if S(r, "type") == "purchases" && (S(d, "status") != S(old, "status") || J(d["receivedAssets"]) != J(old["receivedAssets"])) {
		fail(400, "Use purchase workflow actions to change order status")
	}
	if S(r, "org_id") != S(d, "orgId") {
		for _, other := range a.q("SELECT data FROM records WHERE deleted IS NULL AND id<>?", S(r, "id")) {
			if linksTo(decode(S(other, "data")), S(r, "id")) {
				fail(409, "Unlink related records before moving organizations")
			}
		}
	}
	if S(r, "type") == "passwords" {
		secrets := obj(a.unseal(S(old, "sealed")))
		for _, k := range []string{"password", "totpSeed"} {
			if value, ok := d[k]; ok {
				secrets[k] = value
			}
			delete(d, k)
		}
		d["sealed"] = a.seal(secrets)
	}
	version := int(N(r, "version")) + 1
	time := timestamp()
	a.run("UPDATE records SET org_id=?,data=?,version=?,updated=? WHERE id=?", d["orgId"], J(d), version, time, S(r, "id"))
	a.run("INSERT INTO versions VALUES(?,?,?,?,?)", S(r, "id"), version, J(d), S(u, "name"), time)
	a.audit(u, "update", S(r, "id"), S(r, "type"))
	return a.safe(a.get("SELECT * FROM records WHERE id=?", S(r, "id")))
}
