package app

import "strings"

var permissionPages = []string{"dashboard", "organizations", "favorites", "articles", "procedures", "passwords", "assets", "services", "applications", "dependencies", "discovery", "application-map", "workstations", "servers", "virtual-machines", "dependency-map", "networks", "addresses", "ports", "racks", "diagrams", "purchases", "vendors", "licenses", "domains", "certificates", "agreements", "locations", "contacts", "renewals", "reports", "trash", "settings", "users", "integrations", "api-access", "collectors", "templates", "activity"}

func roleAccess(role, page string) string {
	if role == "admin" {
		return "edit"
	}
	if page == "settings" {
		return "view"
	}
	if role == "client" {
		if contains([]string{"dashboard", "organizations", "favorites", "articles", "procedures", "assets", "services", "applications", "dependencies", "application-map", "workstations", "servers", "virtual-machines", "dependency-map", "networks", "addresses", "ports", "racks", "diagrams", "licenses", "domains", "certificates", "agreements", "locations", "contacts", "renewals"}, page) {
			return "view"
		}
		return "none"
	}
	if contains([]string{"users", "api-access", "collectors", "templates", "activity"}, page) {
		return "none"
	}
	switch role {
	case "editor", "it_analyst":
		if contains([]string{"dashboard", "favorites", "renewals", "reports", "integrations", "application-map", "workstations", "servers", "virtual-machines", "dependency-map", "discovery"}, page) {
			return "view"
		}
		return "edit"
	case "plant_it":
		if contains([]string{"assets", "services", "applications", "dependencies", "networks", "addresses", "ports", "racks", "diagrams", "locations", "contacts", "articles", "procedures"}, page) {
			return "edit"
		}
		if contains([]string{"dashboard", "organizations", "favorites", "application-map", "workstations", "servers", "virtual-machines", "dependency-map", "discovery", "renewals", "reports", "passwords", "licenses", "domains", "certificates", "agreements"}, page) {
			return "view"
		}
		return "none"
	case "viewer":
		return "view"
	case "user":
		if contains([]string{"dashboard", "favorites", "articles", "procedures"}, page) {
			return "view"
		}
		return "none"
	}
	return "none"
}
func access(u M, page string) string {
	if S(u, "role") == "admin" {
		return "edit"
	}
	if !contains(permissionPages, page) {
		return "none"
	}
	permissions := M{}
	if S(u, "permissions") != "" {
		permissions = decode(S(u, "permissions"))
	}
	value := S(permissions, page)
	if contains([]string{"none", "view", "edit"}, value) {
		return value
	}
	return roleAccess(S(u, "role"), page)
}
func requirePage(u M, page, level string) {
	value := access(u, page)
	if value == "none" || level == "edit" && value != "edit" {
		fail(403, "You do not have "+level+" access to this page")
	}
}
func publicAccess(u M) M {
	pages := M{}
	for _, p := range permissionPages {
		pages[p] = access(u, p)
	}
	return pages
}
func validatePermissions(value any) M {
	if value == nil {
		return M{}
	}
	permissions, ok := value.(map[string]any)
	if !ok {
		fail(400, "Page access must be an object")
	}
	for page, level := range permissions {
		if !contains(permissionPages, page) || !contains([]string{"none", "view", "edit"}, textValue(level)) {
			fail(400, "Invalid page access selection")
		}
	}
	return permissions
}
func textValue(v any) string { s, _ := v.(string); return strings.TrimSpace(s) }

// Organization scope is independent of page access; names are provided separately for reference fields.
func withinOrgScope(u, r M) bool {
	if r == nil {
		return false
	}
	if S(u, "role") == "admin" {
		return true
	}
	scope := S(r, "org_id")
	if S(r, "type") == "organizations" {
		scope = S(r, "id")
	}
	orgs := userOrgs(u)
	return len(orgs) == 0 && S(u, "role") != "client" || contains(orgs, scope)
}
func (a *App) recordWritable(u, r M) {
	requirePage(u, S(r, "type"), "edit")
	if !withinOrgScope(u, r) {
		fail(404, "Record not found")
	}
}
