package app

import (
	"net/http"
	"strings"
)

// ---- Security policy (MFA enforcement) ----

func (a *App) securityPolicy() M {
	p := M{"requireMfa": false}
	if row := a.get("SELECT value FROM meta WHERE key='security_policy'"); row != nil {
		for k, v := range decode(S(row, "value")) {
			p[k] = v
		}
	}
	return p
}

// mfaRequired: with the policy on, administrators and anyone who can reveal
// vault credentials must use an authenticator.
func (a *App) mfaRequired(u M) bool {
	if a.securityPolicy()["requireMfa"] != true {
		return false
	}
	return S(u, "role") == "admin" || access(u, "passwords") == "edit"
}

// Routes a user without MFA may still use while enrolment is required.
var mfaEnrolmentPaths = []string{"/api/me", "/api/logout", "/api/mfa/start", "/api/mfa/confirm", "/api/password", "/api/settings/security"}

func (a *App) enforceMFA(u M, path, method string) {
	if S(u, "mfa") != "" || !a.mfaRequired(u) {
		return
	}
	if contains(mfaEnrolmentPaths, path) && (path != "/api/settings/security" || method == "GET") {
		return
	}
	fail(403, "Your organization requires authenticator MFA. Set it up to continue")
}

func (a *App) securityRoute(req *http.Request, u M, b M) result {
	if req.Method == "GET" {
		return out(200, a.securityPolicy())
	}
	if req.Method != "PUT" {
		fail(404, "Endpoint not found")
	}
	requireAdmin(u)
	requireMfa := b["requireMfa"] == true
	if requireMfa && S(u, "mfa") == "" {
		fail(400, "Set up authenticator MFA on your own account before requiring it for others")
	}
	policy := a.securityPolicy()
	policy["requireMfa"] = requireMfa
	a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('security_policy',?)", J(policy))
	detail := "MFA optional"
	if requireMfa {
		detail = "MFA required for administrators and vault editors"
	}
	a.audit(u, "security_policy_changed", "", detail)
	return out(200, policy)
}

// ---- Record field allow-list ----

var commonFields = []string{"name", "orgId", "notes", "visibility", "relatedIds", "customFields", "version"}

// clientFields lists what the browser may set for each record type; it mirrors
// the form schema in web/src/model.ts. Everything else is server-managed.
var clientFields = map[string][]string{
	"services":      {"assetId", "serviceKind", "serviceName", "executablePath", "startMode", "account", "processName", "pid", "servicePort", "protocol", "description", "status"},
	"applications":  {"assetId", "softwareVersion", "publisher", "installLocation", "servicePort", "protocol", "environment", "owner", "status"},
	"dependencies":  {"sourceId", "targetId", "sourcePort", "targetPort", "protocol", "purpose", "status"},
	"organizations": {"domain", "industry", "email", "phone", "status"},
	"locations":     {"address", "city", "region", "postal", "country", "timezone"},
	"contacts":      {"email", "phone", "title", "department", "locationId"},
	"assets":        {"category", "os", "manufacturer", "model", "serial", "ip", "mac", "status", "owner", "locationId", "rackId", "rackStart", "rackUnits", "purchaseDate", "cost", "expires", "templateId", "hostId"},
	"passwords":     {"username", "password", "url", "totpSeed", "expires"},
	"networks":      {"cidr", "vlan", "gateway", "dns", "locationId", "purpose"},
	"addresses":     {"networkId", "address", "assetId", "hostname", "mac", "status"},
	"ports":         {"assetId", "port", "connectedAssetId", "connectedPort", "speed", "vlan", "cable", "status"},
	"racks":         {"units", "locationId", "room", "power", "cooling"},
	"diagrams":      {"kind", "nodes", "edges"},
	"articles":      {"category", "status", "owner", "reviewDate", "content"},
	"procedures":    {"owner", "status", "reviewDate", "steps"},
	"purchases":     {"vendorId", "deviceName", "category", "model", "quantity", "unitCost", "currency", "purchaseDate", "status"},
	"vendors":       {"email", "phone", "website", "account", "support"},
	"licenses":      {"product", "quantity", "assigned", "cost", "expires", "status"},
	"domains":       {"domain", "registrar", "dns", "expires", "autoRenew"},
	"certificates":  {"hostname", "issuer", "fingerprint", "expires", "status"},
	"agreements":    {"provider", "owner", "cost", "expires", "noticeDays", "status"},
	"templates":     {"fields"},
}

func clientAllowed(kind, key string) bool {
	return contains(commonFields, key) || contains(clientFields[kind], key)
}

// fromClient keeps only fields the browser may set. For an update, every
// server-managed field keeps its stored value, so a client cannot forge
// workflow, discovery or approval data.
func fromClient(kind string, input M, existing M) M {
	out := M{}
	for k, v := range existing {
		if !clientAllowed(kind, k) {
			out[k] = v
		}
	}
	for k, v := range input {
		if clientAllowed(kind, k) {
			out[k] = v
		}
	}
	// On create, marking a device as discovered only sends it to the approval
	// queue (it can never approve anything), so it is accepted.
	if existing == nil && kind == "assets" && input["autoDiscovered"] == true {
		out["autoDiscovered"] = true
	}
	if custom, ok := out["customFields"].(map[string]any); ok {
		clean := M{}
		for k, v := range custom {
			if s, ok := v.(string); ok && len(k) <= 200 && len(s) <= 5000 && strings.TrimSpace(k) != "" {
				clean[k] = s
			}
		}
		out["customFields"] = clean
	} else if _, present := out["customFields"]; present {
		delete(out, "customFields")
	}
	return out
}
