package app

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (a *App) recordRoute(req *http.Request, u, r M, action string, b M) result {
	method, recordID := req.Method, S(r, "id")
	kind := S(r, "type")
	if action == "" && method == "GET" {
		outRecord := a.safe(r)
		outRecord["favorite"] = a.get("SELECT user_id FROM favorites WHERE record_id=? AND user_id=?", recordID, S(u, "id")) != nil
		outRecord["attachments"] = a.q("SELECT id,name,mime,created,length(body) AS size FROM attachments WHERE record_id=?", recordID)
		outRecord["comments"] = []M{}
		if S(u, "role") != "client" {
			outRecord["comments"] = a.q("SELECT id,author,body,created FROM comments WHERE record_id=? ORDER BY created", recordID)
		}
		return out(200, outRecord)
	}
	if action == "" && method == "PUT" {
		requireWrite(u)
		return out(200, a.update(u, r, b))
	}
	if action == "" && method == "DELETE" {
		requireWrite(u)
		if kind == "organizations" && a.get("SELECT id FROM records WHERE org_id=? AND deleted IS NULL LIMIT 1", recordID) != nil {
			fail(409, "Move or delete organization records first")
		}
		for _, other := range a.q("SELECT data FROM records WHERE deleted IS NULL AND id<>?", recordID) {
			if linksTo(decode(S(other, "data")), recordID) {
				fail(409, "Unlink related records before deleting")
			}
		}
		a.run("UPDATE records SET deleted=? WHERE id=?", timestamp(), recordID)
		a.audit(u, "delete", recordID, kind)
		return out(200, M{"ok": true})
	}
	if action == "restore" && method == "POST" {
		requireWrite(u)
		a.validate(u, kind, decode(S(r, "data")), recordID)
		a.run("UPDATE records SET deleted=NULL WHERE id=?", recordID)
		a.audit(u, "restore", recordID, kind)
		return out(200, a.safe(a.get("SELECT * FROM records WHERE id=?", recordID)))
	}
	if action == "versions" && method == "GET" {
		if kind == "passwords" || S(u, "role") == "client" {
			fail(403, "Version history is unavailable for this record or role")
		}
		rows := a.q("SELECT * FROM versions WHERE record_id=? ORDER BY version DESC", recordID)
		for _, v := range rows {
			v["data"] = decode(S(v, "data"))
		}
		return out(200, rows)
	}
	if action == "revert" && method == "POST" {
		requireWrite(u)
		if contains([]string{"passwords", "purchases"}, kind) {
			fail(400, "This record does not support version restore")
		}
		version := a.get("SELECT data FROM versions WHERE record_id=? AND version=?", recordID, N(b, "targetVersion"))
		if version == nil {
			fail(404, "Version not found")
		}
		d := decode(S(version, "data"))
		d["version"] = b["version"]
		return out(200, a.update(u, r, d))
	}
	if action == "reveal" && method == "POST" {
		if kind != "passwords" || !contains([]string{"admin", "editor"}, S(u, "role")) {
			fail(403, "Vault access requires editor or administrator role")
		}
		if !checkPassword(S(b, "password"), S(u, "password")) || S(u, "mfa") != "" && !validOTP(fmt.Sprint(a.unseal(S(u, "mfa"))), S(b, "code")) {
			fail(401, "Reauthentication failed")
		}
		a.audit(u, "secret_reveal", recordID, "")
		secrets := obj(a.unseal(S(decode(S(r, "data")), "sealed")))
		var otp any
		if S(secrets, "totpSeed") != "" {
			otp = totp(S(secrets, "totpSeed"), time.Now())
		}
		return out(200, M{"password": secrets["password"], "totp": otp, "validFor": 30 - time.Now().Unix()%30})
	}
	if action == "favorite" && method == "POST" {
		if b["active"] == true {
			a.run("INSERT OR IGNORE INTO favorites VALUES(?,?)", S(u, "id"), recordID)
		} else {
			a.run("DELETE FROM favorites WHERE user_id=? AND record_id=?", S(u, "id"), recordID)
		}
		return out(200, M{"ok": true})
	}
	if action == "comments" && method == "POST" {
		requireWrite(u)
		text := strings.TrimSpace(S(b, "body"))
		if text == "" || len(text) > 5000 {
			fail(400, "Enter a comment of up to 5000 characters")
		}
		a.run("INSERT INTO comments VALUES(?,?,?,?,?,?)", id(), recordID, S(u, "id"), S(u, "name"), text, timestamp())
		a.audit(u, "comment", recordID, "")
		return out(201, M{"ok": true})
	}
	if action == "attachments" && method == "POST" {
		requireWrite(u)
		name := S(b, "name")
		if name == "" {
			fail(400, "File name is required")
		}
		bytes, e := base64.StdEncoding.DecodeString(S(b, "content"))
		if e != nil {
			fail(400, "Invalid file")
		}
		if len(bytes) > 5*1024*1024 {
			fail(413, "File limit is 5 MB")
		}
		name = strings.NewReplacer("\r", "_", "\n", "_", "/", "_", "\\", "_").Replace(name)
		if len(name) > 200 {
			name = name[:200]
		}
		a.run("INSERT INTO attachments VALUES(?,?,?,?,?,?)", id(), recordID, name, S(b, "mime"), bytes, timestamp())
		a.audit(u, "attachment_upload", recordID, "")
		return out(201, M{"ok": true})
	}
	if action == "purchase" && method == "POST" {
		requireWrite(u)
		if kind != "purchases" {
			fail(400, "Not a purchase order")
		}
		if N(b, "version") != N(r, "version") {
			fail(409, "Order changed. Reload before continuing")
		}
		d := decode(S(r, "data"))
		type transition struct {
			from []string
			to   string
		}
		transitions := map[string]transition{"submit": {[]string{"Draft"}, "Submitted"}, "approve": {[]string{"Submitted"}, "Approved"}, "order": {[]string{"Approved"}, "Ordered"}, "receive": {[]string{"Ordered"}, "Received"}, "cancel": {[]string{"Draft", "Submitted", "Approved", "Ordered"}, "Cancelled"}}
		t, ok := transitions[S(b, "action")]
		if !ok || !contains(t.from, S(d, "status")) {
			fail(409, "Invalid purchase order transition")
		}
		if S(b, "action") == "approve" {
			requireAdmin(u)
		}
		if S(b, "action") == "receive" {
			assets := []string{}
			for n := 0; n < int(N(d, "quantity")); n++ {
				name := S(d, "deviceName")
				if name == "" {
					name = S(d, "name")
				}
				category := S(d, "category")
				if category == "" {
					category = "Workstation"
				}
				asset := a.insert(u, "assets", M{"name": fmt.Sprintf("%s-%03d", name, n+1), "orgId": d["orgId"], "category": category, "model": d["model"], "status": "In stock", "purchaseId": recordID, "purchaseDate": a.day(), "cost": d["unitCost"], "currency": d["currency"], "notes": "Received from purchase order " + S(d, "name")})
				assets = append(assets, S(asset, "id"))
			}
			d["receivedAssets"] = assets
		}
		d["status"] = t.to
		d[S(b, "action")+"At"] = timestamp()
		version := int(N(r, "version")) + 1
		a.run("UPDATE records SET data=?,version=?,updated=? WHERE id=?", J(d), version, timestamp(), recordID)
		a.run("INSERT INTO versions VALUES(?,?,?,?,?)", recordID, version, J(d), S(u, "name"), timestamp())
		a.audit(u, "purchase_"+S(b, "action"), recordID, "")
		return out(200, a.safe(a.get("SELECT * FROM records WHERE id=?", recordID)))
	}
	fail(405, "Method not allowed")
	return result{}
}
