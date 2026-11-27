package app

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func login(t *testing.T, a *App, email, password, code string) *apiClient {
	t.Helper()
	c := &apiClient{t: t, a: a}
	if status, m, _ := c.call("POST", "/api/login", M{"email": email, "password": password, "code": code}); status != 200 {
		t.Fatal("login", status, m)
	}
	_, me, _ := c.call("GET", "/api/me", nil)
	c.csrf = S(me, "csrf")
	return c
}

func seedVault(t *testing.T, c *apiClient) (org, cred, article M) {
	_, org, _ = c.call("POST", "/api/records", M{"type": "organizations", "name": "Org"})
	_, cred, _ = c.call("POST", "/api/records", M{"type": "passwords", "name": "Router", "orgId": org["id"], "password": "first-secret"})
	_, article, _ = c.call("POST", "/api/records", M{"type": "articles", "name": "Runbook", "orgId": org["id"], "content": "x"})
	if code, m, _ := c.call("POST", "/api/records/"+S(article, "id")+"/attachments", M{"name": "config.txt", "mime": "text/plain", "content": base64.StdEncoding.EncodeToString([]byte("PLAINTEXT-CONFIG-BACKUP"))}); code != 201 {
		t.Fatal(code, m)
	}
	return
}

func download(t *testing.T, c *apiClient, articleID string) string {
	_, rec, _ := c.call("GET", "/api/records/"+articleID, nil)
	files := A(rec["attachments"])
	if len(files) != 1 {
		t.Fatal("attachments", rec["attachments"])
	}
	f := obj(files[0])
	if N(f, "size") != float64(len("PLAINTEXT-CONFIG-BACKUP")) {
		t.Fatal("size", f["size"])
	}
	r := httptest.NewRequest("GET", "/api/attachments/"+S(f, "id"), nil)
	r.Host, r.RemoteAddr = "127.0.0.1:5173", "127.0.0.1:1"
	r.Header.Set("Cookie", c.cookie)
	w := httptest.NewRecorder()
	c.a.ServeHTTP(w, r)
	return w.Body.String()
}

func TestAttachmentsEncryptedAndPasswordHistoryHasNoSecrets(t *testing.T) {
	a, c := newAdmin(t)
	_, cred, article := seedVault(t, c)
	for _, row := range a.q("SELECT body FROM attachments") {
		if bytes.Contains(row["body"].([]byte), []byte("PLAINTEXT-CONFIG-BACKUP")) {
			t.Fatal("attachment stored in clear")
		}
	}
	_, current, _ := c.call("GET", "/api/records/"+S(cred, "id"), nil)
	c.call("PUT", "/api/records/"+S(cred, "id"), M{"name": "Router", "orgId": current["orgId"], "password": "second-secret", "version": current["version"]})
	for _, v := range a.q("SELECT data FROM versions WHERE record_id=?", S(cred, "id")) {
		if strings.Contains(S(v, "data"), "sealed") {
			t.Fatal("version history keeps a sealed secret")
		}
	}
	if got := download(t, c, S(article, "id")); got != "PLAINTEXT-CONFIG-BACKUP" {
		t.Fatal("download", got)
	}
}

func TestExistingPlainAttachmentsAreEncryptedOnStart(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	a.run("INSERT INTO attachments VALUES('old','r','a.txt','text/plain',?,'now')", []byte("OLD-PLAIN"))
	a.Close()
	b, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	body := b.get("SELECT body FROM attachments WHERE id='old'")["body"].([]byte)
	if bytes.Contains(body, []byte("OLD-PLAIN")) || string(b.unsealBytes(body)) != "OLD-PLAIN" {
		t.Fatal("legacy attachment not migrated")
	}
}

func TestPurgeRemovesRecordHistoryAndFiles(t *testing.T) {
	a, c := newAdmin(t)
	_, _, article := seedVault(t, c)
	articleID := S(article, "id")
	if code, m, _ := c.call("DELETE", "/api/trash/"+articleID, nil); code != 404 {
		t.Fatal("purged a live record", code, m)
	}
	c.call("DELETE", "/api/records/"+articleID, nil)
	if code, m, _ := c.call("DELETE", "/api/trash/"+articleID, nil); code != 200 {
		t.Fatal(code, m)
	}
	for _, q := range []string{"SELECT id FROM records WHERE id=?", "SELECT record_id FROM versions WHERE record_id=?", "SELECT id FROM attachments WHERE record_id=?"} {
		if a.get(q, articleID) != nil {
			t.Fatal("left behind:", q)
		}
	}
	if auditCount(a, "purge") != 1 {
		t.Fatal("purge not audited")
	}
	_, org, _ := c.call("POST", "/api/records", M{"type": "organizations", "name": "Org2"})
	_, old, _ := c.call("POST", "/api/records", M{"type": "articles", "name": "Old", "orgId": org["id"], "content": "x"})
	c.call("DELETE", "/api/records/"+S(old, "id"), nil)
	a.run("UPDATE records SET deleted=? WHERE id=?", time.Now().Add(-40*24*time.Hour).UTC().Format(time.RFC3339Nano), S(old, "id"))
	if _, m, _ := c.call("POST", "/api/trash/purge", M{"olderThanDays": 30}); N(m, "purged") != 1 {
		t.Fatal(m)
	}
}

func TestPurgeAndPolicyNeedAdmin(t *testing.T) {
	_, c := newAdmin(t)
	c.call("POST", "/api/users", M{"name": "Analyst", "email": "analyst@example.test", "password": "another-long-passphrase", "role": "it_analyst"})
	analyst := login(t, c.a, "analyst@example.test", "another-long-passphrase", "")
	if code, _, _ := analyst.call("POST", "/api/trash/purge", M{"olderThanDays": 0}); code != 403 {
		t.Fatal("non-admin purge", code)
	}
	if code, _, _ := analyst.call("PUT", "/api/settings/security", M{"requireMfa": false}); code != 403 {
		t.Fatal("non-admin policy change", code)
	}
}

func TestVaultKeyRotation(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	c := &apiClient{t: t, a: a}
	c.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase"})
	_, me, _ := c.call("GET", "/api/me", nil)
	c.csrf = S(me, "csrf")
	_, cred, article := seedVault(t, c)
	if e := RotateVaultKey(dir); e == nil || !strings.Contains(e.Error(), "in use") {
		t.Fatal("rotation ran while the server was running:", e)
	}
	before, _ := ExportVaultKey(dir)
	oldFile, _ := os.ReadFile(keyFilePath(dir))
	a.Close()
	if e := RotateVaultKey(dir); e != nil {
		t.Fatal(e)
	}
	after, _ := ExportVaultKey(dir)
	if after == before {
		t.Fatal("key did not change")
	}
	check := func() {
		b, err := New(Config{DataDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		c := login(t, b, "admin@example.test", "a-long-test-passphrase", "")
		if _, m, _ := c.call("POST", "/api/records/"+S(cred, "id")+"/reveal", M{"password": "a-long-test-passphrase"}); S(m, "password") != "first-secret" {
			t.Fatal("reveal after rotation", m)
		}
		if got := download(t, c, S(article, "id")); got != "PLAINTEXT-CONFIG-BACKUP" {
			t.Fatal("attachment after rotation", got)
		}
	}
	check()
	// Simulate a rotation that committed but did not swap the key file.
	newFile, _ := os.ReadFile(keyFilePath(dir))
	os.WriteFile(keyFilePath(dir)+".new", newFile, 0600)
	os.WriteFile(keyFilePath(dir), oldFile, 0600)
	check()
	if _, e := os.Stat(keyFilePath(dir) + ".new"); !os.IsNotExist(e) {
		t.Fatal("pending key left behind")
	}
	if _, e := os.Stat(filepath.Join(dir, "vault.key")); keyProtectionAvailable && !os.IsNotExist(e) {
		t.Fatal("plain key on disk")
	}
}

func TestMFAPolicy(t *testing.T) {
	a, c := newAdmin(t)
	if code, _, _ := c.call("PUT", "/api/settings/security", M{"requireMfa": true}); code != 400 {
		t.Fatal("policy enabled by an admin without MFA", code)
	}
	_, start, _ := c.call("POST", "/api/mfa/start", M{"password": "a-long-test-passphrase"})
	if code, m, _ := c.call("POST", "/api/mfa/confirm", M{"code": totp(S(start, "seed"), time.Now())}); code != 200 {
		t.Fatal(code, m)
	}
	if code, m, _ := c.call("PUT", "/api/settings/security", M{"requireMfa": true}); code != 200 {
		t.Fatal(code, m)
	}
	c.call("POST", "/api/users", M{"name": "Analyst", "email": "analyst@example.test", "password": "another-long-passphrase", "role": "it_analyst"})
	c.call("POST", "/api/users", M{"name": "Reader", "email": "reader@example.test", "password": "reader-long-passphrase", "role": "viewer"})
	analyst := login(t, a, "analyst@example.test", "another-long-passphrase", "")
	if code, _, _ := analyst.call("GET", "/api/records", nil); code != 403 {
		t.Fatal("vault editor without MFA got access", code)
	}
	_, me, _ := analyst.call("GET", "/api/me", nil)
	if obj(me["user"])["mfaRequired"] != true {
		t.Fatal(me)
	}
	_, start, _ = analyst.call("POST", "/api/mfa/start", M{"password": "another-long-passphrase"})
	if code, m, _ := analyst.call("POST", "/api/mfa/confirm", M{"code": totp(S(start, "seed"), time.Now())}); code != 200 {
		t.Fatal("enrolment blocked", code, m)
	}
	if code, _, _ := analyst.call("GET", "/api/records", nil); code != 200 {
		t.Fatal("enrolled user still blocked", code)
	}
	reader := login(t, a, "reader@example.test", "reader-long-passphrase", "")
	if code, _, _ := reader.call("GET", "/api/records", nil); code != 200 {
		t.Fatal("viewer blocked by vault MFA policy", code)
	}
}

func TestRecordFieldsAllowList(t *testing.T) {
	a, c := newAdmin(t)
	_, org, _ := c.call("POST", "/api/records", M{"type": "organizations", "name": "Org"})
	_, po, _ := c.call("POST", "/api/records", M{"type": "purchases", "name": "Laptops", "orgId": org["id"], "quantity": 2, "unitCost": 10, "receivedAssets": []string{"x"}, "approveAt": "2026-01-01", "evil": "<script>"})
	for _, k := range []string{"receivedAssets", "approveAt", "evil"} {
		if _, ok := po[k]; ok {
			t.Fatal("client set server field", k)
		}
	}
	_, asset, _ := c.call("POST", "/api/records", M{"type": "assets", "name": "PC", "orgId": org["id"], "category": "Computer", "customFields": M{"Asset tag": "A-1"}, "collectorId": "forged", "approvalStatus": "Approved", "approvedBy": "someone"})
	if S(asset, "approvalStatus") != "Approved" || asset["collectorId"] != nil || asset["approvedBy"] != nil {
		t.Fatal("client forged discovery state", asset)
	}
	a.run("UPDATE records SET data=json_set(data,'$.collectorId','c1','$.observedHostname','pc01') WHERE id=?", S(asset, "id"))
	_, current, _ := c.call("GET", "/api/records/"+S(asset, "id"), nil)
	current["collectorId"] = "forged"
	current["observedHostname"] = "forged"
	current["model"] = "T14"
	code, saved, _ := c.call("PUT", "/api/records/"+S(asset, "id"), current)
	if code != 200 || S(saved, "collectorId") != "c1" || S(saved, "observedHostname") != "pc01" || S(saved, "model") != "T14" || S(obj(saved["customFields"]), "Asset tag") != "A-1" {
		t.Fatal(code, saved)
	}
}
