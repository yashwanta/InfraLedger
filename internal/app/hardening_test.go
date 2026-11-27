package app

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net/http/httptest"
)

func rawRequest(a *App, method, path, host, remote, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Host, r.RemoteAddr = host, remote
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func newAdmin(t *testing.T) (*App, *apiClient) {
	t.Helper()
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	c := &apiClient{t: t, a: a}
	if code, m, _ := c.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase"}); code != 201 {
		t.Fatal(code, m)
	}
	_, me, _ := c.call("GET", "/api/me", nil)
	c.csrf = S(me, "csrf")
	return a, c
}

func auditCount(a *App, action string) int {
	return len(a.q("SELECT id FROM audit WHERE action=?", action))
}

func TestRejectsUnknownHostHeader(t *testing.T) {
	a, _ := newAdmin(t)
	if w := rawRequest(a, "GET", "/api/status", "attacker.example", "127.0.0.1:1", ""); w.Code != 421 {
		t.Fatal("rebinding host accepted:", w.Code)
	}
	for _, host := range []string{"127.0.0.1:5173", "localhost:5173", "192.168.10.5:5173", "[::1]:5173"} {
		if w := rawRequest(a, "GET", "/api/status", host, "127.0.0.1:1", ""); w.Code != 200 {
			t.Fatal(host, w.Code)
		}
	}
	a.config.AllowedHosts = []string{"docs.example.test"}
	if w := rawRequest(a, "GET", "/api/status", "docs.example.test", "127.0.0.1:1", ""); w.Code != 200 {
		t.Fatal("ALLOWED_HOSTS ignored:", w.Code)
	}
}

func TestRemoteSetupNeedsConsoleCode(t *testing.T) {
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.setupCode == "" {
		t.Fatal("no setup code generated")
	}
	body := `{"name":"Admin","email":"admin@example.test","password":"a-long-test-passphrase","setupCode":"WRONG"}`
	if w := rawRequest(a, "GET", "/api/status", "192.168.10.5:5173", "192.168.10.20:5555", ""); !strings.Contains(w.Body.String(), `"setupCodeRequired":true`) {
		t.Fatal(w.Body.String())
	}
	if w := rawRequest(a, "POST", "/api/setup", "192.168.10.5:5173", "192.168.10.20:5555", body); w.Code != 403 {
		t.Fatal("remote setup without code:", w.Code)
	}
	if auditCount(a, "setup_failed") != 1 {
		t.Fatal("failed setup not audited")
	}
	body = strings.Replace(body, "WRONG", strings.ToLower(a.setupCode), 1)
	if w := rawRequest(a, "POST", "/api/setup", "192.168.10.5:5173", "192.168.10.20:5555", body); w.Code != 201 {
		t.Fatal("remote setup with code:", w.Code, w.Body.String())
	}
	if a.setupCode != "" {
		t.Fatal("setup code not cleared")
	}
}

func TestFailedLoginsAreAuditedAndLimitedPerAccount(t *testing.T) {
	a, _ := newAdmin(t)
	bad := `{"email":"admin@example.test","password":"wrong-password-123"}`
	for i := 0; i < loginPerAccount; i++ {
		// A different address each time: the per-account limit must still apply.
		remote := "10.0.0." + string(rune('1'+i%9)) + ":1000"
		if w := rawRequest(a, "POST", "/api/login", "127.0.0.1:5173", remote, bad); w.Code != 401 {
			t.Fatal(i, w.Code, w.Body.String())
		}
	}
	if n := auditCount(a, "login_failed"); n != loginPerAccount {
		t.Fatal("failed sign-ins audited:", n)
	}
	good := `{"email":"admin@example.test","password":"a-long-test-passphrase"}`
	if w := rawRequest(a, "POST", "/api/login", "127.0.0.1:5173", "10.0.9.9:1000", good); w.Code != 429 {
		t.Fatal("account not locked after repeated failures:", w.Code)
	}
	if auditCount(a, "rate_limited") != 1 {
		t.Fatal("rate limit not audited")
	}
	unknown := `{"email":"nobody@example.test","password":"wrong-password-123"}`
	if w := rawRequest(a, "POST", "/api/login", "127.0.0.1:5173", "10.0.8.8:1000", unknown); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestLoginBodyIsSmall(t *testing.T) {
	a, _ := newAdmin(t)
	big := `{"email":"a@b.c","password":"` + strings.Repeat("x", smallBodyLimit) + `"}`
	if w := rawRequest(a, "POST", "/api/login", "127.0.0.1:5173", "127.0.0.1:1", big); w.Code != 413 {
		t.Fatal("oversized sign-in body accepted:", w.Code)
	}
}

func TestRevealReauthIsLimited(t *testing.T) {
	_, c := newAdmin(t)
	_, org, _ := c.call("POST", "/api/records", M{"type": "organizations", "name": "Org"})
	code, cred, _ := c.call("POST", "/api/records", M{"type": "passwords", "name": "Router", "orgId": org["id"], "password": "s3cret-value"})
	if code != 201 {
		t.Fatal(code, cred)
	}
	path := "/api/records/" + S(cred, "id") + "/reveal"
	for i := 0; i < reauthPerAccount; i++ {
		if code, _, _ := c.call("POST", path, M{"password": "wrong"}); code != 401 {
			t.Fatal(i, code)
		}
	}
	if code, _, _ := c.call("POST", path, M{"password": "a-long-test-passphrase"}); code != 429 {
		t.Fatal("reveal not limited:", code)
	}
	if n := auditCount(c.a, "secret_reveal_failed"); n != reauthPerAccount {
		t.Fatal("failed reveals audited:", n)
	}
}

func TestPasswordChangeRevokesAPITokens(t *testing.T) {
	a, c := newAdmin(t)
	if code, m, _ := c.call("POST", "/api/tokens", M{"name": "export"}); code != 201 {
		t.Fatal(code, m)
	}
	if code, m, _ := c.call("POST", "/api/password", M{"current": "a-long-test-passphrase", "password": "a-new-long-passphrase"}); code != 200 {
		t.Fatal(code, m)
	}
	if n := len(a.q("SELECT id FROM api_tokens")); n != 0 {
		t.Fatal("API tokens survived a password change:", n)
	}
}

func TestStaticServesFilesOnlyAndSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "assets"), 0700)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0600)
	os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("1"), 0600)
	a, err := New(Config{DataDir: t.TempDir(), StaticDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if w := rawRequest(a, "GET", "/assets/", "127.0.0.1:5173", "127.0.0.1:1", ""); w.Code != 404 {
		t.Fatal("directory listing served:", w.Code)
	}
	w := rawRequest(a, "GET", "/assets/app.js", "127.0.0.1:5173", "127.0.0.1:1", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if rawRequest(a, "GET", "/", "127.0.0.1:5173", "127.0.0.1:1", "").Code != 200 {
		t.Fatal("index not served")
	}
	for _, h := range []string{"Permissions-Policy", "Cross-Origin-Opener-Policy", "Content-Security-Policy", "X-Frame-Options"} {
		if w.Header().Get(h) == "" {
			t.Fatal("missing header", h)
		}
	}
}

func TestPlainVaultKeyIsConvertedToProtectedStorage(t *testing.T) {
	if !keyProtectionAvailable {
		t.Skip("no OS key protection on this platform")
	}
	dir := t.TempDir()
	key := random(32)
	os.WriteFile(filepath.Join(dir, "vault.key"), key, 0600)
	a, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.seal("hello")
	a.Close()
	if _, e := os.Stat(filepath.Join(dir, "vault.key")); !os.IsNotExist(e) {
		t.Fatal("plain vault.key was not removed")
	}
	blob, _ := os.ReadFile(filepath.Join(dir, "vault.key.protected"))
	if bytes.Contains(blob, key) {
		t.Fatal("protected file contains the raw key")
	}
	b, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.unseal(sealed) != "hello" {
		t.Fatal("key changed after conversion")
	}
	exported, err := ExportVaultKey(dir)
	if err != nil || exported != base64.StdEncoding.EncodeToString(key) {
		t.Fatal("recovery export mismatch", err)
	}
}

func TestLoginLimitSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	c := &apiClient{t: t, a: a}
	c.call("POST", "/api/setup", M{"name": "Admin", "email": "admin@example.test", "password": "a-long-test-passphrase"})
	bad := `{"email":"admin@example.test","password":"wrong-password-123"}`
	for i := 0; i < loginPerAccount; i++ {
		rawRequest(a, "POST", "/api/login", "127.0.0.1:5173", "10.9.9.9:1", bad)
	}
	a.Close()
	b, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	good := `{"email":"admin@example.test","password":"a-long-test-passphrase"}`
	if w := rawRequest(b, "POST", "/api/login", "127.0.0.1:5173", "10.9.9.8:1", good); w.Code != 429 {
		t.Fatal("restart reset the sign-in limit:", w.Code)
	}
}
