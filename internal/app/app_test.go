package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "Test-account-passphrase-2026!"

type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func newServer(t *testing.T) (*App, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := New(Config{DataDir: dir, StaticDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a)
	t.Cleanup(func() { srv.Close(); a.Close() })
	return a, srv, dir
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar}}
}

func (c *client) call(method, path string, body any, headers ...string) (int, map[string]any) {
	c.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+"/api"+path, reader)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	var raw any
	json.NewDecoder(res.Body).Decode(&raw)
	if m, ok := raw.(map[string]any); ok {
		out = m
	} else {
		out = map[string]any{"items": raw}
	}
	return res.StatusCode, out
}

func setup(t *testing.T, base string) *client {
	t.Helper()
	c := newClient(t, base)
	status, body := c.call("POST", "/setup", map[string]any{"name": "Admin", "email": "admin@example.test", "password": testPassword})
	if status != 201 {
		t.Fatalf("setup: %d %v", status, body)
	}
	c.csrf = body["csrf"].(string)
	return c
}

func TestTOTPMatchesRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", truncated to six digits.
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for at, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924"} {
		if got := totp(seed, time.Unix(at, 0)); got != want {
			t.Errorf("totp(%d) = %s, want %s", at, got, want)
		}
	}
	if totp("not base32!", time.Now()) != "" {
		t.Error("invalid seed should produce no code")
	}
}

func TestPasswordHashing(t *testing.T) {
	stored := hashPassword(testPassword)
	if !strings.HasPrefix(stored, "pbkdf2$600000$") || strings.Contains(stored, testPassword) {
		t.Fatalf("unexpected hash format: %s", stored)
	}
	if !checkPassword(testPassword, stored) || checkPassword("wrong-password", stored) {
		t.Fatal("password verification failed")
	}
	if checkPassword(strings.Repeat("a", 5000), stored) {
		t.Fatal("oversized passwords must be rejected")
	}
}

func TestSealRoundTrip(t *testing.T) {
	a := &App{key: random(32)}
	sealed := a.seal("secret value")
	if strings.Contains(sealed, "secret") {
		t.Fatal("sealed value leaks plaintext")
	}
	if a.unseal(sealed) != "secret value" {
		t.Fatal("round trip failed")
	}
	if a.seal("x") == a.seal("x") {
		t.Fatal("nonces must be random")
	}
}

func TestSetupLoginAndProtection(t *testing.T) {
	_, srv, _ := newServer(t)
	anon := newClient(t, srv.URL)
	if _, body := anon.call("GET", "/status", nil); body["setupRequired"] != true || body["backend"] != "Go" {
		t.Fatalf("status before setup: %v", body)
	}
	if status, _ := anon.call("GET", "/records", nil); status != 401 {
		t.Fatalf("records without session: %d", status)
	}
	admin := setup(t, srv.URL)
	if status, _ := anon.call("POST", "/setup", map[string]any{"name": "Again", "email": "x@example.test", "password": testPassword}); status != 409 {
		t.Fatalf("second setup: %d", status)
	}
	if status, _ := admin.call("GET", "/me", nil); status != 200 {
		t.Fatalf("me: %d", status)
	}
	login := newClient(t, srv.URL)
	if status, _ := login.call("POST", "/login", map[string]any{"email": "admin@example.test", "password": "wrong-password"}); status != 401 {
		t.Fatalf("bad login: %d", status)
	}
	if status, _ := login.call("POST", "/login", map[string]any{"email": "ADMIN@example.test", "password": testPassword}); status != 200 {
		t.Fatalf("login: %d", status)
	}
}

func TestCSRFRequiredForMutations(t *testing.T) {
	_, srv, _ := newServer(t)
	admin := setup(t, srv.URL)
	token := admin.csrf
	admin.csrf = ""
	if status, _ := admin.call("POST", "/records", map[string]any{"type": "organizations", "name": "No token"}); status != 403 {
		t.Fatalf("missing CSRF accepted: %d", status)
	}
	admin.csrf = token
	if status, body := admin.call("POST", "/records", map[string]any{"type": "organizations", "name": "With token"}); status != 201 {
		t.Fatalf("create with CSRF: %d %v", status, body)
	}
}

func TestVaultSecretsEncryptedAtRest(t *testing.T) {
	_, srv, dir := newServer(t)
	admin := setup(t, srv.URL)
	_, org := admin.call("POST", "/records", map[string]any{"type": "organizations", "name": "Client"})
	status, cred := admin.call("POST", "/records", map[string]any{"type": "passwords", "name": "Root", "orgId": org["id"], "username": "root", "password": "SECRET-NEVER-PLAINTEXT-123"})
	if status != 201 {
		t.Fatalf("create credential: %d %v", status, cred)
	}
	if _, present := cred["password"]; present {
		t.Fatal("API response must not include the secret")
	}
	db, err := sql.Open("sqlite", DatabasePath(dir)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var data string
	if err := db.QueryRow("SELECT data FROM records WHERE id=?", cred["id"]).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, "SECRET-NEVER") {
		t.Fatal("secret stored in plaintext")
	}
	if status, _ := admin.call("POST", "/records/"+cred["id"].(string)+"/reveal", map[string]any{"password": "wrong"}); status != 401 {
		t.Fatalf("reveal with wrong password: %d", status)
	}
	status, secret := admin.call("POST", "/records/"+cred["id"].(string)+"/reveal", map[string]any{"password": testPassword})
	if status != 200 || secret["password"] != "SECRET-NEVER-PLAINTEXT-123" {
		t.Fatalf("reveal: %d %v", status, secret)
	}
}

func TestIPAMValidation(t *testing.T) {
	_, srv, _ := newServer(t)
	admin := setup(t, srv.URL)
	_, org := admin.call("POST", "/records", map[string]any{"type": "organizations", "name": "Client"})
	_, network := admin.call("POST", "/records", map[string]any{"type": "networks", "name": "LAN", "orgId": org["id"], "cidr": "10.0.0.0/24"})
	address := func(ip string) int {
		status, _ := admin.call("POST", "/records", map[string]any{"type": "addresses", "name": ip, "orgId": org["id"], "networkId": network["id"], "address": ip})
		return status
	}
	if s := address("10.0.0.10"); s != 201 {
		t.Fatalf("valid address: %d", s)
	}
	for ip, want := range map[string]int{"10.0.0.10": 409, "10.0.1.5": 400, "999.1.1.1": 400} {
		if s := address(ip); s != want {
			t.Errorf("address %s: got %d, want %d", ip, s, want)
		}
	}
}

func TestAPITokensAreReadOnly(t *testing.T) {
	_, srv, _ := newServer(t)
	admin := setup(t, srv.URL)
	status, created := admin.call("POST", "/tokens", map[string]any{"name": "Integration"})
	if status != 201 {
		t.Fatalf("create token: %d %v", status, created)
	}
	bearer := newClient(t, srv.URL)
	auth := []string{"Authorization", "Bearer " + created["token"].(string)}
	if s, _ := bearer.call("GET", "/records", nil, auth...); s != 200 {
		t.Fatalf("token read: %d", s)
	}
	if s, _ := bearer.call("POST", "/records", map[string]any{"type": "organizations", "name": "No"}, auth...); s != 403 {
		t.Fatalf("token write: %d", s)
	}
	if s, _ := bearer.call("GET", "/users", nil, auth...); s != 403 {
		t.Fatalf("token user access: %d", s)
	}
}

func TestStaticFrontendServed(t *testing.T) {
	dir, static := t.TempDir(), t.TempDir()
	if err := writeFile(filepath.Join(static, "index.html"), "<div id=root></div>"); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{DataDir: dir, StaticDir: static})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "root") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	rec = httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != 405 {
		t.Fatalf("POST to static: %d", rec.Code)
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0600) }

func TestLegacyDatabaseFileKept(t *testing.T) {
	dir := t.TempDir()
	if got := DatabasePath(dir); filepath.Base(got) != "infraledger.sqlite" {
		t.Fatalf("new workspace: %s", got)
	}
	if err := writeFile(filepath.Join(dir, "trinetra.sqlite"), ""); err != nil {
		t.Fatal(err)
	}
	if got := DatabasePath(dir); filepath.Base(got) != "trinetra.sqlite" {
		t.Fatalf("existing workspace must keep its database: %s", got)
	}
}

func TestUserGuideInstalled(t *testing.T) {
	a, srv, _ := newServer(t)
	admin := setup(t, srv.URL)
	guides := guideArticles()
	if len(guides) < 28 {
		t.Fatalf("expected a guide per page, got %d", len(guides))
	}
	_, list := admin.call("GET", "/records?type=articles", nil)
	count := 0
	for _, item := range list["items"].([]any) {
		if obj(item)["category"] == "User guide" {
			count++
		}
	}
	if count != len(guides) {
		t.Fatalf("setup installed %d guide articles, want %d", count, len(guides))
	}
	// Re-running changes nothing; an edited guide is restored as a new version.
	if status, body := admin.call("POST", "/guide", map[string]any{}); status != 200 || body["created"] != 0.0 || body["updated"] != 0.0 {
		t.Fatalf("repeat install: %d %v", status, body)
	}
	r := a.get("SELECT * FROM records WHERE type='articles' AND deleted IS NULL ORDER BY created LIMIT 1")
	data := decode(S(r, "data"))
	data["content"], data["version"] = "edited", r["version"]
	if status, _ := admin.call("PUT", "/records/"+S(r, "id"), data); status != 200 {
		t.Fatalf("edit guide: %d", status)
	}
	if _, body := admin.call("POST", "/guide", map[string]any{}); body["updated"] != 1.0 {
		t.Fatalf("refresh: %v", body)
	}
	viewer := newClient(t, srv.URL)
	admin.call("POST", "/users", map[string]any{"name": "V", "email": "v@example.test", "password": testPassword, "role": "viewer"})
	_, login := viewer.call("POST", "/login", map[string]any{"email": "v@example.test", "password": testPassword})
	viewer.csrf, _ = login["csrf"].(string)
	if status, _ := viewer.call("POST", "/guide", map[string]any{}); status != 403 {
		t.Fatalf("non-admin install: %d", status)
	}
}
