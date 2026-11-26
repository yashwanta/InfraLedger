package app

import (
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type attempt struct {
	Count int
	Reset time.Time
}
type enrollment struct {
	Seed    string
	Expires time.Time
}
type Config struct {
	DataDir, StaticDir, Origin, TimeZone string
	SecureCookie                         bool
}
type App struct {
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
	backgroundWG     sync.WaitGroup
	db               *sql.DB
	key              []byte
	mu               sync.Mutex
	config           Config
	zone             *time.Location
	attempts         map[string]attempt
	pending          map[string]enrollment
	eventsMu         sync.Mutex
	subscribers      map[chan struct{}]struct{}
}
type result struct {
	status  int
	body    any
	headers http.Header
	file    []byte
}

func out(status int, body any) result { return result{status: status, body: body} }
func New(config Config) (*App, error) {
	if config.DataDir == "" {
		config.DataDir = "data"
	}
	if config.StaticDir == "" {
		config.StaticDir = "dist"
	}
	if config.TimeZone == "" {
		config.TimeZone = "America/New_York"
	}
	zone, e := time.LoadLocation(config.TimeZone)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(config.DataDir, 0700); e != nil {
		return nil, e
	}
	keyPath := filepath.Join(config.DataDir, "vault.key")
	var key []byte
	if value := os.Getenv("VAULT_KEY"); value != "" {
		key, e = base64.StdEncoding.DecodeString(value)
	} else {
		key, e = os.ReadFile(keyPath)
		if errors.Is(e, os.ErrNotExist) {
			key = random(32)
			var file *os.File
			file, e = os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if errors.Is(e, os.ErrExist) {
				key, e = os.ReadFile(keyPath)
			} else if e == nil {
				_, e = file.Write(key)
				closeErr := file.Close()
				if e == nil {
					e = closeErr
				}
			}
		}
	}
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must contain 32 bytes")
	}
	db, e := sql.Open("sqlite", filepath.Join(config.DataDir, "trinetra.sqlite"))
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL,orgs TEXT NOT NULL DEFAULT '[]',active INTEGER NOT NULL DEFAULT 1,mfa TEXT,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),csrf TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,type TEXT NOT NULL,org_id TEXT,data TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,created TEXT NOT NULL,updated TEXT NOT NULL,deleted TEXT);
 CREATE INDEX IF NOT EXISTS records_type ON records(type,org_id,deleted);
 CREATE TABLE IF NOT EXISTS versions(record_id TEXT NOT NULL,version INTEGER NOT NULL,data TEXT NOT NULL,actor TEXT NOT NULL,time TEXT NOT NULL,PRIMARY KEY(record_id,version));
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,time TEXT NOT NULL,details TEXT);
 CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY,record_id TEXT NOT NULL,name TEXT NOT NULL,mime TEXT NOT NULL,body BLOB NOT NULL,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY,record_id TEXT NOT NULL,user_id TEXT NOT NULL,author TEXT NOT NULL,body TEXT NOT NULL,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS favorites(user_id TEXT NOT NULL,record_id TEXT NOT NULL,PRIMARY KEY(user_id,record_id));
 CREATE TABLE IF NOT EXISTS api_tokens(id TEXT PRIMARY KEY,hash TEXT UNIQUE NOT NULL,user_id TEXT NOT NULL,name TEXT NOT NULL,created TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS collectors(id TEXT PRIMARY KEY,name TEXT NOT NULL,org_id TEXT NOT NULL,asset_id TEXT NOT NULL,user_id TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,created TEXT NOT NULL,expires INTEGER NOT NULL,last_seen TEXT);
 CREATE TABLE IF NOT EXISTS proxmox_connections(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,user_id TEXT NOT NULL,config TEXT NOT NULL,sealed TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Queued',summary TEXT NOT NULL DEFAULT '{}',last_sync TEXT,next_run INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS discovery_profiles(collector_id TEXT PRIMARY KEY,config TEXT NOT NULL,requested_at TEXT,last_scan_at TEXT,last_discovery_at TEXT,summary TEXT NOT NULL DEFAULT '{}');`)
	if e != nil {
		db.Close()
		return nil, e
	}
	columns, queryErr := db.Query("PRAGMA table_info(users)")
	if queryErr != nil {
		db.Close()
		return nil, queryErr
	}
	hasPermissions := false
	for columns.Next() {
		var cid, notNull, pk int
		var name, kind string
		var def any
		if scanErr := columns.Scan(&cid, &name, &kind, &notNull, &def, &pk); scanErr != nil {
			columns.Close()
			db.Close()
			return nil, scanErr
		}
		if name == "permissions" {
			hasPermissions = true
		}
	}
	columns.Close()
	if !hasPermissions {
		if _, migrationErr := db.Exec("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'"); migrationErr != nil {
			db.Close()
			return nil, migrationErr
		}
	}

	// Reclassify only collector-created process/port observations; keep IDs and links.
	if _, migrationErr := db.Exec(`UPDATE records SET type='services' WHERE type='applications' AND json_extract(data,'$.collectorId') IS NOT NULL AND (json_extract(data,'$.sourceKey') LIKE 'app:%' OR json_extract(data,'$.sourceKey') LIKE 'service:%')`); migrationErr != nil {
		db.Close()
		return nil, migrationErr
	}
	// Previously unclassified local discovery records now require review.
	if _, err := db.Exec(`UPDATE records SET data=json_set(data,'$.approvalStatus','Pending') WHERE type='assets' AND deleted IS NULL AND json_extract(data,'$.autoDiscovered')=1 AND json_extract(data,'$.category')='Network endpoint' AND json_extract(data,'$.approvalStatus') IS NULL`); err != nil {
		db.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{db: db, key: key, zone: zone, config: config, attempts: map[string]attempt{}, pending: map[string]enrollment{}, backgroundCtx: ctx, backgroundCancel: cancel}
	a.startProxmox()
	return a, nil
}
func (a *App) Close() error { a.backgroundCancel(); a.backgroundWG.Wait(); return a.db.Close() }
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(a.config.StaticDir, "index.html"))
			return
		}
		http.FileServer(http.Dir(a.config.StaticDir)).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/api/events" {
		a.serveEvents(w, r)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	transaction := false
	defer func() {
		if p := recover(); p != nil {
			if transaction {
				a.db.Exec("ROLLBACK")
			}
			status, message := 500, "Internal error. Check the server log."
			if e, ok := p.(apiError); ok {
				status, message = e.Status, e.Message
			} else {
				log.Printf("Request failed: %v", p)
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(M{"error": message})
		}
	}()
	mutating := r.Method != "GET" && r.Method != "HEAD"
	body := M{}
	if mutating {
		origin := r.Header.Get("Origin")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if origin != "" && origin != scheme+"://"+r.Host && origin != a.config.Origin {
			fail(403, "Cross-origin requests are not allowed")
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(403, "Cross-site request rejected")
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(415, "Use application/json")
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 9*1024*1024))
		if e := decoder.Decode(&body); e != nil && e != io.EOF {
			var max *http.MaxBytesError
			if errors.As(e, &max) {
				fail(413, "Request exceeds 9 MB")
			}
			fail(400, "Invalid JSON")
		}
		if body == nil {
			fail(400, "Request body must be an object")
		}
		a.run("BEGIN IMMEDIATE")
		transaction = true
	}
	result := a.route(r, body)
	if transaction {
		a.run("COMMIT")
		transaction = false
		a.broadcast()
	}
	for k, values := range result.headers {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	if result.status == 0 {
		result.status = 200
	}
	if result.file != nil {
		w.WriteHeader(result.status)
		w.Write(result.file)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(result.status)
	json.NewEncoder(w).Encode(result.body)
}
func (a *App) session(r *http.Request) (M, M, bool) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		t := a.get("SELECT * FROM api_tokens WHERE hash=? AND expires>?", digest(strings.TrimPrefix(auth, "Bearer ")), time.Now().UnixMilli())
		if t == nil {
			return nil, nil, true
		}
		return a.get("SELECT * FROM users WHERE id=? AND active=1", S(t, "user_id")), nil, true
	}
	cookie, e := r.Cookie("trinetra_session")
	if e != nil {
		return nil, nil, false
	}
	s := a.get("SELECT * FROM sessions WHERE token=? AND expires>?", digest(cookie.Value), time.Now().UnixMilli())
	if s == nil {
		return nil, nil, false
	}
	return a.get("SELECT * FROM users WHERE id=? AND active=1", S(s, "user_id")), s, false
}
func (a *App) createSession(u M) result {
	rawToken, csrf := token(32), token(24)
	a.run("DELETE FROM sessions WHERE expires<?", time.Now().UnixMilli())
	a.run("INSERT INTO sessions VALUES(?,?,?,?)", digest(rawToken), S(u, "id"), csrf, time.Now().Add(8*time.Hour).UnixMilli())
	cookie := (&http.Cookie{Name: "trinetra_session", Value: rawToken, Path: "/", HttpOnly: true, Secure: a.config.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 28800}).String()
	return result{status: 200, body: M{"user": a.publicUser(u), "csrf": csrf}, headers: http.Header{"Set-Cookie": []string{cookie}}}
}
func (a *App) visible(u M, where string, args ...any) []M {
	out := []M{}
	for _, r := range a.q("SELECT * FROM records WHERE "+where+" ORDER BY updated DESC", args...) {
		if a.canRead(u, r) {
			out = append(out, a.safe(r))
		}
	}
	return out
}
func (a *App) route(req *http.Request, b M) result {
	path, method := req.URL.Path, req.Method
	if path == "/api/status" && method == "GET" {
		return out(200, M{"setupRequired": a.get("SELECT id FROM users LIMIT 1") == nil, "name": "Trinetra IT", "version": "1.0.0", "timeZone": a.config.TimeZone, "backend": "Go", "frontend": "React + TypeScript"})
	}
	if path == "/api/setup" && method == "POST" {
		if a.get("SELECT id FROM users LIMIT 1") != nil {
			fail(409, "Workspace already initialized")
		}
		if strings.TrimSpace(S(b, "name")) == "" || !emailPattern.MatchString(S(b, "email")) {
			fail(400, "Enter your name and a valid email")
		}
		strongPassword(S(b, "password"))
		uid := id()
		a.run("INSERT INTO users(id,email,name,password,role,created) VALUES(?,?,?,?,?,?)", uid, strings.ToLower(S(b, "email")), strings.TrimSpace(S(b, "name")), hashPassword(S(b, "password")), "admin", timestamp())
		u := a.get("SELECT * FROM users WHERE id=?", uid)
		a.audit(u, "workspace_setup", "", "")
		if S(b, "discoveryCIDR") != "" {
			defaults := defaultDiscovery()
			defaults["cidrs"] = []any{S(b, "discoveryCIDR")}
			defaults = validateDiscovery(defaults)
			a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('discovery_defaults',?)", J(defaults))
		}
		if b["samples"] == true {
			a.seed(u)
		}
		r := a.createSession(u)
		r.status = 201
		return r
	}
	if path == "/api/login" && method == "POST" {
		address, _, _ := net.SplitHostPort(req.RemoteAddr)
		bucket := a.attempts[address]
		if time.Now().After(bucket.Reset) {
			bucket = attempt{Reset: time.Now().Add(15 * time.Minute)}
		}
		if bucket.Count >= 10 {
			fail(429, "Too many login attempts. Try again in 15 minutes")
		}
		bucket.Count++
		a.attempts[address] = bucket
		u := a.get("SELECT * FROM users WHERE email=? AND active=1", strings.ToLower(S(b, "email")))
		if u == nil || !checkPassword(S(b, "password"), S(u, "password")) {
			fail(401, "Invalid email or password")
		}
		if S(u, "mfa") != "" && !validOTP(fmt.Sprint(a.unseal(S(u, "mfa"))), S(b, "code")) {
			fail(401, "Enter a valid six-digit authenticator code")
		}
		delete(a.attempts, address)
		a.audit(u, "login", "", "")
		return a.createSession(u)
	}
	if path == "/api/telemetry" && method == "POST" {
		return a.telemetry(req, b)
	}
	if path == "/api/discovery/config" && method == "GET" {
		collector, _, _ := a.collectorAuth(req)
		return out(200, a.discoveryProfile(S(collector, "id")))
	}
	u, session, isAPI := a.session(req)
	if u == nil {
		fail(401, "Sign in required")
	}
	mutating := method != "GET" && method != "HEAD"
	if mutating && !isAPI && req.Header.Get("X-CSRF-Token") != S(session, "csrf") {
		fail(403, "Session verification failed. Refresh and try again")
	}
	if isAPI {
		if mutating {
			fail(403, "API tokens are read-only")
		}
		if path != "/api/export" && path != "/api/records" && !(strings.HasPrefix(path, "/api/records/") && strings.Count(path, "/") == 3) {
			fail(403, "API tokens may only read documentation records and exports")
		}
	}
	if path == "/api/integrations/proxmox" || strings.HasPrefix(path, "/api/integrations/proxmox/") {
		return a.proxmoxRoute(req, u, b)
	}
	if path == "/api/collectors" || strings.HasPrefix(path, "/api/collectors/") {
		return a.collectorRoute(req, u, b)
	}
	if path == "/api/discovery" || strings.HasPrefix(path, "/api/discovery/") {
		return a.discoveryRoute(req, u, b)
	}
	if path == "/api/me" && method == "GET" {
		return out(200, M{"user": a.publicUser(u), "csrf": session["csrf"]})
	}
	if path == "/api/logout" && method == "POST" {
		a.run("DELETE FROM sessions WHERE token=?", S(session, "token"))
		return result{status: 200, body: M{"ok": true}, headers: http.Header{"Set-Cookie": []string{"trinetra_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"}}}
	}
	if path == "/api/password" && method == "POST" {
		if !checkPassword(S(b, "current"), S(u, "password")) {
			fail(401, "Current password is incorrect")
		}
		strongPassword(S(b, "password"))
		a.run("UPDATE users SET password=? WHERE id=?", hashPassword(S(b, "password")), S(u, "id"))
		a.run("DELETE FROM sessions WHERE user_id=?", S(u, "id"))
		a.audit(u, "password_change", "", "")
		return a.createSession(u)
	}
	if path == "/api/mfa/start" && method == "POST" {
		if S(u, "mfa") != "" {
			fail(409, "MFA is already enabled")
		}
		if !checkPassword(S(b, "password"), S(u, "password")) {
			fail(401, "Password is incorrect")
		}
		seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random(20))
		a.pending[S(u, "id")] = enrollment{Seed: seed, Expires: time.Now().Add(10 * time.Minute)}
		return out(200, M{"seed": seed, "uri": "otpauth://totp/Trinetra:" + url.PathEscape(S(u, "email")) + "?secret=" + seed + "&issuer=Trinetra"})
	}
	if path == "/api/mfa/confirm" && method == "POST" {
		p, ok := a.pending[S(u, "id")]
		if !ok || time.Now().After(p.Expires) || !validOTP(p.Seed, S(b, "code")) {
			fail(400, "Invalid or expired authenticator code")
		}
		a.run("UPDATE users SET mfa=? WHERE id=?", a.seal(p.Seed), S(u, "id"))
		delete(a.pending, S(u, "id"))
		a.audit(u, "mfa_enabled", "", "")
		return out(200, M{"ok": true})
	}
	if path == "/api/mfa/disable" && method == "POST" {
		if S(u, "mfa") == "" || !checkPassword(S(b, "password"), S(u, "password")) || !validOTP(fmt.Sprint(a.unseal(S(u, "mfa"))), S(b, "code")) {
			fail(401, "Password or authenticator code is incorrect")
		}
		a.run("UPDATE users SET mfa=NULL WHERE id=?", S(u, "id"))
		a.audit(u, "mfa_disabled", "", "")
		return out(200, M{"ok": true})
	}
	if path == "/api/context" && method == "GET" {
		orgs := []M{}
		for _, o := range a.q("SELECT * FROM records WHERE type='organizations' AND deleted IS NULL") {
			if withinOrgScope(u, o) {
				d := decode(S(o, "data"))
				orgs = append(orgs, M{"id": o["id"], "name": d["name"], "type": "organizations", "contextOnly": true})
			}
		}
		return out(200, M{"organizations": orgs})
	}
	if path == "/api/records" && method == "GET" {
		rows := a.visible(u, "deleted IS NULL")
		outRows := []M{}
		term := strings.ToLower(req.URL.Query().Get("q"))
		for _, r := range rows {
			if kind := req.URL.Query().Get("type"); kind != "" && S(r, "type") != kind {
				continue
			}
			if org := req.URL.Query().Get("org"); org != "" && S(r, "orgId") != org && S(r, "id") != org {
				continue
			}
			if term != "" && !strings.Contains(strings.ToLower(J(r)), term) {
				continue
			}
			outRows = append(outRows, r)
		}
		return out(200, outRows)
	}
	if path == "/api/records" && method == "POST" {
		requireWrite(u)
		return out(201, a.insert(u, S(b, "type"), b))
	}
	if path == "/api/trash" && method == "GET" {
		requirePage(u, "trash", "view")
		return out(200, a.visible(u, "deleted IS NOT NULL"))
	}
	if strings.HasPrefix(path, "/api/records/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/records/"), "/")
		if len(parts) > 2 {
			fail(404, "Endpoint not found")
		}
		recordID := parts[0]
		action := ""
		if len(parts) == 2 {
			action = parts[1]
		}
		r := a.raw(u, recordID, action == "restore")
		return a.recordRoute(req, u, r, action, b)
	}
	if strings.HasPrefix(path, "/api/attachments/") {
		file := a.get("SELECT * FROM attachments WHERE id=?", strings.TrimPrefix(path, "/api/attachments/"))
		if file == nil {
			fail(404, "Attachment not found")
		}
		a.raw(u, S(file, "record_id"), false)
		if method == "GET" {
			a.audit(u, "attachment_download", S(file, "record_id"), "")
			return result{status: 200, file: file["body"].([]byte), headers: http.Header{"Content-Type": []string{"application/octet-stream"}, "Content-Disposition": []string{"attachment; filename*=UTF-8''" + url.PathEscape(S(file, "name"))}}}
		}
		if method == "DELETE" {
			a.recordWritable(u, a.raw(u, S(file, "record_id"), false))
			a.run("DELETE FROM attachments WHERE id=?", S(file, "id"))
			a.audit(u, "attachment_delete", S(file, "record_id"), "")
			return out(200, M{"ok": true})
		}
	}
	if path == "/api/favorites" && method == "GET" {
		requirePage(u, "favorites", "view")
		outRows := []M{}
		for _, r := range a.q("SELECT records.* FROM records JOIN favorites ON records.id=favorites.record_id WHERE favorites.user_id=? AND records.deleted IS NULL", S(u, "id")) {
			if a.canRead(u, r) {
				outRows = append(outRows, a.safe(r))
			}
		}
		return out(200, outRows)
	}
	if path == "/api/audit" && method == "GET" {
		requirePage(u, "activity", "view")
		rows := a.q("SELECT * FROM audit ORDER BY id DESC LIMIT 1000")
		if S(u, "role") != "admin" {
			filtered := []M{}
			for _, event := range rows {
				target := a.get("SELECT * FROM records WHERE id=?", S(event, "target"))
				if S(event, "user_id") == S(u, "id") || a.canRead(u, target) {
					filtered = append(filtered, event)
				}
			}
			rows = filtered
		}
		return out(200, rows)
	}
	if path == "/api/users" {
		if method == "GET" {
			requirePage(u, "users", "view")
		} else {
			requireAdmin(u)
		}
		if method == "GET" {
			rows := []M{}
			for _, v := range a.q("SELECT * FROM users ORDER BY created") {
				rows = append(rows, a.publicUser(v))
			}
			return out(200, rows)
		}
		if method == "POST" {
			strongPassword(S(b, "password"))
			if !contains(roles, S(b, "role")) || strings.TrimSpace(S(b, "name")) == "" || !emailPattern.MatchString(S(b, "email")) {
				fail(400, "Invalid user details")
			}
			orgs := strArray(b["orgs"])
			a.validateOrgs(u, S(b, "role"), orgs)
			if a.get("SELECT id FROM users WHERE email=?", strings.ToLower(S(b, "email"))) != nil {
				fail(409, "Email is already in use")
			}
			uid := id()
			a.run("INSERT INTO users(id,email,name,password,role,orgs,created,permissions) VALUES(?,?,?,?,?,?,?,?)", uid, strings.ToLower(S(b, "email")), S(b, "name"), hashPassword(S(b, "password")), S(b, "role"), J(orgs), timestamp(), J(validatePermissions(b["permissions"])))
			a.audit(u, "user_created", uid, S(b, "role"))
			return out(201, a.publicUser(a.get("SELECT * FROM users WHERE id=?", uid)))
		}
	}
	if strings.HasPrefix(path, "/api/users/") && method == "PUT" {
		requireAdmin(u)
		uid := strings.TrimPrefix(path, "/api/users/")
		target := a.get("SELECT * FROM users WHERE id=?", uid)
		if target == nil {
			fail(404, "User not found")
		}
		if !contains(roles, S(b, "role")) {
			fail(400, "Invalid role")
		}
		orgs := strArray(b["orgs"])
		a.validateOrgs(u, S(b, "role"), orgs)
		if uid == S(u, "id") && (S(b, "role") != "admin" || b["active"] != true) {
			fail(400, "You cannot remove your own administrator access")
		}
		active := 0
		if b["active"] == true {
			active = 1
		}
		a.run("UPDATE users SET role=?,orgs=?,active=?,permissions=? WHERE id=?", S(b, "role"), J(orgs), active, J(validatePermissions(b["permissions"])), uid)
		if uid == S(u, "id") {
			a.run("DELETE FROM sessions WHERE user_id=? AND token<>?", uid, S(session, "token"))
		} else {
			a.run("DELETE FROM sessions WHERE user_id=?", uid)
		}
		a.run("DELETE FROM api_tokens WHERE user_id=?", uid)
		a.audit(u, "user_access_changed", uid, "")
		return out(200, M{"ok": true})
	}
	if path == "/api/tokens" {
		if method == "GET" {
			requirePage(u, "api-access", "view")
		} else {
			requirePage(u, "api-access", "edit")
		}
		if method == "GET" {
			return out(200, a.q("SELECT id,name,created,expires FROM api_tokens WHERE user_id=?", S(u, "id")))
		}
		if method == "POST" {
			if strings.TrimSpace(S(b, "name")) == "" {
				fail(400, "Token name is required")
			}
			rawToken, tid, expires := "tri_"+token(32), id(), time.Now().Add(30*24*time.Hour).UnixMilli()
			a.run("INSERT INTO api_tokens VALUES(?,?,?,?,?,?)", tid, digest(rawToken), S(u, "id"), S(b, "name"), timestamp(), expires)
			a.audit(u, "api_token_created", tid, "")
			return out(201, M{"id": tid, "token": rawToken, "expires": expires})
		}
	}
	if strings.HasPrefix(path, "/api/tokens/") && method == "DELETE" {
		requirePage(u, "api-access", "edit")
		tid := strings.TrimPrefix(path, "/api/tokens/")
		a.run("DELETE FROM api_tokens WHERE id=? AND user_id=?", tid, S(u, "id"))
		a.audit(u, "api_token_revoked", tid, "")
		return out(200, M{"ok": true})
	}
	if path == "/api/export" && method == "GET" {
		if S(u, "role") == "client" {
			fail(403, "Workspace export is unavailable for client accounts")
		}
		a.audit(u, "documentation_export", "", "")
		return out(200, M{"format": "trinetra-documentation-v1", "exportedAt": timestamp(), "records": a.visible(u, "deleted IS NULL AND type<>'passwords'")})
	}
	if path == "/api/import" && method == "POST" {
		requireWrite(u)
		rows, ok := b["records"].([]any)
		if !ok || len(rows) > 500 {
			fail(400, "Import up to 500 records at a time")
		}
		created := []M{}
		for _, v := range rows {
			row := obj(v)
			if contains([]string{"passwords", "organizations", "templates"}, S(row, "type")) {
				fail(400, "CSV import supports organization-owned records, excluding passwords")
			}
			created = append(created, a.insert(u, S(row, "type"), row))
		}
		a.audit(u, "records_imported", "", fmt.Sprint(len(created)))
		return out(201, M{"records": created})
	}
	fail(404, "Endpoint not found")
	return result{}
}
func (a *App) validateOrgs(u M, role string, orgs []string) {
	if (role == "client" || role == "plant_it") && len(orgs) == 0 {
		fail(400, "Assign at least one organization or plant to this role")
	}
	for _, oid := range orgs {
		if S(a.raw(u, oid, false), "type") != "organizations" {
			fail(400, "Select an organization")
		}
	}
}
