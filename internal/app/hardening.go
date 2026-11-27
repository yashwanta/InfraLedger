package app

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Attempt limits. Failures are counted per source address and per account so
// one address cannot guess many accounts and many addresses cannot guess one.
const (
	loginWindow       = 15 * time.Minute
	loginPerAddress   = 20
	loginPerAccount   = 10
	reauthPerAccount  = 5
	maxTrackedBuckets = 50000
	smallBodyLimit    = 64 * 1024
	largeBodyLimit    = 9 * 1024 * 1024
)

// limited reports whether key has reached max failures in the current window.
func (a *App) limited(key string, max int) bool {
	b, ok := a.attempts[key]
	if !ok || time.Now().After(b.Reset) {
		return false
	}
	return b.Count >= max
}

// failed records one failure against key.
func (a *App) failed(key string) {
	now := time.Now()
	if len(a.attempts) >= maxTrackedBuckets {
		for k, v := range a.attempts {
			if now.After(v.Reset) {
				delete(a.attempts, k)
			}
		}
		if len(a.attempts) >= maxTrackedBuckets {
			a.attempts = map[string]attempt{}
		}
	}
	b := a.attempts[key]
	if now.After(b.Reset) {
		b = attempt{Reset: now.Add(loginWindow)}
	}
	b.Count++
	a.attempts[key] = b
}

// clientAddress returns the caller's IP. X-Forwarded-For is honoured only when
// the direct peer is the configured TRUSTED_PROXY.
func (a *App) clientAddress(r *http.Request) string {
	peer, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		peer = r.RemoteAddr
	}
	if a.config.TrustedProxy != "" && peer == a.config.TrustedProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return peer
}

func isLoopback(address string) bool {
	ip, e := netip.ParseAddr(address)
	return e == nil && ip.IsLoopback()
}

// hostAllowed blocks DNS-rebinding: browsers send the attacker's host name, so
// only IP literals, localhost, this computer's name, the APP_ORIGIN host and
// ALLOWED_HOSTS are accepted.
func (a *App) hostAllowed(host string) bool {
	name := host
	if h, _, e := net.SplitHostPort(host); e == nil {
		name = h
	}
	name = strings.ToLower(strings.Trim(name, "[]"))
	if name == "" {
		return false
	}
	if _, e := netip.ParseAddr(name); e == nil {
		return true
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}
	if hostname, e := os.Hostname(); e == nil && strings.EqualFold(name, hostname) {
		return true
	}
	if a.config.Origin != "" {
		if u, e := url.Parse(a.config.Origin); e == nil && strings.EqualFold(u.Hostname(), name) {
			return true
		}
	}
	for _, allowed := range a.config.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), name) {
			return true
		}
	}
	return false
}

// setupCodeValid: first-run setup from this computer needs no code; from any
// other address it needs the one-time code printed in the server console.
func (a *App) setupCodeValid(r *http.Request, code string) bool {
	if isLoopback(a.clientAddress(r)) && a.config.TrustedProxy == "" {
		return true
	}
	if a.setupCode == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(code))), []byte(a.setupCode)) == 1
}

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// checkLoginPassword spends the same PBKDF2 time whether or not the account
// exists, so response time does not reveal valid email addresses.
func checkLoginPassword(password string, u M) bool {
	if u == nil {
		dummyHashOnce.Do(func() { dummyHash = hashPassword(token(24)) })
		checkPassword(password, dummyHash)
		return false
	}
	return checkPassword(password, S(u, "password"))
}

type failureEvent struct {
	userID  any
	actor   string
	action  string
	target  string
	details string
}

// auditFailure queues an event that is written after the failed request's
// transaction is rolled back, so failed attempts are always recorded.
func (a *App) auditFailure(u M, actor, action, target, details string) {
	var userID any
	if u != nil {
		userID = u["id"]
		actor = S(u, "name")
	}
	if actor == "" {
		actor = "Unknown"
	}
	a.failures = append(a.failures, failureEvent{userID, clip(actor, 200), action, target, clip(details, 500)})
}

func (a *App) flushFailures() {
	for _, f := range a.failures {
		a.db.Exec("INSERT INTO audit(user_id,actor,action,target,time,details) VALUES(?,?,?,?,?,?)", f.userID, f.actor, f.action, f.target, timestamp(), f.details)
	}
	a.failures = nil
}

// reauthenticate checks the password (and code when MFA is on) for sensitive
// actions by a signed-in user, with a per-account failure limit.
func (a *App) reauthenticate(r *http.Request, u M, password, code, action, target string) bool {
	key := "reauth:" + S(u, "id")
	if a.limited(key, reauthPerAccount) {
		a.auditFailure(u, "", "rate_limited", target, action+" from "+a.clientAddress(r))
		fail(429, "Too many failed attempts. Try again in 15 minutes")
	}
	ok := checkPassword(password, S(u, "password"))
	if ok && S(u, "mfa") != "" {
		ok = validOTP(fmt.Sprint(a.unseal(S(u, "mfa"))), code)
	}
	if !ok {
		a.failed(key)
		a.auditFailure(u, "", action+"_failed", target, "from "+a.clientAddress(r))
		return false
	}
	delete(a.attempts, key)
	return true
}

func (a *App) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), interest-cohort=()")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if r.TLS != nil || a.config.SecureCookie {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

// serveStatic serves only regular files from the build folder: no directory
// listings and no dot-files.
func (a *App) serveStatic(w http.ResponseWriter, r *http.Request) {
	clean := path.Clean("/" + r.URL.Path)
	if clean == "/" {
		clean = "/index.html"
	}
	for _, part := range strings.Split(clean, "/") {
		if strings.HasPrefix(part, ".") {
			http.NotFound(w, r)
			return
		}
	}
	full := filepath.Join(a.config.StaticDir, filepath.FromSlash(clean))
	info, e := os.Stat(full)
	if e != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, full)
}
