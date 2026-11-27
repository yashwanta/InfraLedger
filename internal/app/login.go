package app

import (
	"fmt"
	"net/http"
	"strings"
)

type loginKey struct{}

type loginCheck struct {
	email, userID, hash, address string
	passwordOK                   bool
}

// precheckLogin applies the attempt limits and runs the slow password hash
// outside the global lock, so sign-in attempts cannot stall other users.
func (a *App) precheckLogin(r *http.Request, b M) *loginCheck {
	check := &loginCheck{email: strings.ToLower(strings.TrimSpace(S(b, "email"))), address: a.clientAddress(r)}
	var u M
	limited := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.limited("ip:"+check.address, loginPerAddress) || a.limited("acct:"+check.email, loginPerAccount) {
			a.auditFailure(nil, clip(check.email, 200), "rate_limited", "", "sign-in from "+check.address)
			a.flushFailures()
			return true
		}
		u = a.get("SELECT * FROM users WHERE email=? AND active=1", check.email)
		return false
	}()
	if limited {
		fail(429, "Too many sign-in attempts. Try again in 15 minutes")
	}
	if u != nil {
		check.userID, check.hash = S(u, "id"), S(u, "password")
	}
	check.passwordOK = checkLoginPassword(S(b, "password"), u)
	return check
}

func (a *App) finishLogin(req *http.Request, b M) result {
	check, _ := req.Context().Value(loginKey{}).(*loginCheck)
	if check == nil {
		fail(400, "Invalid sign-in request")
	}
	u := a.get("SELECT * FROM users WHERE email=? AND active=1", check.email)
	reject := func(action, message string) {
		a.failed("ip:" + check.address)
		a.failed("acct:" + check.email)
		a.auditFailure(u, clip(check.email, 200), action, "", "from "+check.address)
		fail(401, message)
	}
	// The hash must be the one that was verified outside the lock.
	if u == nil || !check.passwordOK || S(u, "id") != check.userID || S(u, "password") != check.hash {
		reject("login_failed", "Invalid email or password")
	}
	if S(u, "mfa") != "" && !validOTP(fmt.Sprint(a.unseal(S(u, "mfa"))), S(b, "code")) {
		reject("mfa_failed", "Enter a valid six-digit authenticator code")
	}
	a.clearAttempts("ip:"+check.address, "acct:"+check.email)
	a.audit(u, "login", "", "from "+check.address)
	return a.createSession(u)
}

func (a *App) version() string {
	if a.config.Version == "" {
		return "dev"
	}
	return a.config.Version
}
