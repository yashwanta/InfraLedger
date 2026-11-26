package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTOTPRFCVector(t *testing.T) {
	if actual := totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)); actual != "287082" {
		t.Fatal(actual)
	}
}

func TestSetupSeedsConnectedInfrastructure(t *testing.T) {
	a, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewBufferString(`{"name":"Test Admin","email":"admin@example.test","password":"a-long-test-passphrase","samples":true}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(a.q("SELECT id FROM records WHERE type='applications'")) != 2 {
		t.Fatal("sample applications missing")
	}
	if len(a.q("SELECT id FROM records WHERE type='dependencies'")) != 1 {
		t.Fatal("sample dependency missing")
	}
}
func TestPasswordHash(t *testing.T) {
	hash := hashPassword("a-long-password-for-test")
	if !checkPassword("a-long-password-for-test", hash) || checkPassword("wrong", hash) {
		t.Fatal("password verification failed")
	}
}
func TestEncryption(t *testing.T) {
	a := &App{key: random(32)}
	sealed := a.seal(M{"password": "secret"})
	if S(obj(a.unseal(sealed)), "password") != "secret" {
		t.Fatal("round-trip failed")
	}
	a.key = random(32)
	defer func() {
		if recover() == nil {
			t.Error("wrong key accepted")
		}
	}()
	a.unseal(sealed)
}
