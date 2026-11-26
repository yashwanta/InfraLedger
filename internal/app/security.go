package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func token(n int) string     { return base64.RawURLEncoding.EncodeToString(random(n)) }
func id() string             { return hex.EncodeToString(random(16)) }
func digest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func hashPassword(password string) string {
	salt := random(16)
	key, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		panic(err)
	}
	return "pbkdf2$600000$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key)
}
func checkPassword(password, stored string) bool {
	if len(password) > 4096 {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) == 4 && parts[0] == "pbkdf2" && parts[1] == "600000" {
		salt, e := hex.DecodeString(parts[2])
		if e != nil {
			return false
		}
		want, e := hex.DecodeString(parts[3])
		if e != nil {
			return false
		}
		actual, e := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
		return e == nil && subtle.ConstantTimeCompare(want, actual) == 1
	}
	legacy := strings.Split(stored, ":")
	if len(legacy) == 2 {
		want, e := hex.DecodeString(legacy[1])
		if e != nil {
			return false
		}
		actual, e := scrypt.Key([]byte(password), []byte(legacy[0]), 16384, 8, 1, 64)
		return e == nil && subtle.ConstantTimeCompare(want, actual) == 1
	}
	return false
}
func strongPassword(v string) {
	if len(v) < 12 || len(v) > 256 {
		fail(400, "Use a password between 12 and 256 characters")
	}
}
func (a *App) seal(v any) string {
	block, e := aes.NewCipher(a.key)
	must(e)
	gcm, e := cipher.NewGCM(block)
	must(e)
	nonce := random(gcm.NonceSize())
	data, e := json.Marshal(v)
	must(e)
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, data, nil))
}
func (a *App) unseal(s string) any {
	data, e := base64.StdEncoding.DecodeString(s)
	must(e)
	block, e := aes.NewCipher(a.key)
	must(e)
	gcm, e := cipher.NewGCM(block)
	must(e)
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		panic("Invalid encrypted value")
	}
	plain, e := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	must(e)
	var value any
	must(json.Unmarshal(plain, &value))
	return value
}
func totp(seed string, at time.Time) string {
	seed = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(seed), " ", ""))
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(seed, "="))
	if e != nil || len(key) < 10 {
		return ""
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter)
	b := mac.Sum(nil)
	offset := b[len(b)-1] & 15
	code := (binary.BigEndian.Uint32(b[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}
func validOTP(seed, code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, n := range []int{-1, 0, 1} {
		if subtle.ConstantTimeCompare([]byte(totp(seed, time.Now().Add(time.Duration(n)*30*time.Second))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
