package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Attachments are stored as attachmentMagic || nonce || AES-GCM ciphertext.
var attachmentMagic = []byte("ILENC1")

const attachmentOverhead = 6 + 12 + 16

func gcmFor(key []byte) cipher.AEAD {
	block, e := aes.NewCipher(key)
	must(e)
	gcm, e := cipher.NewGCM(block)
	must(e)
	return gcm
}

func sealBytesWith(key, plain []byte) []byte {
	gcm := gcmFor(key)
	nonce := random(gcm.NonceSize())
	out := append(append([]byte{}, attachmentMagic...), nonce...)
	return gcm.Seal(out, nonce, plain, attachmentMagic)
}

func unsealBytesWith(key, data []byte) []byte {
	if !bytes.HasPrefix(data, attachmentMagic) {
		return data // stored before attachment encryption was added
	}
	gcm := gcmFor(key)
	rest := data[len(attachmentMagic):]
	if len(rest) < gcm.NonceSize()+gcm.Overhead() {
		panic("Invalid encrypted attachment")
	}
	plain, e := gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], attachmentMagic)
	must(e)
	return plain
}

func (a *App) sealBytes(plain []byte) []byte  { return sealBytesWith(a.key, plain) }
func (a *App) unsealBytes(data []byte) []byte { return unsealBytesWith(a.key, data) }

const attachmentSizeSQL = "CASE WHEN substr(body,1,6)=CAST('ILENC1' AS BLOB) THEN length(body)-34 ELSE length(body) END"

// migrateVault runs at start-up: check the key against the canary, encrypt
// attachments stored in clear, and drop old sealed secrets from version
// history (password history is never shown, so the copies only add risk).
func (a *App) migrateVault() error {
	var canary string
	switch e := a.db.QueryRow("SELECT value FROM meta WHERE key='vault_canary'").Scan(&canary); {
	case errors.Is(e, sql.ErrNoRows):
		if _, e := a.db.Exec("INSERT INTO meta(key,value) VALUES('vault_canary',?)", a.seal("InfraLedger")); e != nil {
			return e
		}
	case e != nil:
		return e
	default:
		if !canOpen(a.key, canary) {
			// A key rotation may have committed without swapping the key file.
			pendingPath := keyFilePath(a.config.DataDir) + ".new"
			blob, readErr := os.ReadFile(pendingPath)
			pending, decodeErr := decodeKeyFile(blob)
			if readErr != nil || decodeErr != nil || !canOpen(pending, canary) || os.Getenv("VAULT_KEY") != "" {
				return fmt.Errorf("the vault key does not match this database; restore the matching key (VAULT_KEY recovery key or vault.key.protected)")
			}
			if e := os.Rename(pendingPath, keyFilePath(a.config.DataDir)); e != nil {
				return e
			}
			a.key = pending
			log.Printf("Finished an interrupted vault key rotation")
		}
	}
	rows, e := a.db.Query("SELECT id FROM attachments WHERE substr(body,1,6)<>CAST('ILENC1' AS BLOB)")
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		var body []byte
		if e := a.db.QueryRow("SELECT body FROM attachments WHERE id=?", id).Scan(&body); e != nil {
			return e
		}
		if _, e := a.db.Exec("UPDATE attachments SET body=? WHERE id=?", a.sealBytes(body), id); e != nil {
			return e
		}
	}
	if len(ids) > 0 {
		log.Printf("Encrypted %d existing attachment(s)", len(ids))
	}
	_, e = a.db.Exec(`UPDATE versions SET data=json_remove(data,'$.sealed') WHERE json_extract(data,'$.sealed') IS NOT NULL AND record_id IN (SELECT id FROM records WHERE type='passwords')`)
	return e
}

func canOpen(key []byte, sealed string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	(&App{key: key}).unseal(sealed)
	return true
}

// purgeRecord permanently removes a record in the recycle bin together with
// its history, attachments, comments and favorites. secure_delete overwrites
// the freed database pages.
func (a *App) purgeRecord(u M, r M) {
	recordID := S(r, "id")
	for _, q := range []string{"DELETE FROM attachments WHERE record_id=?", "DELETE FROM comments WHERE record_id=?", "DELETE FROM favorites WHERE record_id=?", "DELETE FROM versions WHERE record_id=?", "DELETE FROM records WHERE id=?"} {
		a.run(q, recordID)
	}
	a.audit(u, "purge", recordID, S(r, "type"))
}

func (a *App) trashRoute(req *http.Request, u M, b M) result {
	requireAdmin(u)
	path, method := req.URL.Path, req.Method
	if path == "/api/trash/purge" && method == "POST" {
		days := N(b, "olderThanDays")
		if days < 0 || days > 3650 || float64(int(days)) != days {
			fail(400, "Enter a number of days between 0 and 3650")
		}
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		rows := a.q("SELECT * FROM records WHERE deleted IS NOT NULL AND deleted<=?", cutoff)
		for _, r := range rows {
			a.purgeRecord(u, r)
		}
		return out(200, M{"purged": len(rows)})
	}
	if strings.HasPrefix(path, "/api/trash/") && method == "DELETE" {
		r := a.get("SELECT * FROM records WHERE id=? AND deleted IS NOT NULL", strings.TrimPrefix(path, "/api/trash/"))
		if r == nil {
			fail(404, "Record is not in the recycle bin")
		}
		a.purgeRecord(u, r)
		return out(200, M{"ok": true})
	}
	fail(404, "Endpoint not found")
	return result{}
}

// RotateVaultKey re-encrypts every sealed value with a new key. The server
// must be stopped; the data-folder lock enforces that.
func RotateVaultKey(dataDir string) error {
	if os.Getenv("VAULT_KEY") != "" {
		return fmt.Errorf("VAULT_KEY is set: rotate the key in your secret manager instead, or unset it to use the protected key file")
	}
	lock, e := lockDataDir(dataDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	oldKey, e := loadVaultKey(dataDir)
	if e != nil {
		return e
	}
	newKey := random(32)
	db, e := sql.Open("sqlite", filepath.Join(dataDir, "trinetra.sqlite"))
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var canary string
	if e := db.QueryRow("SELECT value FROM meta WHERE key='vault_canary'").Scan(&canary); e == nil && !canOpen(oldKey, canary) {
		return fmt.Errorf("current vault key does not match the database; rotation stopped")
	}
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	oldApp, newApp := &App{key: oldKey}, &App{key: newKey}
	reseal := func(v string) (string, error) {
		var out string
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("decrypt: %v", p)
				}
			}()
			out = newApp.seal(oldApp.unseal(v))
		}()
		return out, err
	}
	count := 0
	type row struct{ id, value string }
	collect := func(query string) ([]row, error) {
		rows, e := tx.Query(query)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		list := []row{}
		for rows.Next() {
			var r row
			if e := rows.Scan(&r.id, &r.value); e != nil {
				return nil, e
			}
			list = append(list, r)
		}
		return list, rows.Err()
	}
	simple := []struct{ sel, upd string }{
		{"SELECT id, mfa FROM users WHERE mfa IS NOT NULL AND mfa<>''", "UPDATE users SET mfa=? WHERE id=?"},
		{"SELECT id, sealed FROM proxmox_connections", "UPDATE proxmox_connections SET sealed=? WHERE id=?"},
		{"SELECT id, sealed FROM remote_credentials", "UPDATE remote_credentials SET sealed=? WHERE id=?"},
		{"SELECT key, value FROM meta WHERE key='vault_canary'", "UPDATE meta SET value=? WHERE key=?"},
	}
	for _, s := range simple {
		rows, e := collect(s.sel)
		if e != nil {
			return e
		}
		for _, r := range rows {
			v, e := reseal(r.value)
			if e != nil {
				return fmt.Errorf("%s: %w", r.id, e)
			}
			if _, e := tx.Exec(s.upd, v, r.id); e != nil {
				return e
			}
			count++
		}
	}
	records, e := collect("SELECT id, data FROM records WHERE type='passwords'")
	if e != nil {
		return e
	}
	for _, r := range records {
		d := decode(r.value)
		if S(d, "sealed") == "" {
			continue
		}
		v, e := reseal(S(d, "sealed"))
		if e != nil {
			return fmt.Errorf("credential %s: %w", r.id, e)
		}
		d["sealed"] = v
		if _, e := tx.Exec("UPDATE records SET data=? WHERE id=?", J(d), r.id); e != nil {
			return e
		}
		count++
	}
	if _, e := tx.Exec(`UPDATE versions SET data=json_remove(data,'$.sealed') WHERE json_extract(data,'$.sealed') IS NOT NULL`); e != nil {
		return e
	}
	attachments, e := tx.Query("SELECT id, body FROM attachments")
	if e != nil {
		return e
	}
	type blobRow struct {
		id   string
		body []byte
	}
	blobs := []blobRow{}
	for attachments.Next() {
		var b blobRow
		if e := attachments.Scan(&b.id, &b.body); e != nil {
			attachments.Close()
			return e
		}
		blobs = append(blobs, b)
	}
	attachments.Close()
	for _, b := range blobs {
		var plain []byte
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("attachment %s: %v", b.id, p)
				}
			}()
			plain = unsealBytesWith(oldKey, b.body)
		}()
		if err != nil {
			return err
		}
		if _, e := tx.Exec("UPDATE attachments SET body=? WHERE id=?", sealBytesWith(newKey, plain), b.id); e != nil {
			return e
		}
		count++
	}
	if _, e := tx.Exec("INSERT INTO audit(user_id,actor,action,target,time,details) VALUES(NULL,'System','vault_key_rotated','',?,?)", timestamp(), fmt.Sprintf("%d values re-encrypted", count)); e != nil {
		return e
	}
	// Write the new key next to the old one, commit, then swap. If the swap is
	// interrupted, start-up finds the pending key with the canary.
	pending, e := encodeKeyFile(newKey)
	if e != nil {
		return e
	}
	pendingPath := keyFilePath(dataDir) + ".new"
	os.Remove(pendingPath)
	if e := writeExclusive(pendingPath, pending); e != nil {
		return e
	}
	if e := tx.Commit(); e != nil {
		os.Remove(pendingPath)
		return e
	}
	if e := os.Rename(pendingPath, keyFilePath(dataDir)); e != nil {
		return fmt.Errorf("database re-encrypted but the new key could not replace the old file (%v); start InfraLedger normally and it will finish the switch", e)
	}
	log.Printf("Vault key rotated: %d values re-encrypted. Export a new recovery key with -export-vault-key; the old one no longer works.", count)
	return nil
}
