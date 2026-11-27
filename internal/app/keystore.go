package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// loadVaultKey returns the 32-byte vault key.
//
// Order: VAULT_KEY environment variable; the OS-protected key file
// (vault.key.protected, Windows DPAPI bound to the account running the
// server); a legacy plain vault.key, which is converted to the protected form
// and then removed; otherwise a new key is created in protected form.
func loadVaultKey(dataDir string) ([]byte, error) {
	if value := os.Getenv("VAULT_KEY"); value != "" {
		key, e := base64.StdEncoding.DecodeString(value)
		if e != nil {
			return nil, fmt.Errorf("VAULT_KEY is not valid base64: %w", e)
		}
		return checkKey(key)
	}
	plainPath := filepath.Join(dataDir, "vault.key")
	protectedPath := filepath.Join(dataDir, "vault.key.protected")
	if blob, e := os.ReadFile(protectedPath); e == nil {
		key, e := unprotectKey(blob)
		if e != nil {
			return nil, fmt.Errorf("cannot unlock %s: %w. It can only be opened by the Windows account that created it; run InfraLedger as that account, or start it with VAULT_KEY set to the exported recovery key", protectedPath, e)
		}
		if _, e := os.Stat(plainPath); e == nil {
			log.Printf("Warning: an unprotected %s is also present; delete it after confirming you have a recovery copy", plainPath)
		}
		return checkKey(key)
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	key, e := os.ReadFile(plainPath)
	created := false
	if errors.Is(e, os.ErrNotExist) {
		key, e, created = random(32), nil, true
	}
	if e != nil {
		return nil, e
	}
	if _, e := checkKey(key); e != nil {
		return nil, e
	}
	if !keyProtectionAvailable {
		if created {
			if e := writeExclusive(plainPath, key); e != nil {
				return nil, e
			}
		}
		return key, nil
	}
	blob, e := protectKey(key)
	if e != nil {
		return nil, fmt.Errorf("protect vault key: %w", e)
	}
	if again, e := unprotectKey(blob); e != nil || string(again) != string(key) {
		return nil, fmt.Errorf("protected vault key failed verification")
	}
	if e := writeExclusive(protectedPath, blob); e != nil {
		return nil, e
	}
	if !created {
		if e := os.Remove(plainPath); e != nil {
			log.Printf("Warning: vault key is now protected but %s could not be removed: %v", plainPath, e)
		} else {
			log.Printf("Vault key converted to OS-protected storage (%s). Export a recovery copy with -export-vault-key.", protectedPath)
		}
	}
	return key, nil
}

func checkKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must contain 32 bytes")
	}
	return key, nil
}

func writeExclusive(path string, data []byte) error {
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = file.Write(data)
	if closeErr := file.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		os.Remove(path)
	}
	return e
}

// ExportVaultKey prints the recovery key (base64) for safekeeping offline.
func ExportVaultKey(dataDir string) (string, error) {
	_, protectedErr := os.Stat(filepath.Join(dataDir, "vault.key.protected"))
	_, plainErr := os.Stat(filepath.Join(dataDir, "vault.key"))
	if os.Getenv("VAULT_KEY") == "" && protectedErr != nil && plainErr != nil {
		return "", fmt.Errorf("no vault key found in %s", dataDir)
	}
	key, e := loadVaultKey(dataDir)
	if e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
