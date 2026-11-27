//go:build !windows

package app

import (
	"errors"
	"os"
)

// On Linux/macOS the key stays in vault.key with mode 0600 inside a 0700 data
// folder; use VAULT_KEY from a secret manager for stronger separation.
const keyProtectionAvailable = false

func protectKey([]byte) ([]byte, error)   { return nil, errors.New("not supported") }
func unprotectKey([]byte) ([]byte, error) { return nil, errors.New("not supported") }
func restrictDataDir(dir string) error    { return os.Chmod(dir, 0700) }
