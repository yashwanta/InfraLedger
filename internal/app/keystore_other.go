//go:build !windows

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// On Linux/macOS the key stays in vault.key with mode 0600 inside a 0700 data
// folder; use VAULT_KEY from a secret manager for stronger separation.
const keyProtectionAvailable = false

func protectKey([]byte) ([]byte, error)   { return nil, errors.New("not supported") }
func unprotectKey([]byte) ([]byte, error) { return nil, errors.New("not supported") }
func restrictDataDir(dir string) error    { return os.Chmod(dir, 0700) }

func lockDataDir(dir string) (*os.File, error) {
	f, e := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return nil, e
	}
	if e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("data folder %s is in use by another InfraLedger process; stop it first", dir)
	}
	return f, nil
}
