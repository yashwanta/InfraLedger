//go:build windows

package app

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const keyProtectionAvailable = true

var keyEntropy = []byte("InfraLedger vault key v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

// protectKey encrypts with DPAPI in the current user's scope.
func protectKey(key []byte) ([]byte, error) {
	var out windows.DataBlob
	if e := windows.CryptProtectData(blob(key), nil, blob(keyEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, e
	}
	return takeBlob(&out), nil
}

func unprotectKey(data []byte) ([]byte, error) {
	var out windows.DataBlob
	if e := windows.CryptUnprotectData(blob(data), nil, blob(keyEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, e
	}
	return takeBlob(&out), nil
}

// restrictDataDir limits the data folder to the account running the server,
// SYSTEM and Administrators, and stops inheriting wider permissions.
func restrictDataDir(dir string) error {
	token := windows.GetCurrentProcessToken()
	user, e := token.GetTokenUser()
	if e != nil {
		return e
	}
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", user.User.Sid.String())
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
