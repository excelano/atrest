// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build windows

package atrest

import (
	"bytes"
	"context"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platform on Windows is DPAPI, which encrypts under a key derived from the
// user's logon credentials. The data opens only for the same user on the same
// machine, or wherever that user's roaming profile carries the key.
var platform protector = dpapi{}

// persistent is true because DPAPI's key follows the user's logon credentials.
func persistent() bool { return true }

// unlock has nothing to do: DPAPI's key is the user's logon, which is never
// locked while the user is logged on.
func unlock(context.Context) error {
	return errors.New("atrest: DPAPI has no store to unlock")
}

type dpapi struct{}

func (dpapi) alg() string { return "dpapi" }

// protect passes name as DPAPI's optional entropy, which must be presented
// again to unprotect. UI_FORBIDDEN makes DPAPI fail rather than prompt. DPAPI
// is the only store, so the envelope names none.
func (dpapi) protect(name string, plain []byte) ([]byte, string, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob(plain), nil, blob([]byte(name)), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, "", err
	}
	return take(&out), "", nil
}

func (dpapi) unprotect(name, _ string, sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptUnprotectData(blob(sealed), nil, blob([]byte(name)), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	return take(&out), nil
}

// blob points DPAPI at b. DPAPI rejects a null data pointer even at size
// zero, so an empty slice points at a spare byte instead.
func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{Data: new(byte)}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// take copies a DPAPI output buffer into Go memory and frees the original,
// which DPAPI allocated with LocalAlloc.
func take(b *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return bytes.Clone(unsafe.Slice(b.Data, b.Size))
}
