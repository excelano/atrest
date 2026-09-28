// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build windows

package atrest

import (
	"errors"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	stored, err := Seal("atrest.test", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plain, sealed, err := Open("atrest.test", stored)
	if err != nil || !sealed || string(plain) != msalCache {
		t.Fatalf("Open = %q, sealed=%v, err=%v; want the original, sealed", plain, sealed, err)
	}
	if _, _, err := Open("other.test", stored); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("Open under another name: err = %v; want ErrCannotOpen", err)
	}
}

func TestDPAPIEmpty(t *testing.T) {
	stored, err := Seal("atrest.test", nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plain, sealed, err := Open("atrest.test", stored)
	if err != nil || !sealed || len(plain) != 0 {
		t.Errorf("Open = %q, sealed=%v, err=%v; want empty, sealed", plain, sealed, err)
	}
}
