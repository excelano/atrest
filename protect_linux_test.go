// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux

package atrest

import "testing"

// These run against whatever this machine actually offers — a session bus
// with a Secret Service, a usable kernel keyring, or neither — rather than a
// stand-in, the same way protect_windows_test.go exercises real DPAPI. A
// machine with neither is reported rather than failed on, since that is a
// property of the runner, not a defect atrest could have.

func TestSecretServiceKeyRoundTrip(t *testing.T) {
	key1, err := secretServiceKey("atrest-test/secret-service")
	if err != nil {
		t.Skipf("no Secret Service reachable here: %v", err)
	}
	key2, err := secretServiceKey("atrest-test/secret-service")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("secretServiceKey returned a different key on the second call")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestPersistentFollowsSecretService(t *testing.T) {
	_, err := secretServiceKey("atrest-test/persistent")
	if got, want := Persistent(), err == nil; got != want {
		t.Errorf("Persistent() = %v, but secretServiceKey error = %v", got, err)
	}
}

func TestKeyringKeyRoundTrip(t *testing.T) {
	key1, err := keyringKey("atrest-test/keyring")
	if err != nil {
		t.Skipf("no kernel keyring reachable here: %v", err)
	}
	key2, err := keyringKey("atrest-test/keyring")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("keyringKey returned a different key on the second call")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

// TestSealOpenRoundTripReal exercises the real platform var end to end,
// through whichever backend linuxKey finds. A machine offering neither still
// passes: Seal degrades to plaintext, which is the contract Available()
// documents.
func TestSealOpenRoundTripReal(t *testing.T) {
	stored, err := Seal("atrest-test/seal-open", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plain, sealed, err := Open("atrest-test/seal-open", stored)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plain) != msalCache {
		t.Errorf("plain = %q; want the original", plain)
	}
	if !sealed {
		t.Log("no key store reachable here; Seal passed the data through unchanged")
	}
}
