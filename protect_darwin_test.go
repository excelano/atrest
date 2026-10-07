// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build darwin

package atrest

import "testing"

// These run against whatever this machine actually offers, the same
// discipline as protect_windows_test.go and protect_linux_test.go. A session
// with no reachable login Keychain — over SSH without the console session's
// audit context, notably — is reported rather than failed on, since that is a
// property of the runner, not a defect atrest could have.

func TestKeychainKeyRoundTrip(t *testing.T) {
	key1, err := keychainStore{}.key("atrest-test/keychain", true)
	if err != nil {
		t.Skipf("no Keychain reachable here: %v", err)
	}
	key2, err := keychainStore{}.key("atrest-test/keychain", true)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("the Keychain returned a different key on the second call")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

// TestSealOpenRoundTripReal exercises the real platform var end to end. A
// machine offering no reachable Keychain still passes: Seal degrades to
// plaintext, which is the contract Available() documents.
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
		t.Log("no Keychain reachable here; Seal passed the data through unchanged")
	}
}
