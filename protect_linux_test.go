// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux

package atrest

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// These run against whatever this machine actually offers — a session bus
// with a Secret Service, a usable kernel keyring, or neither — rather than a
// stand-in, the same way protect_windows_test.go exercises real DPAPI. A
// machine with neither is reported rather than failed on, since that is a
// property of the runner, not a defect atrest could have.

func TestSecretServiceKeyRoundTrip(t *testing.T) {
	key1, err := secretServiceStore{}.key("atrest-test/secret-service", true)
	if err != nil {
		t.Skipf("no Secret Service reachable here: %v", err)
	}
	key2, err := secretServiceStore{}.key("atrest-test/secret-service", false)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("the Secret Service returned a different key on the second call")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestPersistentFollowsSecretService(t *testing.T) {
	_, err := secretServiceStore{}.key("atrest-test/persistent", true)
	if got, want := Persistent(), err == nil; got != want {
		t.Errorf("Persistent() = %v, but the Secret Service key error = %v", got, err)
	}
}

// Unlock on a collection that is already unlocked needs no prompt and no
// display. The locked case needs a user at the dialog, so it is exercised by
// hand, not here.
func TestUnlockWhenAlreadyUnlocked(t *testing.T) {
	if !secretServiceUnlocked() {
		t.Skip("the Secret Service is locked or unreachable here")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Unlock(ctx); err != nil {
		t.Errorf("Unlock with the collection already unlocked: %v", err)
	}
}

func TestSecretServiceNoKeyWithoutCreate(t *testing.T) {
	if !secretServiceUnlocked() {
		t.Skip("the Secret Service is locked or unreachable here")
	}
	_, err := secretServiceStore{}.key("atrest-test/never-created", false)
	if err != errNoKey {
		t.Errorf("err = %v; want errNoKey for a name never stored", err)
	}
}

func TestKeyringKeyRoundTrip(t *testing.T) {
	key1, err := keyringStore{}.key("atrest-test/keyring", true)
	if err != nil {
		t.Skipf("no kernel keyring reachable here: %v", err)
	}
	key2, err := keyringStore{}.key("atrest-test/keyring", false)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("the kernel keyring returned a different key on the second call")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

// TestSealOpenRoundTripReal exercises the real platform var end to end,
// through whichever store a Seal finds reachable. A machine offering neither still
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
		return
	}
	var env envelope
	if err := json.Unmarshal(stored, &env); err != nil || platform.(keyedAESGCM).store(env.Store) == nil {
		t.Errorf("envelope %s names no store this platform has", stored)
	}
}
