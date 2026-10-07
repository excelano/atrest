// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux || darwin

package atrest

import (
	"encoding/json"
	"errors"
	"testing"
)

// fakeStore is a key store whose reachability the test controls.
type fakeStore struct {
	name        string
	keys        map[string][]byte
	unavailable bool
}

func (s *fakeStore) id() string { return s.name }

func (s *fakeStore) key(name string, create bool) ([]byte, error) {
	if s.unavailable {
		return nil, errUnavailable
	}
	if key, ok := s.keys[name]; ok {
		return key, nil
	}
	if !create {
		return nil, errNoKey
	}
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	s.keys[name] = key
	return key, nil
}

func newFakeStore(name string) *fakeStore {
	return &fakeStore{name: name, keys: map[string][]byte{}}
}

func storeNamed(t *testing.T, stored []byte) string {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(stored, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env.Store
}

func TestSealUsesFirstReachableStore(t *testing.T) {
	first, second := newFakeStore("first"), newFakeStore("second")
	first.unavailable = true
	withPlatform(t, keyedAESGCM{stores: []keyStore{first, second}})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := storeNamed(t, stored); got != "second" {
		t.Errorf("envelope names store %q; want the reachable one, second", got)
	}
	plain, _, err := Open("test.cache", stored)
	if err != nil || string(plain) != msalCache {
		t.Errorf("Open = %q, %v; want the original", plain, err)
	}
}

func TestOpenLockedStoreReportsErrLocked(t *testing.T) {
	first, second := newFakeStore("first"), newFakeStore("second")
	withPlatform(t, keyedAESGCM{stores: []keyStore{first, second}})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	first.unavailable = true
	_, _, err = Open("test.cache", stored)
	if !errors.Is(err, ErrLocked) || !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v; want both ErrLocked and ErrCannotOpen", err)
	}
	if len(second.keys) != 0 {
		t.Error("Open created a key in the other store instead of reporting the named one locked")
	}
}

func TestOpenMissingKeyIsNotLocked(t *testing.T) {
	first := newFakeStore("first")
	withPlatform(t, keyedAESGCM{stores: []keyStore{first}})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	delete(first.keys, "test.cache")
	_, _, err = Open("test.cache", stored)
	if !errors.Is(err, ErrCannotOpen) || errors.Is(err, ErrLocked) {
		t.Errorf("err = %v; want ErrCannotOpen without ErrLocked", err)
	}
	if len(first.keys) != 0 {
		t.Error("Open created a key that could never open the data")
	}
}

func TestOpenWrongKeyInNamedStore(t *testing.T) {
	first := newFakeStore("first")
	withPlatform(t, keyedAESGCM{stores: []keyStore{first}})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	other, _ := randomKey()
	first.keys["test.cache"] = other
	_, _, err = Open("test.cache", stored)
	if !errors.Is(err, ErrCannotOpen) || errors.Is(err, ErrLocked) {
		t.Errorf("err = %v; want ErrCannotOpen without ErrLocked", err)
	}
}

// An envelope written before the store was recorded names none, and the key
// may be in any store, so each reachable one is tried.
func TestOpenUnnamedStoreTriesEveryStore(t *testing.T) {
	first, second := newFakeStore("first"), newFakeStore("second")
	withPlatform(t, keyedAESGCM{stores: []keyStore{second}})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(stored, &env); err != nil {
		t.Fatal(err)
	}
	env.Store = ""
	unnamed, _ := json.Marshal(env)

	withPlatform(t, keyedAESGCM{stores: []keyStore{first, second}})
	plain, _, err := Open("test.cache", unnamed)
	if err != nil || string(plain) != msalCache {
		t.Errorf("Open = %q, %v; want the original from the second store", plain, err)
	}
	if len(first.keys) != 0 {
		t.Error("Open created a key in a store that held none")
	}

	second.unavailable = true
	_, _, err = Open("test.cache", unnamed)
	if !errors.Is(err, ErrCannotOpen) || errors.Is(err, ErrLocked) {
		t.Errorf("err = %v; want ErrCannotOpen, not ErrLocked, since no store is named", err)
	}
}
