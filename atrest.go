// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

// Package atrest protects small local files, such as token caches, with the
// operating system's own data-protection facility, so their contents are
// useless once copied off the account that wrote them: into a backup, a synced
// home directory, or a disk image.
//
// Seal wraps data in a JSON envelope naming the algorithm that protected it.
// Open reverses Seal and also accepts plaintext, reporting which it was given,
// so a caller that finds plaintext written by an older build can read it and
// seal it again instead of discarding it. Where no facility exists, and where
// one exists but nothing on the machine can reach it right now, such as a
// container with no D-Bus session and no usable kernel keyring, Seal returns
// data unchanged; Available reports whether the platform has a facility at
// all, not whether this call will succeed.
//
// The envelope is JSON so that an older build of a program which hands the
// file to a JSON parser sees an object it does not recognise, rather than
// bytes it cannot parse. MSAL's token cache, for one, reads an unrecognised
// object as an empty cache and prompts for sign-in, where unparseable bytes
// fail every call.
//
// Protection is against the file leaving its context. Any process running as
// the same user can open what Seal produced, on every platform.
package atrest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// ErrCannotOpen reports sealed data that this build cannot open: sealed on
// another machine or by another user, sealed by an algorithm this platform
// lacks, or written by a newer envelope version. The data is not corrupt, but
// nothing here will read it; a cache in this state should be treated as
// empty.
var ErrCannotOpen = errors.New("atrest: sealed data cannot be opened here")

// ErrLocked is an ErrCannotOpen whose cause is the key store that holds the
// data's key being locked, or unreachable from this process, rather than the
// key being absent. The data opens once the store does, which Unlock can ask
// for, so a caller that would otherwise discard the data and start over can
// offer that first. errors.Is reports both ErrLocked and ErrCannotOpen for it.
var ErrLocked = errors.New("atrest: the key store is locked")

// lockedError names the store so the caller can say which one to unlock.
type lockedError struct{ store string }

func (e lockedError) Error() string {
	return "its key store, " + e.store + ", is locked or unreachable"
}

func (lockedError) Is(target error) bool { return target == ErrLocked }

// errUnavailable means no key store could be reached to seal or unseal with
// right now: no session bus and no usable kernel keyring on Linux, no
// Keychain reachable on macOS. Seal and Open both treat it as "nothing to
// seal with here," the same as platform being nil, rather than as a failure,
// so a cache still reads and writes without becoming unreadable or refusing
// to save. A platform that has no notion of transient unavailability, such as
// Windows' DPAPI, never returns it.
var errUnavailable = errors.New("atrest: no key store reachable")

// errNoKey is a key store that is reachable but holds no key under the name
// asked for: the data was sealed elsewhere, or the key did not survive.
var errNoKey = errors.New("atrest: no key under this name")

// envelopeVersion is written into every envelope. A reader refuses any other
// value, so a format change must bump it.
const envelopeVersion = 1

// envelope is the stored form of sealed data. Data is base64 in the JSON.
// Store names which of the platform's key stores holds the key, on a platform
// with more than one, so Open asks that store rather than whichever one is
// reachable at the time.
type envelope struct {
	Version int    `json:"atrest"`
	Alg     string `json:"alg"`
	Data    []byte `json:"data"`
	Store   string `json:"store,omitempty"`
}

// envelopeKeys are the envelope's JSON field names.
var envelopeKeys = []string{"atrest", "alg", "data", "store"}

// protector is a platform's data-protection facility. name is the caller's
// label for the data, bound into the protection where the facility allows,
// so data sealed under one name does not open under another. protect also
// reports which key store it used, empty where the platform has only one
// facility; unprotect is given that store back, or an empty string for an
// envelope written before stores were recorded.
type protector interface {
	alg() string
	protect(name string, plain []byte) (sealed []byte, store string, err error)
	unprotect(name, store string, sealed []byte) ([]byte, error)
}

// Available reports whether this platform has a sealing facility at all. It
// is true on Linux and macOS even where nothing is reachable at the moment
// — no D-Bus session, no usable kernel keyring, no Keychain — since that can
// change between one call and the next; Seal itself is what falls back to
// plaintext on a call it cannot seal.
func Available() bool {
	return platform != nil
}

// Persistent reports whether what Seal produces right now would still open
// after a reboot. It is false on Linux when only the kernel keyring is
// reachable, because that key does not survive one, and where the platform has
// no facility. A caller whose cache is worth more than the protection, such as
// a refresh token that costs an interactive sign-in to replace, can store it
// unsealed while this is false rather than lose it at every boot.
func Persistent() bool {
	return persistent()
}

// Unlock asks the platform to unlock the key store behind an ErrLocked through
// the desktop's own prompt, on Linux the Secret Service's dialog for the login
// keyring. It returns nil once the store is unlocked, and an error when it
// stays locked: the prompt was dismissed, ctx ended first, this process has no
// display to show a prompt on, or the platform has nothing to unlock.
func Unlock(ctx context.Context) error {
	return unlock(ctx)
}

// Seal protects data under name and returns the envelope to store. name must
// be the same at every Open of the result, and should be specific to the
// program and the file, since it keeps one program's sealed data from opening
// under another's name.
func Seal(name string, data []byte) ([]byte, error) {
	if platform == nil {
		return data, nil
	}
	sealed, store, err := platform.protect(name, data)
	if errors.Is(err, errUnavailable) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("atrest: sealing: %w", err)
	}
	return json.Marshal(envelope{Version: envelopeVersion, Alg: platform.alg(), Data: sealed, Store: store})
}

// Open returns the plaintext of data and whether data was sealed. Data that
// is not an envelope is returned as plaintext with sealed false; a caller
// that can seal should then store it sealed.
//
// A JSON object carrying envelope fields alongside others is also plaintext:
// an older build that preserves unknown fields read the envelope as an empty
// document and saved its own contents back around the envelope's fields.
// Those fields are removed before the plaintext is returned.
//
// An envelope that cannot be opened here returns an error wrapping
// ErrCannotOpen, and also ErrLocked when unlocking its key store would open it.
func Open(name string, data []byte) (plain []byte, sealed bool, err error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return data, false, nil
	}
	if _, ok := fields["atrest"]; !ok {
		return data, false, nil
	}
	if !onlyEnvelopeKeys(fields) {
		for _, k := range envelopeKeys {
			delete(fields, k)
		}
		plain, err := json.Marshal(fields)
		if err != nil {
			return nil, false, fmt.Errorf("atrest: removing stale envelope fields: %w", err)
		}
		return plain, false, nil
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, false, fmt.Errorf("%w: malformed envelope: %v", ErrCannotOpen, err)
	}
	if env.Version != envelopeVersion {
		return nil, false, fmt.Errorf("%w: envelope version %d", ErrCannotOpen, env.Version)
	}
	if platform == nil || env.Alg != platform.alg() {
		return nil, false, fmt.Errorf("%w: algorithm %q unavailable", ErrCannotOpen, env.Alg)
	}
	plain, err = platform.unprotect(name, env.Store, env.Data)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrCannotOpen, err)
	}
	return plain, true, nil
}

func onlyEnvelopeKeys(fields map[string]json.RawMessage) bool {
	for k := range fields {
		if !slices.Contains(envelopeKeys, k) {
			return false
		}
	}
	return true
}
