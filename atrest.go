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
// seal it again instead of discarding it. Where no facility exists, Seal
// returns data unchanged and Available reports false.
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

// envelopeVersion is written into every envelope. A reader refuses any other
// value, so a format change must bump it.
const envelopeVersion = 1

// envelope is the stored form of sealed data. Data is base64 in the JSON.
type envelope struct {
	Version int    `json:"atrest"`
	Alg     string `json:"alg"`
	Data    []byte `json:"data"`
}

// envelopeKeys are the envelope's JSON field names.
var envelopeKeys = []string{"atrest", "alg", "data"}

// protector is a platform's data-protection facility. name is the caller's
// label for the data, bound into the protection where the facility allows,
// so data sealed under one name does not open under another.
type protector interface {
	alg() string
	protect(name string, plain []byte) ([]byte, error)
	unprotect(name string, sealed []byte) ([]byte, error)
}

// Available reports whether Seal protects data on this platform. When false,
// Seal returns its input unchanged.
func Available() bool {
	return platform != nil
}

// Seal protects data under name and returns the envelope to store. name must
// be the same at every Open of the result, and should be specific to the
// program and the file, since it keeps one program's sealed data from opening
// under another's name.
func Seal(name string, data []byte) ([]byte, error) {
	if platform == nil {
		return data, nil
	}
	sealed, err := platform.protect(name, data)
	if err != nil {
		return nil, fmt.Errorf("atrest: sealing: %w", err)
	}
	return json.Marshal(envelope{Version: envelopeVersion, Alg: platform.alg(), Data: sealed})
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
// ErrCannotOpen.
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
	plain, err = platform.unprotect(name, env.Data)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrCannotOpen, err)
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
