// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build darwin

package atrest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

// platform on macOS is AES-256-GCM, keyed by a generic password this call
// keeps in the user's login Keychain.
var platform protector = keyedAESGCM{getOrCreateKey: keychainKey}

// persistent is true because the login Keychain outlives a reboot. A Keychain
// that cannot be reached makes Seal return its input unchanged, which also
// outlives one.
func persistent() bool { return true }

// keychainAccount is the Keychain item's account field for every key this
// package stores. One constant works because items are told apart by
// service, not by account, and the account field carries nothing this design
// needs.
const keychainAccount = "atrest"

// keychainKey fetches or creates name's key as a generic password in the
// user's login Keychain, through the security(1) command line rather than
// linking a Keychain binding directly into every consumer's binary.
//
// The reason is the access control list a Keychain item carries: it names
// the process that created it, and lets that process read it back without a
// prompt. A binding compiled into each of the family's binaries would put a
// different name on that list for every one of them, and a fresh one again
// on every unsigned rebuild, so each first run and each upgrade would raise
// its own "xftp wants to access your keychain" dialog. Asking
// /usr/bin/security to do it instead means the ACL names one binary every
// build of every family member shares, already trusted, so nothing prompts.
//
// name becomes the item's service string only as a hash: security's
// interactive-mode command parser is not one this code has been able to
// exercise against a real build, and a name callers can put arbitrary bytes
// into should never reach it unescaped.
func keychainKey(name string) ([]byte, error) {
	service := "atrest-" + hex.EncodeToString(sha256Sum(name))
	if key, ok := findKeychainKey(service); ok {
		return key, nil
	}
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if _, err := runSecurity(fmt.Sprintf("add-generic-password -a %s -s %s -w %s -U", keychainAccount, service, encoded)); err != nil {
		return nil, errUnavailable
	}
	// Read the item back rather than trust the write succeeded: a locked or
	// otherwise unreachable Keychain can let the command exit cleanly without
	// the item actually persisting, and returning an unverified key would
	// seal this run's cache under bytes a later run can never find again.
	if got, ok := findKeychainKey(service); ok && bytes.Equal(got, key) {
		return key, nil
	}
	return nil, errUnavailable
}

func findKeychainKey(service string) ([]byte, bool) {
	out, err := runSecurity(fmt.Sprintf("find-generic-password -a %s -s %s -w", keychainAccount, service))
	if err != nil {
		return nil, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(key) != 32 {
		return nil, false
	}
	return key, true
}

// runSecurity sends one command to security(1) in interactive mode, over
// stdin rather than as an argument, so a key never appears in this process's
// argv, or any other process's ps listing.
//
// A failed exit maps to errUnavailable: a headless session or a locked
// Keychain are the two ordinary reasons, and the caller degrades the same way
// for either. Success is judged by the exit status alone; a per-command
// failure inside an otherwise successful interactive session, such as
// find-generic-password reporting no such item, is instead read from what
// came back, in findKeychainKey and in the read-back after create above.
func runSecurity(command string) (string, error) {
	cmd := exec.Command("/usr/bin/security", "-i")
	// One command, then EOF: -i exits with that command's own status once
	// stdin runs out. There is no "quit" command — sending one exits the
	// session with an "unknown command" failure that would mask whatever the
	// real command just did, which a build without a Mac to test against did
	// not catch until this was run for real.
	cmd.Stdin = strings.NewReader(command + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", errUnavailable
	}
	return out.String(), nil
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
