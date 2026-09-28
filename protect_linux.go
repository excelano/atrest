// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux

package atrest

import (
	"golang.org/x/sys/unix"
)

// platform on Linux is AES-256-GCM, keyed by whichever of two key stores this
// call finds reachable: the user's D-Bus Secret Service first, since it
// survives a reboot and is what a desktop session already keeps unlocked, and
// the kernel's per-user keyring otherwise, which does not survive a reboot but
// needs no daemon and works over SSH. Either way the key never touches disk.
//
// A cache is disposable — nothing is lost if its key goes away, only a
// sign-in — so a key that outlives one boot is a convenience, not a
// requirement, and losing it to a reboot is preferable to falling back to a
// third store weaker than either of these two.
var platform protector = keyedAESGCM{getOrCreateKey: linuxKey}

func linuxKey(name string) ([]byte, error) {
	if key, err := secretServiceKey(name); err == nil {
		return key, nil
	}
	if key, err := keyringKey(name); err == nil {
		return key, nil
	}
	return nil, errUnavailable
}

// keyringKey fetches or creates name's key in the kernel's per-user
// persistent keyring, linked into the session keyring so it is reachable the
// way request_key(2) expects. It needs no daemon and no unlocked session, so
// it is what SSH and cron have when nothing else is running, but a seccomp
// profile that blocks the keyctl syscall — Docker's default does — leaves it
// as unreachable as everything else.
func keyringKey(name string) ([]byte, error) {
	ring, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, -1, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
	if err != nil {
		return nil, err
	}
	desc := "atrest:" + name
	if id, err := unix.KeyctlSearch(ring, "user", desc, 0); err == nil {
		buf := make([]byte, 64)
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	// add_key updates a "user" key already under this description instead of
	// refusing, so two processes racing to create the first key for name can
	// leave the kernel holding whichever one called last. The loser then
	// fails to decrypt what it just sealed under its own copy — a lost cache,
	// not a lost key, so the cost is the one sign-in this design already
	// accepts.
	if _, err := unix.AddKey("user", desc, key, ring); err != nil {
		return nil, err
	}
	return key, nil
}
