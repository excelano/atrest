# atrest

A small Go library that seals local files, such as token caches, with the operating system's own data protection, so a copy of the file taken off the account that wrote it cannot be read. A backup, a synced home directory and a disk image all carry the file without the means to open it.

It exists so that a program which has to keep a credential on disk does not also keep a key beside it. A key stored next to the ciphertext protects nothing, and the operating system already holds a secret tied to the user's logon that the program can borrow.

## Install

```
go get github.com/excelano/atrest
```

## Usage

```go
import "github.com/excelano/atrest"

stored, err := atrest.Seal("myapp/token", cache)
if err != nil { /* ... */ }
// write stored to disk

plain, sealed, err := atrest.Open("myapp/token", stored)
switch {
case errors.Is(err, atrest.ErrCannotOpen):
    // sealed by another user or machine: treat the file as absent
case err != nil:
    // ...
case !sealed && atrest.Available():
    // plaintext from an older build: use it, and store it sealed now
}
```

```go
if atrest.Persistent() {
    stored, err = atrest.Seal("myapp/token", cache)
} else {
    stored = cache
}
```

The name passed to `Seal` has to be passed again to `Open`, and data sealed under one name does not open under another. Make it specific to the program and the file, and never change it: a new name makes every existing file unreadable.

## The envelope

`Seal` returns a JSON object naming the envelope version and the algorithm that sealed the data. `Open` accepts either that envelope or plaintext and reports which it was given, so a program can migrate its existing files on first read instead of discarding them.

The envelope is JSON so that an older build of a program, one that hands the file straight to a JSON parser, sees an object it does not recognise rather than bytes it cannot parse. A parser that tolerates unknown fields reads the envelope as an empty document and carries on, and if that older build then saves its own data back around the envelope's fields, `Open` recognises the mixture as plaintext and removes the stale fields. Mixed old and new builds sharing a file therefore cost a fresh start in the old build, not a failure.

## Platforms

On Windows, `Seal` uses DPAPI, which encrypts under a key derived from the user's logon credentials, and passes the name as DPAPI's entropy.

On Linux and macOS, `Seal` encrypts with AES-256-GCM under a key it keeps in the platform's own secret store rather than beside the ciphertext: the user's D-Bus Secret Service on Linux, falling back to the kernel's per-user keyring when no session bus or no unlocked collection is reachable, and the login Keychain on macOS. A key that only lives in the kernel keyring does not survive a reboot, and a Secret Service whose collection is locked, as on a machine that logs in without a password to unlock it, falls through to that keyring. `Persistent` reports whether `Seal` would currently key under a store that survives a reboot. A caller whose file is costly to lose, such as a refresh token that takes an interactive sign-in to replace, can store it unsealed while `Persistent` is false instead of losing it at every boot.

Where nothing is reachable — no D-Bus session and no usable keyring, a locked Keychain, a container whose seccomp profile blocks the kernel keyring call — `Seal` returns its input unchanged rather than failing, so the caller's file stays plaintext and its protection is whatever file mode the caller gives it. This can happen even though `Available` reports true, since availability is a property of the platform and reachability is a property of the moment.

Sealing protects a file that leaves its context. It does not protect a file from other programs running as the same user, on any platform, because the operating system opens sealed data for any of them.

## License

MIT.
