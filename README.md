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

The name passed to `Seal` has to be passed again to `Open`, and data sealed under one name does not open under another. Make it specific to the program and the file, and never change it: a new name makes every existing file unreadable.

## The envelope

`Seal` returns a JSON object naming the envelope version and the algorithm that sealed the data. `Open` accepts either that envelope or plaintext and reports which it was given, so a program can migrate its existing files on first read instead of discarding them.

The envelope is JSON so that an older build of a program, one that hands the file straight to a JSON parser, sees an object it does not recognise rather than bytes it cannot parse. A parser that tolerates unknown fields reads the envelope as an empty document and carries on, and if that older build then saves its own data back around the envelope's fields, `Open` recognises the mixture as plaintext and removes the stale fields. Mixed old and new builds sharing a file therefore cost a fresh start in the old build, not a failure.

## Platforms

On Windows, `Seal` uses DPAPI, which encrypts under a key derived from the user's logon credentials, and passes the name as DPAPI's entropy. Elsewhere, `Available` reports false and `Seal` returns its input unchanged, so the caller's file stays plaintext and its protection is whatever file mode the caller gives it.

Sealing protects a file that leaves its context. It does not protect a file from other programs running as the same user, on any platform, because the operating system opens sealed data for any of them.

## License

MIT.
