# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/atrest/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest release receives security fixes. Older versions are not supported.

## What atrest can access

atrest is a library, not a service. `Seal` and `Open` transform a byte slice the caller passes in, calling on the operating system to do it: DPAPI's `CryptProtectData` and `CryptUnprotectData` on Windows, with prompting forbidden; on Linux, the user's own D-Bus session bus to reach the Secret Service, or the kernel keyring syscalls where that is unreachable; on macOS, the `/usr/bin/security` command line to reach the login Keychain. Every one of these stays on the local machine and under the calling user's own account; none of them is a network call in the sense of leaving the host. It reads and writes no files of its own — storing what `Seal` returns is the caller's job — and starts no process except `/usr/bin/security` on macOS.

## What atrest stores

Nothing outside the platform's own secret store. On Windows, DPAPI derives its key from the user's logon credentials, and no key of atrest's own making is ever involved. On Linux and macOS, atrest generates a random key the first time `Seal` is called for a given name and hands it to the platform's secret store to hold; from then on it is read back from there, never written to a file, and never logged. No telemetry, no analytics, no remote logging.
