# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/atrest/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest release receives security fixes. Older versions are not supported.

## What atrest can access

atrest is a library, not a service. `Seal` and `Open` transform a byte slice the caller passes in, calling the operating system's data-protection API where there is one (DPAPI's `CryptProtectData` and `CryptUnprotectData` on Windows, with prompting forbidden). It reads and writes no files, makes no network calls and runs no subprocesses. Storing what `Seal` returns is the caller's job.

## What atrest stores

Nothing. It holds no key of its own: the key belongs to the operating system and never passes through atrest. No telemetry, no analytics, no remote logging.
