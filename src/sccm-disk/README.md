# sccm-disk BOF

A Beacon Object File (BOF) for recovering SCCM Network Access Account (NAA)
credentials from the **on-disk** CIM repository (CRED-4). It parses
`OBJECTS.DATA` for `CCM_NetworkAccessAccount` and decrypts the
`NetworkAccessUsername` / `NetworkAccessPassword` `PolicySecret` blobs locally
with `CryptUnprotectData`, impersonating `SYSTEM`.

## Features

- On-disk parsing of the SCCM CIM repository (`OBJECTS.DATA`)
- Local DPAPI decrypt of `PolicySecret` blobs as `SYSTEM`
- Automatic `SYSTEM` impersonation (`winlogon`/`services`/`svchost`/`spoolsv`)
- High-integrity (admin) check before running
- Optional target path (defaults to the standard `OBJECTS.DATA` location)
- Cross-architecture build (x64 and x86)

## Usage

### Syntax

```
sccm-disk [PATH]
```

### Examples

```bash
# Use the default OBJECTS.DATA location
sccm-disk

# Parse a specific OBJECTS.DATA copy
sccm-disk C:\Windows\System32\wbem\Repository\OBJECTS.DATA
```

## Output Format

```
=== DPAPI SCCM CRED-4 (BOF) ===
[*] SCCM source file: C:\Windows\System32\wbem\Repository\OBJECTS.DATA

[*] Triaging SCCM Network Access Account #1
    Plaintext NAA Username : CORP\networkaccess
    Plaintext NAA Password : <recovered password>

[*] SCCM disk triage complete: 2 decrypted secrets
```

## Build

```bash
# Build BOF objects for x64 and x86
make all

# Build a standalone test executable (x64)
make test

# Run boflint on both objects
make lint

# Clean build artifacts
make clean
```

## Notes

- Defaults to `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` when no path
  is given.
- NAA-only: this BOF recovers the network access account. It does not parse
  task sequences or collection variables.
- The legacy manual `DPAPI_SYSTEM -> masterkey -> blob` path is intentionally
  not included; only the direct `CryptUnprotectData` (CRED_PROTECTED blob)
  decrypt is exercised.
- If SCCM is configured to use the client's machine account instead of an NAA,
  the BOF reports `[!] SCCM is configured to use the client's machine account
  instead of an NAA`.
- For live WMI policy recovery (CRED-3), use the `sccm-wmi` BOF. For local
  file/cache/log/registry enumeration (RECON-7), use `sccm-local-recon`.
