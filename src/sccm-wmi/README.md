# sccm-wmi BOF

A Beacon Object File (BOF) for recovering SCCM Network Access Account (NAA)
credentials from the **live** client policy (CRED-3). It queries the WMI
namespace `ROOT\ccm\policy\Machine\ActualConfig` for
`CCM_NetworkAccessAccount` and decrypts the `NetworkAccessUsername` /
`NetworkAccessPassword` `PolicySecret` blobs locally with
`CryptUnprotectData`, impersonating `SYSTEM`.

## Features

- Live WMI retrieval of `CCM_NetworkAccessAccount` (no disk parsing)
- Local DPAPI decrypt of `PolicySecret` blobs as `SYSTEM`
- Automatic `SYSTEM` impersonation (`winlogon`/`services`/`svchost`/`spoolsv`)
- High-integrity (admin) check before running
- Cross-architecture build (x64 and x86)

## Usage

### Syntax

```
sccm-wmi
```

### Examples

```bash
# Recover the NAA username and password from the live SCCM client policy
sccm-wmi
```

## Output Format

```
=== DPAPI SCCM CRED-3 (BOF) ===
[*] SCCM source: WMI ROOT\ccm\policy\Machine\ActualConfig

[*] Triaging SCCM Network Access Account #1
    Plaintext NAA Username : CORP\networkaccess
    Plaintext NAA Password : <recovered password>

[*] SCCM WMI triage complete: 1 account entries, 2 decrypted secrets
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

- One network access account is expected on a given client; all returned
  entries are triaged.
- If SCCM is configured to use the client's machine account instead of an NAA,
  the BOF reports `[!] SCCM is configured to use the client's machine account
  instead of an NAA`.
- The legacy manual `DPAPI_SYSTEM -> masterkey -> blob` path is intentionally
  not included; the WMI path only exercises the direct `CryptUnprotectData`
  (CRED_PROTECTED blob) decrypt.
- For on-disk `OBJECTS.DATA` recovery (CRED-4), use the `sccm-disk` BOF.
- For local file/cache/log/registry enumeration (RECON-7), use `sccm-local-recon`.
