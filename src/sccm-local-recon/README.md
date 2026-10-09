# sccm-local-recon BOF

A Beacon Object File (BOF) for local SCCM client reconnaissance (RECON-7). It
runs in the current user's context (no `SYSTEM` impersonation) and:

- Summarizes the SCCM local paths (`CCM\Logs`, `ccmcache`, `ccmsetup`) with
  per-user read/write access.
- Lists the client cache (`ccmcache`) tree (depth 2) with per-entry permissions
  and sizes.
- Reads the `HKLM\SOFTWARE\Microsoft\SMS\DP\ManagementPoints` registry value.
- Scrapes the CCM logs for candidate UNC paths and URLs.

## Features

- Local SCCM path, cache, and registry enumeration
- Per-user read/write permission probing (`CreateFileW` access checks)
- CCM log scraping for UNC paths and `http(s)` URLs
- Read-only, current-user-context (no `SYSTEM`, no DPAPI)
- Cross-architecture build (x64 and x86)

## Usage

### Syntax

```
sccm-local-recon
```

### Examples

```bash
# Enumerate the local SCCM client (paths, cache, ManagementPoints, log UNC/URLs)
sccm-local-recon
```

## Output Format

```
=== DPAPI SCCM RECON-7 (BOF) ===
[*] SCCM local paths:
    drw-  C:\Windows\CCM\Logs
    drw-  C:\Windows\ccmcache
    drw-  C:\Windows\ccmsetup

[*] Client cache contents and permissions for the current user:
    Perms      Size  Name
    -rw-    12.3KB  C:\Windows\ccmcache\1\0
    -rw-    45.0KB  C:\Windows\ccmcache\1\0\a

[*] Registry ManagementPoints:
    http://smsdist.corp.local:80/SMS_MP/

[*] Searching logs for possible UNC paths:
    Found match in C:\Windows\CCM\Logs\execmgr.log
      \\fileserver\dept\...

[*] Searching logs for possible URLs:
    Found match in C:\Windows\CCM\Logs\execmgr.log
      http://smsdist.corp.local/...
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

- Read-only: file enumeration, registry read, and log scanning only.
- Log scanning reads files up to 8 MiB each from `C:\Windows\CCM\Logs`.
- For credential recovery use `sccm-wmi` (CRED-3, live WMI) or `sccm-disk`
  (CRED-4, on-disk `OBJECTS.DATA`).
