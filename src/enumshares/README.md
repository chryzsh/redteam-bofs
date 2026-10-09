
# enumshares

Enumerate remote shares and their access level on a single host or across multiple hosts from a file.

## Overview

`enumshares` connects to each target host and enumerates all available SMB shares. For each share, it tests actual filesystem read access using `FindFirstFileW` to determine whether the current user can list the share contents.

## Usage

### Single Host (inline)

Provide a hostname or IP directly:
```
enumshares DC01
enumshares 10.100.10.1
enumshares fileserver.example.local
```

### Multiple Hosts (file upload)

Upload a newline-separated hostnames file through the OC2 GUI or CNA, then run:
```
enumshares
```

In Cobalt Strike, pass the file path on the operator's system:
```
enumshares C:\Users\RTO\Documents\hostnames.txt
```

### Hostnames File Format

One hostname per line, ending with a newline:
```
database
database.example.local
10.100.10.1
```

### Output
- `[+] Accessible` — share contents can be listed (confirmed read access)
- `[-] Access denied` — no filesystem access to the share
- `[!] No file system access` — IPC$ share (skipped)

## Build

```bash
make          # Build x64 + x86
make x64      # Build x64 only
make x86      # Build x86 only
make clean    # Remove artifacts
```

## Credits

Originally from [REDMED-X/OperatorsKit](https://github.com/REDMED-X/OperatorsKit). Modified to fix false positive access checks by replacing `NetUseAdd` (share-level connection test) with `FindFirstFileW` (actual filesystem access test).
