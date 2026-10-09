# checkaccess BOF

A Beacon Object File (BOF) for probing read access on a directory path and its subdirectories.
Supports both UNC paths and local paths, with output in the same verdict style as `enumshares`.

## Features

- Directory read access probe for a single path plus subdirectory checks
- Depth-1 mode by default, optional full recursive mode (`-r`)
- Supports UNC and local directory paths
- Enumshares-style verdict output (`[+] Accessible`, `[-] Access denied`, `[!] No file system access`)
- Read-only operation (no writes)
- Cross-architecture build (x64 and x86)

## Usage

### Syntax

```
checkaccess [--recursive|-r] [--suppress-access-denied|--suppress-denied|-s] <path>
```

### Examples

```bash
# UNC directory
checkaccess \\test\dept

# Recursive through all nested subdirectories
checkaccess \\test\dept -r

# Nested UNC directory
checkaccess \\fileserver\projects\retail

# Local directory
checkaccess C:\Users\Public
```

## Output Format

```
Path: \\test\dept <- [+] Accessible
Subfolders (depth 1):
Path: \\test\dept\finance <- [+] Accessible
Path: \\test\dept\hr <- [-] Access denied
Path: \\test\secret <- [-] Access denied
Path: \\test\IPC$ <- [!] No file system access
Path: C:\Windows\System32\notadir.txt <- [-] Not a directory
```

## Build

```bash
# Build BOF objects for x64 and x86
make all

# Build test executables
make test

# Clean build artifacts
make clean
```

## Notes

- One parent path per invocation
- Checks immediate child directories by default; use `-r` for all nested levels
- `--suppress-access-denied` suppresses only subdirectory `[-] Access denied` lines
- Directory checks only (not file checks)
- Primary use case is UNC directory access probing
- Uses `GetFileAttributesW` + `FindFirstFileW(<path>\\*)` probe model
