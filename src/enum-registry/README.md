# Enum Registry BOF

A Beacon Object File (BOF) for gathering intelligence from the Windows Registry.

## Overview

Enum Registry BOF performs read-only enumeration of Windows Registry to gather system intelligence including:

- **RDP Connection History**: Enumerates past RDP connections from Terminal Server Client registry keys
- **Installed Software**: Lists installed applications from both 64-bit and 32-bit Uninstall registry keys
- **Environment Variables**: Displays system and user environment variables
- **WSL/Docker Detection**: Detects Windows Subsystem for Linux and Docker Desktop installations

## Features

- Read-only registry operations (no system modifications)
- Selective intelligence gathering via flags
- Comprehensive error handling
- Heap allocation for large buffers (minimal stack usage)
- Support for both x86 and x64 architectures

## Compilation

### Prerequisites

- mingw-w64 cross-compiler (`x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`)
- GNU Make

### Build Commands

```bash
# Compile BOF object files for both architectures
make all

# Compile as executable for local testing
make test

# Clean build artifacts
make clean
```

### Build Outputs

- `enum-registry.x64.o` - 64-bit BOF object file
- `enum-registry.x86.o` - 32-bit BOF object file

## Usage

### Arguments

The BOF accepts a single integer argument representing intelligence type flags:

```c
#define INTEL_TYPE_RDP      0x01  // RDP connection history
#define INTEL_TYPE_SOFTWARE 0x02  // Installed software
#define INTEL_TYPE_ENV      0x04  // Environment variables
#define INTEL_TYPE_WSL      0x08  // WSL/Docker detection
#define INTEL_TYPE_ALL      0xFF  // All intelligence types
```

### Examples

```
# Gather all intelligence (default)
enum-registry 0xFF

# RDP history only
enum-registry 0x01

# Software and environment variables
enum-registry 0x06

# WSL detection only
enum-registry 0x08
```

## Performance Characteristics

### Execution Time

**Expected execution time varies based on registry size:**

- **Typical execution**: 1-5 seconds
- **Systems with extensive software installations**: 5-10 seconds
- **Minimal systems**: <1 second

The BOF blocks the beacon during execution. Execution time depends on:
- Number of installed software packages
- Number of environment variables
- Number of RDP connection history entries

### Resource Usage

- **Stack usage**: <1KB per function (heap allocation for large buffers)
- **Memory**: Allocates heap memory for registry value buffers, freed after use
- **Privileges**: Runs with current user privileges; some operations may require elevation

## Security Considerations

### Information Disclosure

This tool is designed to enumerate and display sensitive system information including:
- RDP connection history (may include server names and usernames)
- Installed software inventory
- Environment variables (may contain paths, credentials, or configuration)
- WSL/Docker presence

**Handle output securely and follow operational security practices.**

### Privileges

- **User context**: Most operations work with standard user privileges
- **Elevated context**: Some software enumeration keys (HKLM) may require administrator privileges for full visibility

### Operational Safety

- **Read-only operations**: No registry modifications
- **No network activity**: Local enumeration only
- **No credential harvesting**: Does not extract or transmit credentials

## Technical Details

### Registry Keys Accessed

**RDP History:**
- `HKCU\Software\Microsoft\Terminal Server Client\Servers`
- `HKCU\Software\Microsoft\Terminal Server Client\Default`

**Installed Software:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

**Environment Variables:**
- `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`
- `HKCU\Environment`

**WSL/Docker:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`
- `HKLM\Software\Docker Inc.\Docker\1.0`

### API Usage

All registry operations use Wide (Unicode) string APIs:
- `RegOpenKeyExW`
- `RegEnumKeyExW`
- `RegEnumValueW`
- `RegQueryValueExW`
- `RegCloseKey`

Memory management uses Windows Heap APIs:
- `HeapAlloc` (with `HEAP_ZERO_MEMORY`)
- `HeapFree`

## Error Handling

The BOF implements comprehensive error handling:
- All registry API calls check return values
- Graceful fallback on access denied or missing keys
- NULL pointer checks before heap allocations
- Proper resource cleanup on all code paths

## Limitations

- Blocks beacon during execution (1-10 seconds typical)
- Registry size affects execution time
- Some HKLM keys may require elevated privileges
- Large software catalogs (100+ packages) may extend execution time

## Code Quality

- Position-independent code (PIC) compilation
- Stripped symbols for reduced size
- Heap allocation for large buffers (no stack overflow risk)
- No global variables
- No hardcoded addresses or magic numbers

## License

This BOF is intended for authorized red team operations and security assessments only.
