# Credential Guard Check BOF

A Beacon Object File (BOF) to check the status of Windows security features including Credential Guard, HVCI, LSA Protection, and VBS.

## Features

This BOF checks the following Windows security features:

- **Credential Guard**: Protects credentials by isolating them using virtualization-based security
- **HVCI** (Hypervisor-protected Code Integrity): Ensures only properly signed code can run in kernel mode
- **LSA Protection** (RunAsPPL): Runs LSASS as a protected process to prevent credential dumping
- **VBS** (Virtualization-Based Security): Foundational security feature using hardware virtualization

## Detection Methods

The BOF uses registry key queries to determine security feature status:

| Security Feature | Registry Location | Detection Method |
|-----------------|-------------------|------------------|
| Credential Guard | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` | DWORD value (1=UEFI lock, 2=no UEFI lock, 0=disabled) |
| HVCI | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` | DWORD value (1=enabled, 0=disabled) |
| LSA Protection | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | DWORD value (1=UEFI, 2=no UEFI, 0=disabled) |
| VBS | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` | DWORD value (1=enabled, 0=disabled) |

## Compilation

### Prerequisites

- `x86_64-w64-mingw32-gcc` (for x64 compilation)
- `i686-w64-mingw32-gcc` (for x86 compilation)

### Building

```bash
# Compile BOF object files
make all

# Compile test executables for local testing
make test

# Clean build artifacts
make clean
```

### Output Files

- `dist/credguard-check.x64.o` - 64-bit BOF object file
- `dist/credguard-check.x86.o` - 32-bit BOF object file
- `credguard-check.x64.exe` - 64-bit test executable (optional, root directory)
- `credguard-check.x86.exe` - 32-bit test executable (optional, root directory)

## Usage

### Cobalt Strike

1. Load the Aggressor script:
   ```
   beacon> load credguard-check.cna
   ```

2. Execute the BOF:
   ```
   beacon> credguard-check
   ```

### OC2

Execute via OC2:
```
credguard-check
```

## Example Output

```
========================================
  Windows Security Features Check
========================================

[*] Credential Guard Status:
    [+] ENABLED with UEFI lock (Value: 1)

[*] HVCI (Hypervisor-protected Code Integrity) Status:
    [+] ENABLED (Value: 1)

[*] LSA Protection (RunAsPPL) Status:
    [+] ENABLED with UEFI variable (Value: 1)

[*] VBS (Virtualization-Based Security) Status:
    [+] ENABLED (Value: 1)
    [*] Platform Security Features: Secure Boot + DMA Protection

========================================
  Scan Complete
========================================
```

## Technical Details

### BOF Implementation

- **Language**: C
- **APIs Used**: Registry APIs (RegOpenKeyExA, RegQueryValueExA, RegCloseKey)
- **Memory**: Stack-based (no heap allocations)
- **Size**: ~4KB per architecture

### File Structure

```
credguard-check/
├── beacon.h                      # BOF API declarations
├── entry.c                       # Main BOF implementation
├── Makefile                      # Compilation rules
├── credguard-check.cna           # Cobalt Strike Aggressor script
├── credguard_check_bof.s1.py     # OC2 Python script
├── dist/                         # Compiled BOF binaries
│   ├── credguard-check.x64.o     # Compiled x64 BOF
│   └── credguard-check.x86.o     # Compiled x86 BOF
└── README.md                     # This file
```

## OPSEC Considerations

### Stealth

- **No Network Activity**: All checks are local registry queries
- **No New Processes**: Executes within the beacon process
- **Small Memory Footprint**: ~4KB BOF with minimal stack usage
- **Fast Execution**: Registry queries complete in milliseconds

### Detection Surface

- **Registry Access**: The BOF queries multiple registry keys under `HKLM\SYSTEM`
- **Read-Only Operations**: No modifications are made to the system
- **Standard APIs**: Uses common Windows registry APIs

### Defensive Detections

Potential detection methods:
- Registry access monitoring for security-related keys
- Sysmon Event ID 12 (RegistryEvent - Object create and delete)
- Sysmon Event ID 13 (RegistryEvent - Value Set)
- Windows Event ID 4656 (A handle to an object was requested)

## References

### Microsoft Documentation

- [Credential Guard Overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Configure Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [Memory Integrity (HVCI)](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

### Research & Analysis

- [Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)
- [LSA Protection Bypass/Detection](https://medium.com/h7w/lsa-protection-bypass-detection-16e8db3ab66c)

## License

This BOF is provided for authorized security testing, defensive security, CTF challenges, and educational contexts only.

## Author

Created: 2025-11-11
