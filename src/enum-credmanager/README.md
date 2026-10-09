# Credential Manager Enumeration BOF

A simple, reliable Beacon Object File (BOF) for enumerating Windows Credential Manager credentials for the current user.

## Overview

This BOF uses the standard `CredEnumerateW` Windows API to list all credentials stored in the Windows Credential Manager. It displays metadata including target names, usernames, credential types, and persistence settings **without decrypting passwords** (enumeration only).

## Features

- ✅ **Simple & Reliable:** Uses documented Windows API (CredEnumerateW)
- ✅ **No Admin Required:** Works in current user context
- ✅ **Low OPSEC Footprint:** Read-only operation, standard Windows API
- ✅ **Comprehensive Output:** Shows all credential metadata
- ✅ **Optional Filtering:** Filter credentials by target name
- ✅ **Safe:** No decryption, no privilege escalation, no disk writes

## Credential Types Supported

- **GENERIC:** Generic credentials (created with `cmdkey /generic`)
- **DOMAIN_PASSWORD:** Domain passwords (RDP, network shares, domain logons)
- **DOMAIN_CERTIFICATE:** Certificate-based domain credentials
- **DOMAIN_VISIBLE_PASSWORD:** Domain passwords with visible UI prompts
- **GENERIC_CERTIFICATE:** Generic certificate-based credentials

## Compilation

```bash
# Compile for both x86 and x64
make all

# Compile test executables (for local testing)
make test

# Clean build artifacts
make clean
```

**Requirements:**
- mingw-w64 toolchain (x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc)

## Usage

### OC2 (Operator Console 2)

Load the BOF script in your OC2 scripts directory, then:

```bash
# List all credentials
enum-credmanager

# Filter by target name
enum-credmanager -f github.com
enum-credmanager --filter corp.local
enum-credmanager -f LegacyGeneric
```

### Cobalt Strike (Aggressor Script)

If using with Cobalt Strike, create an Aggressor script to load the BOF.

## Example Output

```
[*] Enumerating Windows Credential Manager entries...
[*] Context: Current user

[+] Found 9 credential(s)

================================================================================

[Credential 1]
  Target:      LegacyGeneric:target=https://github.com
  Username:    testuser@github.com
  Type:        GENERIC
  Persistence: LOCAL_MACHINE
  Blob Size:   42 bytes (encrypted)
  Last Write:  2025-11-15 14:32:15

[Credential 2]
  Target:      server01.corp.local
  Username:    CORP\admin
  Type:        DOMAIN_PASSWORD
  Persistence: LOCAL_MACHINE
  Blob Size:   38 bytes (encrypted)
  Last Write:  2025-11-15 14:35:22

[Credential 3]
  Target:      MicrosoftAccount:user=bob@outlook.com
  Username:    bob@outlook.com
  Type:        GENERIC
  Persistence: ENTERPRISE
  Blob Size:   128 bytes (encrypted)
  Comment:     Microsoft Account Credential
  Last Write:  2025-11-10 09:15:33

================================================================================
[+] Enumeration complete: 9 credential(s) found
```

## Testing

### Create Test Credentials

Run the PowerShell script to create test credentials:

```powershell
.\create-test-credentials.ps1
```

This will create:
- 5 Generic credentials (web/app services)
- 4 Domain credentials (network/RDP)

### Verify Credentials

You can view credentials in Windows Credential Manager:

```powershell
# GUI
rundll32.exe keymgr.dll,KRShowKeyMgr

# Command line
cmdkey /list
```

### Cleanup Test Credentials

Remove individual credentials:

```powershell
cmdkey /delete:LegacyGeneric:target=https://github.com
cmdkey /delete:server01.corp.local
```

## Technical Details

### APIs Used

- `CredEnumerateW()` - Enumerate all credentials for current user
- `CredFree()` - Free credential array
- `FileTimeToLocalFileTime()` - Convert timestamps
- `FileTimeToSystemTime()` - Convert to readable time

### Libraries Required

- `advapi32.lib` - For Credential Manager APIs

### Argument Encoding

The BOF accepts an optional filter string:
- **No arguments:** Lists all credentials
- **One string argument:** Filters credentials by target name (case-insensitive substring match)

**OC2 Encoding:** `z` (optional string) or empty

## OPSEC Considerations

### Low Detection Risk

- ✅ Uses standard, documented Windows API
- ✅ No privileged operations required
- ✅ Read-only, no modifications
- ✅ No unusual API call patterns
- ✅ No network operations
- ✅ No disk writes

### What's Logged

- **Windows Event Log:** Credential Manager access may be logged in Security log (Event ID 5379-5381) depending on audit policy
- **EDR/AV:** Standard credential enumeration, low suspicion
- **Network Traffic:** None

### Comparison to Other Methods

| Method | Admin Required | Detection Risk | Reliability |
|--------|----------------|----------------|-------------|
| This BOF (CredEnumerateW) | No | Low | High |
| Privilege Escalation + CredBackup | Yes | High | Medium |
| File Parsing (direct DPAPI) | No | Low | Low |
| Mimikatz | Yes | Very High | High |

## Limitations

- **Current User Only:** Cannot enumerate other users' credentials
- **No Decryption:** Shows metadata only, not passwords (see decrypt-credmanager BOF for decryption)
- **Session-Based Creds:** Only shows credentials for the current user session

## Next Steps

After enumeration, you can:

1. **Use decrypt-credmanager BOF** to decrypt passwords for identified credentials
2. **Target specific credentials** based on target names (e.g., RDP servers, databases)
3. **Cross-reference** with other reconnaissance data

## Files

- `entry.c` - BOF source code
- `beacon.h` - Beacon and Windows API declarations
- `Makefile` - Build configuration
- `enum_credmanager_bof.s1.py` - OC2 Python interface
- `create-test-credentials.ps1` - PowerShell script to create test data
- `README.md` - This file

## Credits

- **Approach:** Standard Windows API usage (CredEnumerateW)
- **Implementation:** enum-credmanager BOF

## References

- [Microsoft Docs - CredEnumerateW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew)
- [Microsoft Docs - Credential Manager](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)
- [Windows Credential Manager Overview](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)

---

**Status:** ✅ Complete - Ready for testing
**Complexity:** Low
**Value:** Medium (reconnaissance)
**OPSEC:** Low risk
