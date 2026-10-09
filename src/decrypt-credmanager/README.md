# Credential Manager Decryption BOF

A simple, reliable Beacon Object File (BOF) for enumerating and **decrypting** Windows Credential Manager credentials for the current user.

## Overview

This BOF uses the standard `CredEnumerateW` and `CryptUnprotectData` Windows APIs to list all credentials stored in the Windows Credential Manager and **decrypt their passwords**. It works entirely in the current user's context without requiring admin privileges.

## Features

- ✅ **Simple & Reliable:** Uses documented Windows APIs (CredEnumerateW + CryptUnprotectData)
- ✅ **Password Decryption:** Extracts plaintext passwords from credential blobs
- ✅ **No Admin Required:** Works in current user context
- ✅ **DPAPI Decryption:** Uses Windows DPAPI for secure credential decryption
- ✅ **Comprehensive Output:** Shows all credential metadata AND decrypted passwords
- ✅ **Optional Filtering:** Filter credentials by target name
- ✅ **Error Handling:** Clear messages when decryption fails (different user, etc.)

## How It Works

1. **Enumerate:** Uses `CredEnumerateW()` to list all credentials for current user
2. **Decrypt:** For each credential, calls `CryptUnprotectData()` to decrypt the password blob
3. **Parse:** Interprets decrypted data as Unicode/ASCII password string
4. **Display:** Shows plaintext password along with metadata

**Key Point:** DPAPI can only decrypt credentials encrypted by the **same user**. Credentials from other users will fail to decrypt.

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
# Decrypt all credentials
decrypt-credmanager

# Filter by target name
decrypt-credmanager -f github.com
decrypt-credmanager --filter corp.local
decrypt-credmanager -f rdp
```

### Cobalt Strike (Aggressor Script)

If using with Cobalt Strike, create an Aggressor script to load the BOF.

## Example Output

```
[*] Enumerating and decrypting Windows Credential Manager entries...
[*] Context: Current user
[!] Note: Only credentials encrypted by current user can be decrypted

[+] Found 9 credential(s)

================================================================================

[Credential 1]
  Target:      LegacyGeneric:target=https://github.com
  Username:    testuser@github.com
  Type:        GENERIC
  Persistence: LOCAL_MACHINE
  Last Write:  2025-11-15 14:32:15
  Blob Size:   42 bytes (encrypted)
  [+] Decryption: SUCCESS
  Password:    GitHubTestPassword123!
  Decrypted:   47 00 69 00 74 00 48 00 75 00 62 00 54 00 65 00 ...

[Credential 2]
  Target:      server01.corp.local
  Username:    CORP\admin
  Type:        DOMAIN_PASSWORD
  Persistence: LOCAL_MACHINE
  Last Write:  2025-11-15 14:35:22
  Blob Size:   38 bytes (encrypted)
  [+] Decryption: SUCCESS
  Password:    ServerAdminPass123!
  Decrypted:   53 00 65 00 72 00 76 00 65 00 72 00 41 00 64 00 ...

[Credential 3]
  Target:      MicrosoftAccount:user=alice@outlook.com
  Username:    alice@outlook.com
  Type:        GENERIC
  Persistence: ENTERPRISE
  Last Write:  2025-11-10 09:15:33
  Blob Size:   128 bytes (encrypted)
  [-] Decryption: FAILED (Error: 13)
      Reason: Likely encrypted by different user

================================================================================
[+] Enumeration complete: 9 credential(s) found
[+] Decryption results: 8 successful, 1 failed

[!] Failed credentials were likely encrypted by a different user
[!] DPAPI can only decrypt data encrypted by the same user in same context
```

## Testing

### Create Test Credentials

Run the PowerShell script to create test credentials with known passwords:

```powershell
.\create-test-credentials.ps1
```

This will create:
- 5 Generic credentials (web/app services) with passwords like `GitHubTestPassword123!`
- 4 Domain credentials (network/RDP) with passwords like `ServerAdminPass123!`

### Verify Decryption

Run the BOF and verify it decrypts the known passwords:

```bash
decrypt-credmanager
```

You should see all the test passwords displayed in plaintext.

### Cleanup Test Credentials

Remove individual credentials:

```powershell
cmdkey /delete:LegacyGeneric:target=https://github.com
cmdkey /delete:server01.corp.local
```

## Technical Details

### APIs Used

- `CredEnumerateW()` - Enumerate all credentials for current user
- `CryptUnprotectData()` - Decrypt DPAPI-protected data (credential passwords)
- `CredFree()` - Free credential array
- `LocalFree()` - Free decrypted data buffer
- `FileTimeToLocalFileTime()` / `FileTimeToSystemTime()` - Convert timestamps

### Libraries Required

- `advapi32.lib` - For Credential Manager APIs
- `crypt32.lib` - For DPAPI decryption

### DPAPI Context

**Important:** `CryptUnprotectData()` only works for credentials encrypted by the **current user** in the **current logon session**.

| Scenario | Result |
|----------|--------|
| Current user's credential | ✅ Decrypts successfully |
| Different user's credential | ❌ Fails with ERROR_INVALID_DATA |
| SYSTEM context credential (from user session) | ❌ Fails (wrong context) |
| User context credential (from SYSTEM) | ❌ Fails (wrong context) |

### Argument Encoding

The BOF accepts an optional filter string:
- **No arguments:** Decrypts all credentials
- **One string argument:** Filters credentials by target name (case-insensitive substring match)

**OC2 Encoding:** `z` (optional string) or empty

## OPSEC Considerations

### Detection Risk: Medium

- ✅ Uses standard, documented Windows APIs
- ✅ No privileged operations required
- ⚠️ DPAPI decryption is a normal user operation, but credential access may be logged
- ✅ No network operations
- ✅ No disk writes
- ⚠️ Plaintext passwords displayed in beacon output

### What's Logged

- **Windows Event Log:** Credential Manager access may be logged in Security log (Event ID 5379-5381) depending on audit policy
- **DPAPI Usage:** CryptUnprotectData calls may be monitored by EDR
- **EDR/AV:** Credential access patterns may trigger behavioral detection
- **Network Traffic:** Beacon communication contains plaintext passwords (ensure encrypted channel)

### Comparison to Other Methods

| Method | Admin Required | Detection Risk | Decryption | Reliability |
|--------|----------------|----------------|------------|-------------|
| This BOF (CryptUnprotectData) | No | Medium | Current User | High |
| Privilege Escalation + CredBackup | Yes | High | Any User | Medium |
| File Parsing (direct DPAPI) | No | Low | None | Low |
| Mimikatz | Yes | Very High | Any User | High |
| SharpDPAPI | No (for current user) | Medium-High | Current User+ | High |

## Limitations

- **Current User Only:** Cannot decrypt other users' credentials without their master keys
- **Context Dependent:** Must be in the same user session context as when credential was created
- **DPAPI Protected:** If DPAPI master keys are unavailable, decryption will fail
- **Plaintext Output:** Passwords displayed in plaintext in beacon output (OPSEC consideration)

## Security Considerations

**For Red Teams:**
- Ensure secure communication channel (passwords in beacon output)
- Consider logging/archival implications (plaintext passwords)
- Test in lab environment first
- Understand detection signatures for credential access

**For Blue Teams:**
- Monitor Event IDs 5379-5381 (Credential Manager access)
- Monitor CryptUnprotectData API calls from unusual processes
- Implement Credential Guard where possible
- Audit stored credentials regularly

## Next Steps

After decrypting credentials, you can:

1. **Use credentials** for lateral movement (RDP, network shares, etc.)
2. **Extract domain credentials** for pass-the-hash or authentication
3. **Identify high-value targets** (admin accounts, service accounts)
4. **Cross-reference** with other reconnaissance data

## Files

- `entry.c` - BOF source code with decryption logic
- `beacon.h` - Beacon and Windows API declarations (including Crypt32)
- `Makefile` - Build configuration
- `decrypt_credmanager_bof.s1.py` - OC2 Python interface
- `create-test-credentials.ps1` - PowerShell script to create test data
- `README.md` - This file

## Comparison with enum-credmanager

| Feature | enum-credmanager | decrypt-credmanager |
|---------|------------------------|---------------------------|
| Lists credentials | ✅ | ✅ |
| Shows metadata | ✅ | ✅ |
| Decrypts passwords | ❌ | ✅ |
| Admin required | ❌ | ❌ |
| Detection risk | Low | Medium |
| Use case | Reconnaissance | Credential extraction |

## Credits

- **Approach:** Standard Windows API usage (CredEnumerateW + CryptUnprotectData)
- **DPAPI:** Windows Data Protection API
- **Implementation:** decrypt-credmanager BOF

## References

- [Microsoft Docs - CredEnumerateW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew)
- [Microsoft Docs - CryptUnprotectData](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [Microsoft Docs - Credential Manager](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)
- [Windows DPAPI Overview](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) - Reference for DPAPI internals

---

**Status:** ✅ Complete - Ready for testing
**Complexity:** Low-Medium
**Value:** High (credential extraction)
**OPSEC:** Medium risk (credential access may be logged)
