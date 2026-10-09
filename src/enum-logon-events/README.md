# Enum Logon Events BOF

A Beacon Object File (BOF) for enumerating Windows Security Event Log Event ID 4624 (successful logon events) to identify lateral movement patterns, authentication methods, and potential attack paths.

## Overview

This BOF queries the Windows Security event log for successful logon events (Event ID 4624) and extracts key information useful for red team operations:
- Who logged into the system (username)
- When they logged in (timestamp)
- How they logged in (logon type: Interactive, Network, RDP)
- Where they logged in from (source IP address)
- Authentication method used (NTLM v1, NTLM v2, Kerberos)

Based on [Seatbelt's LogonEventsCommand](https://github.com/GhostPack/Seatbelt) but adapted for BOF constraints.

## Features

- ✅ **Configurable Time Range:** Query last 1-30 days (default: 7 days)
- ✅ **Event Limit Cap:** Prevent beacon blocking (default: 500 events max)
- ✅ **Smart Filtering:** Automatically filters noise (SYSTEM, computer accounts)
- ✅ **Lateral Movement Intel:** Identifies network logons with source IPs
- ✅ **Weak Auth Detection:** Highlights NTLM v1 usage (exploitable)
- ✅ **Statistics Summary:** Counts logon types and auth methods
- ✅ **Low OPSEC Footprint:** Read-only event log access

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
# Default: Last 7 days, max 500 events
enum-logon-events

# Last 24 hours
enum-logon-events --days 1

# Last 30 days, up to 1000 events
enum-logon-events --days 30 --max-events 1000

# Last 3 days, max 200 events (faster execution)
enum-logon-events -d 3 -m 200
```

### Cobalt Strike (Aggressor Script)

If using with Cobalt Strike, create an Aggressor script to load the BOF.

## Example Output

```
[*] Querying Security event log for Event ID 4624...
[*] Time range: Last 7 day(s)
[*] Max events: 500
[!] Requires administrator privileges

[+] Query successful, enumerating events...
================================================================================

[Network] 2025-11-15 14:23:15
  User:    CORP\admin
  From:    192.168.1.50
  Auth:    NTLM (NTLM V2)

[RemoteInteractive] 2025-11-15 13:45:22
  User:    CORP\bob
  From:    10.0.0.25
  Auth:    Kerberos

[Interactive] 2025-11-15 09:12:03
  User:    WORKSTATION\localuser
  Auth:    Negotiate

[Network] 2025-11-14 18:30:45
  User:    DOMAIN\serviceaccount
  From:    192.168.1.100
  Auth:    NTLM (NTLM V1)

================================================================================
[+] Summary:
  Total events displayed:  347
  Filtered (noise):        89
  Network logons:          128
  Interactive logons:      156
  RemoteInteractive:       63

[+] Authentication Methods (Network logons only):
  NTLM v1:  2 (WEAK! Can be cracked!)
  NTLM v2:  85
  Kerberos: 206
```

## Event Information

### Logon Types

| Type | Name | Description | Operational Value |
|------|------|-------------|-------------------|
| 2 | Interactive | Console/keyboard logon | Local access |
| 3 | Network | SMB, network share | **Lateral movement** |
| 4 | Batch | Scheduled task | Persistence check |
| 5 | Service | Windows service | Service enumeration |
| 7 | Unlock | Workstation unlock | User activity |
| 8 | NetworkCleartext | IIS basic auth | Cleartext passwords! |
| 9 | NewCredentials | RunAs | Credential usage |
| 10 | RemoteInteractive | RDP, Terminal Services | **Remote access** |
| 11 | CachedInteractive | Cached credentials | Offline auth |

### Authentication Packages

| Package | Description | Security Notes |
|---------|-------------|----------------|
| **NTLM (v1)** | NT LAN Manager v1 | ⚠️ **WEAK!** Can be cracked 100% |
| **NTLM (v2)** | NT LAN Manager v2 | NetNTLMv2 - can be relayed/cracked |
| **Kerberos** | Kerberos authentication | Stronger, but still attack vectors |
| **Negotiate** | SPNEGO (tries Kerberos, falls back to NTLM) | Most common |

### Filtered Accounts (Not Displayed)

The BOF automatically filters out noise to focus on actionable intelligence:
- `SYSTEM`
- `LOCAL SERVICE`
- `NETWORK SERVICE`
- `ANONYMOUS LOGON`
- Computer accounts (ending with `$`)
- `UMFD-X` accounts (User Mode Font Driver)
- `DWM-X` accounts (Desktop Window Manager)
- `NT VIRTUAL MACHINE` domain

## Operational Use Cases

### 1. Lateral Movement Planning

Identify accounts that have network logons:
```
[Network] CORP\admin from 192.168.1.50
```
→ **`admin` account accessed this host from 192.168.1.50** (potential pivot target)

### 2. Credential Harvesting Targets

Find interactive/RDP logons:
```
[RemoteInteractive] CORP\domainadmin from 10.0.0.10
```
→ **Domain admin RDP'd in** (high-value credential target)

### 3. Weak Authentication Detection

Identify NTLM v1 usage:
```
[+] Authentication Methods:
  NTLM v1:  5 (WEAK! Can be cracked!)
```
→ **NTLM v1 in use** (can capture and crack for plaintext passwords)

### 4. Attack Path Mapping

Correlate with other reconnaissance:
1. Run `enum-logon-events` → Find `CORP\admin` logged in from `192.168.1.50`
2. Run `decrypt-credmanager` → Find saved RDP credentials for `192.168.1.50`
3. Use credentials to pivot to `192.168.1.50`

### 5. Privilege Escalation Context

See who has accessed the system:
```
[Interactive] WORKSTATION\Administrator
```
→ **Local admin recently logged in** (potential token theft target)

## Technical Details

### APIs Used

- `EvtQuery()` - Open event log query with XPath filter
- `EvtNext()` - Iterate through events
- `EvtRender()` - Extract event data as structured properties
- `EvtClose()` - Cleanup event handles

### Libraries Required

- `wevtapi.lib` - Windows Event Log API

### Event ID 4624 Property Indices

The BOF extracts properties by index from the event data:

| Index | Property | Description |
|-------|----------|-------------|
| 0 | TimeCreated | Event timestamp |
| 1 | SubjectUserName | User who initiated the logon |
| 2 | SubjectDomainName | Domain of initiating user |
| 5 | **TargetUserName** | **User who logged in** |
| 6 | **TargetDomainName** | **Domain of logged in user** |
| 8 | **LogonType** | **Type of logon (2, 3, 10, etc.)** |
| 10 | **AuthenticationPackageName** | **Auth method (NTLM, Kerberos)** |
| 14 | **LmPackageName** | **NTLM version (v1, v2)** |
| 18 | **IpAddress** | **Source IP address** |

### XPath Query Format

```xml
*[System/EventID=4624] and *[System[TimeCreated[@SystemTime >= '2025-11-08T00:00:00.000Z']]]
```

The BOF dynamically builds this query based on the `--days` parameter.

## OPSEC Considerations

### Detection Risk: Low-Medium

**Low Risk Factors:**
- ✅ Read-only operation (no modifications)
- ✅ Standard Windows API (wevtapi.dll)
- ✅ Same access as Event Viewer, Seatbelt, or `Get-WinEvent`
- ✅ No disk writes or network operations

**Medium Risk Factors:**
- ⚠️ Requires administrator privileges (context already suspicious)
- ⚠️ Security log access may be audited (Event ID 4663 if object access auditing enabled)
- ⚠️ Could be slow on busy systems (beacon blocking 5-10 seconds)
- ⚠️ EDR may monitor wevtapi.dll usage from non-standard processes

### What's Logged

- **Event ID 4663** (Object Access): May log Security log access if object access auditing is enabled
- **No event generated** on most default Windows configurations
- **Same footprint as:** Seatbelt, Event Viewer, PowerShell Get-WinEvent

### Beacon Safety

**Crash Risks:** Low
- All buffer allocations checked
- Timeout on event enumeration (5 seconds)
- Max event cap prevents infinite loops
- Proper error handling on all APIs

**Execution Time:**
- 100 events: ~1-2 seconds
- 500 events: ~3-5 seconds
- 1000 events: ~5-10 seconds (shows warning)

## Requirements

### System Requirements

- **Windows Version:** Windows Vista+ (Event Log API introduced in Vista)
- **Privileges:** Administrator (Security log access)
- **Audit Policy:** "Audit Logon Events" must be enabled (default on most systems)

### Limitations

1. **Requires Admin:** Security event log access is privileged
2. **Depends on Auditing:** Event ID 4624 must be enabled in audit policy
3. **Log Rotation:** Busy systems may have rotated out old events
4. **Performance:** Can be slow on domain controllers (millions of events)
5. **Local Only:** Does not query remote event logs (Phase 1 limitation)

## Comparison with Seatbelt

| Feature | Seatbelt LogonEvents | This BOF |
|---------|----------------------|----------|
| **Language** | C# (.NET) | C (Native) |
| **Execution** | Execute-assembly | In-process BOF |
| **Privileges** | Admin required | Admin required |
| **Data Extracted** | Full event details | Core fields only |
| **Filtering** | Regex support | Hardcoded filters |
| **Statistics** | Deduplication, counts | Basic counts |
| **Performance** | Fast (CLR) | Fast (native) |
| **OPSEC** | CLR injection | Lower footprint |

**Advantages of BOF:**
- Smaller memory footprint
- No CLR/.NET required
- Faster for small event counts
- Lower detection risk (native code)

**Advantages of Seatbelt:**
- More features (regex, deduplication)
- Better statistics
- Multiple event IDs
- Easier to modify (C#)

## Testing

### Test Environment Setup

Run the PowerShell test script to view existing events:

```powershell
.\test-logon-events.ps1
```

This will:
1. Show recent logon events from Security log
2. Display logon statistics
3. Help verify BOF output matches PowerShell results

### Validation

Compare BOF output with PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data | Where-Object {$_.Name -match 'Target|Logon|Ip|Auth'}
  }
```

## Troubleshooting

### "Access denied" Error

**Cause:** Not running as administrator

**Solution:** Run beacon in high integrity context or as SYSTEM

### "Security event log not found"

**Cause:** Security log disabled or missing (rare)

**Solution:** Verify event log service is running: `Get-Service -Name EventLog`

### "No events found"

**Possible causes:**
- No logons in the specified time range
- Audit policy disabled
- Event log rotated (old events deleted)

**Solution:**
- Increase days: `enum-logon-events --days 30`
- Check audit policy: `auditpol /get /category:"Logon/Logoff"`

### Slow Execution

**Cause:** Large number of events (thousands)

**Solution:**
- Reduce days: `enum-logon-events --days 1`
- Reduce max events: `enum-logon-events --max-events 100`

## Future Enhancements (Phase 2)

Potential features for future versions:

- [ ] User regex filtering (like Seatbelt)
- [ ] Event ID 4625 (failed logons)
- [ ] Event ID 4648 (explicit credential use / RunAs)
- [ ] Deduplication (unique users only)
- [ ] JSON/CSV output format
- [ ] Remote event log querying
- [ ] IP address geolocation hints
- [ ] Correlation with other BOFs

## Files

- `entry.c` - BOF source code (550 lines)
- `beacon.h` - Beacon and Windows Event Log API declarations
- `Makefile` - Build configuration
- `enum_logon_events_bof.s1.py` - OC2 Python interface
- `test-logon-events.ps1` - PowerShell test script
- `README.md` - This file

## Credits

- **Inspiration:** [Seatbelt by GhostPack](https://github.com/GhostPack/Seatbelt)
- **Event Log Research:** Microsoft Security Event Log documentation
- **Implementation:** enum-logon-events BOF

## References

- [Event ID 4624 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Windows Event Log API](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [EvtQuery Function](https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [Seatbelt - LogonEventsCommand](https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/EventLogs/LogonEventsCommand.cs)

---

**Status:** ✅ Complete - Ready for operational use
**Complexity:** Medium-High
**Value:** High (lateral movement reconnaissance)
**OPSEC:** Low-Medium risk
