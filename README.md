# Redteam BOFs

A collection of Beacon Object Files (BOFs) for post-exploitation operations. Includes credential hunting, system enumeration, event log analysis, and privilege management tools.

## Available BOFs

| BOF | Description | Usage |
|-----|-------------|-------|
| **adduser-domaingroup** | Adds a user to a domain global/universal group via `NetGroupAddUser` (target a DC) | [Usage](docs/USAGE.md#adduser-domaingroup) |
| **adduser-localgroup** | Adds a user to a local group on a Windows computer | [Usage](docs/USAGE.md#adduser-localgroup) |
| **bkread** | Reads a file with `SeBackupPrivilege` and backup semantics, without changing ACLs | [Usage](docs/USAGE.md#bkread) |
| **checkaccess** | Probes read access for a directory path and subfolders (depth-1 or recursive) | [Usage](docs/USAGE.md#checkaccess) |
| **credguard-check** | Checks Credential Guard, HVCI, LSA Protection, VBS status | [Usage](docs/USAGE.md#credguard-check) |
| **curl** | HTTP/HTTPS requests with TLS fingerprinting | [Usage](docs/USAGE.md#curl) |
| **decrypt-credmanager** | Decrypts Windows Credential Manager entries using DPAPI | [Usage](docs/USAGE.md#decrypt-credmanager) |
| **dpapi-unprotect** | Decrypts an arbitrary DPAPI blob (with optional entropy) in the current user's context | [Usage](docs/USAGE.md#dpapi-unprotect) |
| **dsreg-status** | Reports documented `dsregcmd /status` device, tenant, user, and proxy state | [Usage](docs/USAGE.md#dsreg-status) |
| **edge-passdump** | Dumps plaintext passwords saved in Microsoft Edge from process memory | [Usage](docs/USAGE.md#edge-passdump) |
| **enum-credmanager** | Lists Windows Credential Manager entries (no decryption) | [Usage](docs/USAGE.md#enum-credmanager) |
| **enum-creds** | Credential-focused file enumeration with optional app-data discovery and inline content dump | [Usage](docs/USAGE.md#enum-creds) |
| **enum-logon-events** | Queries Security Event Log for logon events (4624) | [Usage](docs/USAGE.md#enum-logon-events) |
| **enum-registry** | Extracts RDP history, installed software, env vars, WSL/Docker info across all loaded user hives | [Usage](docs/USAGE.md#enum-registry) |
| **enum-stored-accounts** | Lists service accounts, tasks with stored passwords, and per-profile DPAPI material (which tokens are worth stealing) | [Usage](docs/USAGE.md#enum-stored-accounts) |
| **enum-user-right** | Lists accounts assigned an effective LSA user right; defaults to `SeMachineAccountPrivilege` | [Usage](docs/USAGE.md#enum-user-right) |
| **fake-windows-popup** (BOF-PE, x64) | Shows native Windows credential UI with optional validation and password output | [Usage](docs/USAGE.md#fake-windows-popup) |
| **enumshares** | Enumerate remote shares and test filesystem access (single host) | [Usage](docs/USAGE.md#enumshares) |
| **enumshares-file** | Enumerate remote shares from an uploaded hostnames file | [Usage](docs/USAGE.md#enumshares-file) |
| **listpipes** | Lists named pipes for IPC reconnaissance | [Usage](docs/USAGE.md#listpipes) |
| **lsfiles** | Recursive file/directory listing with wildcards, date/size filters | [Usage](docs/USAGE.md#lsfiles) |
| **nslookup-file** | Resolves a file of hostnames with parallel DNS queries | [Usage](docs/USAGE.md#nslookup-file) |
| **removeuser-domaingroup** | Removes a user from a domain global/universal group via `NetGroupDelUser` (target a DC) | [Usage](docs/USAGE.md#removeuser-domaingroup) |
| **removeuser-localgroup** | Removes a user from a local group on a Windows computer (or a domain-local group when targeted at a DC) | [Usage](docs/USAGE.md#removeuser-localgroup) |
| **sccm-wmi** | Recovers SCCM Network Access Account credentials from live WMI policy as `SYSTEM` (CRED-3) | [Usage](docs/USAGE.md#sccm-wmi) |
| **sccm-disk** | Recovers SCCM Network Access Account credentials from on-disk `OBJECTS.DATA` as `SYSTEM` (CRED-4) | [Usage](docs/USAGE.md#sccm-disk) |
| **sccm-local-recon** | Local SCCM client recon: paths, cache permissions, ManagementPoints, log UNC/URL scraping (RECON-7) | [Usage](docs/USAGE.md#sccm-local-recon) |
| **tcpscan** | TCP connect scan of a single host | [Usage](docs/USAGE.md#tcpscan) |
| **tcpscan-file** | TCP connect scan of hosts from an uploaded file (accepts `nslookup-file` output) | [Usage](docs/USAGE.md#tcpscan-file) |

See [docs/USAGE.md](docs/USAGE.md) for detailed command syntax and examples.

---

## External BOF Scripts (OC2)

The `oc2-python-scripts-bof/` directory contains OC2 integration scripts for **external BOFs**. Source repos are tracked as git submodules under `external/`. Run `./oc2-python-scripts-bof/sync-bofs.sh` to pull, build, and sync the compiled BOF binaries.

### Sync External BOFs

```bash
# Pull, build, and sync all external BOFs
./oc2-python-scripts-bof/sync-bofs.sh

# Skip pulling submodules
./oc2-python-scripts-bof/sync-bofs.sh --no-pull

# Skip builds and only copy existing object files
./oc2-python-scripts-bof/sync-bofs.sh --no-build

# Sync selected projects only
./oc2-python-scripts-bof/sync-bofs.sh PrivKit SQL-BOF
```

| Project | Commands | Deploy | Source |
|---------|----------|--------|--------|
| **cookie-monster** | `cookie-monster` | with redteam-bofs | [KingOfTheNOPs/cookie-monster](https://github.com/KingOfTheNOPs/cookie-monster) |
| **Kerbeus-BOF** | `krb_asktgt`, `krb_asktgs`, `krb_s4u`, `krb_ptt`, `krb_klist`, `krb_dump`, etc. | standalone | [RalfHacker/Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) |
| **LNKgenerator-BOF** | `LNKgenerator` | with redteam-bofs | [KingOfTheNOPs/LNKgenerator-BOF](https://github.com/KingOfTheNOPs/LNKgenerator-BOF) |
| **SQL-BOF** | `sql-whoami`, `sql-query`, `sql-xpcmd`, `sql-links`, etc. | standalone | [Tw1sm/SQL-BOF](https://github.com/Tw1sm/SQL-BOF) |
| **OperatorsKit** | `addtaskscheduler`, `credprompt` | with redteam-bofs | [REDMED-X/OperatorsKit](https://github.com/REDMED-X/OperatorsKit) |
| **PrivKit** | `privcheck`, `privkit-alwaysinstallelevated`, `privkit-autologon`, `privkit-credmanager`, `privkit-hijackablepath`, `privkit-modifiableautorun`, `privkit-modifiablesvc`, `privkit-tokenprivileges`, `privkit-unquotedsvcpath`, `privkit-pshistory`, `privkit-uacstatus` | with redteam-bofs | [mertdas/PrivKit](https://github.com/mertdas/PrivKit) |

Kerbeus-BOF and SQL-BOF ship their own `*_bof.s1.py` with hardcoded `/shared/bofs/<project>/...` paths, so they are deployed standalone at the top of the teamserver's BOF dir rather than nested under `custom/redteam-bofs/`.

See [docs/USAGE.md#external-bof-scripts](docs/USAGE.md#external-bof-scripts) for usage details.

---

## Getting Started

### Prerequisites

Install the mingw-w64 cross-compiler:

```bash
# Debian/Ubuntu
sudo apt install mingw-w64

# macOS
brew install mingw-w64
```

### Building

```bash
# Build all BOFs
make

# Build specific BOF
make enum-creds

# Build the x64 BOF-PE
make fake-windows-popup

# List available BOFs
make list
```

Output files are placed in each BOF's directory:
- `*.x64.o` - 64-bit object file
- `*.x86.o` - 32-bit object file
- `build-mingw/*.exe` - x64 BOF-PE executable

### C2 Integration

Each BOF includes integration scripts:
- `*.s1.py` - OC2/Sliver Python scripts
- `*.cna` - Cobalt Strike Aggressor scripts (where available)

---

## Development

### Build Commands

```bash
make              # Build all production BOFs (14)
make test         # Build test executables
make clean        # Remove artifacts
make help         # Show all options
```

### Adding a New BOF

1. Create `src/<bof-name>/` with `entry.c`, `beacon.h`, and `Makefile`. BOF-PE projects use CMake and a local Makefile wrapper.
2. Add OC2 script: `<bof-name>_bof.s1.py`
3. Add to `Makefile` and `build-all.sh` BOFS arrays
4. Update this README and USAGE.md

---

## Documentation

| Document | Description |
|----------|-------------|
| [USAGE.md](docs/USAGE.md) | Command syntax and examples |
| [BUILD.md](docs/BUILD.md) | Build instructions |

---

## License

Individual BOFs may have different licenses. See each BOF's directory.

## Disclaimer

For authorized security testing and research only. Users are responsible for legal compliance.
