# dsreg-status

`dsreg-status` is a BOF that reports the high-value portions of `dsregcmd /status`
from documented Windows APIs. It is intended for user-context execution on
Microsoft Entra joined, hybrid joined, and workplace-joined devices.

## Implemented in Phase 1

- Device join state
- Device ID and join certificate thumbprint/validity
- Tenant and join-user metadata
- User key metadata from `DSREG_USER_INFO`
- Work account and MDM URLs
- IE proxy configuration for the current user
- WinHTTP default proxy configuration

## Explicitly Deferred

- `SSO State`
- `Diagnostic Data`
- `Ngc Prerequisite Check`
- `DeviceAuthStatus`
- Key provider/container and TPM-backed key reporting

These fields appear to require undocumented `dsreg.dll` behavior or additional
platform-specific logic. The BOF prints `UNAVAILABLE (phase 2)` for them.

## Usage

```text
dsreg-status
```

## Output Notes

- The BOF does not shell out to `dsregcmd.exe`.
- Empty strings are printed when the API returns no value for the current host.
- Join/proxy collection failures are printed inline as `ERROR (0x...)`.
