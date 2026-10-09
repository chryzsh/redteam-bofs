# fake-windows-popup BOF-PE

Native BOF-PE port of FakeWindowsPopup. It displays the operating system's
Windows credential UI over a dimmed interactive desktop.

This is a BOF-PE, not a traditional COFF BOF. It requires a compatible
BOF-PE loader and currently targets x64 Windows.

## Behavior

- Detects domain membership and selects a domain controller or local hostname.
- Uses `CredUIPromptForWindowsCredentialsW` for the credential dialog.
- Defaults to capture-only mode, avoiding authentication traffic and lockout risk.
- Optionally validates through `LogonUserW` with at most three attempts.
- Suppresses password output unless explicitly enabled.
- Optionally reopens ordinary Cancel/close and empty-password submissions until
  the timeout; the emergency hotkey remains available.
- Closes the overlay on completion and supports `Ctrl+Alt+0` cancellation.

## Arguments

Packed format: `ZZiiiii`

```text
caption message timeout-seconds max-attempts validate include-password persistent
```

Empty caption and message values generate Windows Security defaults. `validate`,
`include-password`, and `persistent` use `0` or `1`. When persistent mode is
enabled, ordinary Cancel/close and empty-password submissions reopen the prompt;
the timeout and `Ctrl+Alt+0` still cancel it.

Cobalt Strike's built-in `inline-execute-pe` passes a raw command string rather
than Beacon-packed fields. The same PE accepts a four- or five-number shorthand:

```text
inline-execute-pe /path/fake-windows-popup.exe 60 1 0 0 1
```

It also accepts the full raw form with quoted caption and message followed by
the same numeric fields. The trailing persistent value is optional in both raw
forms and defaults to `0`.

## Build

```sh
make -C src/fake-windows-popup all
make -C src/fake-windows-popup test
make -C src/fake-windows-popup inspect
```

The executable is written to
`src/fake-windows-popup/build-mingw/fake-windows-popup.exe`. The build copies the
standalone `beacon.dll` compatibility library beside the executable.

## Operational constraints

- The prompt appears only on the process's current interactive desktop.
- Startup output reports the process session and physical console session for
  diagnosis. They can legitimately differ for an interactive RDP session.
- If Windows denies foreground activation to a background Beacon, the dimmer is
  removed from the topmost band so it cannot cover the brokered credential UI.
- The dimmer imitates secure-desktop dimming but is not the secure desktop.
- The invocation remains active until the dialog exits. A timeout requests that
  the project-owned dialog close; Windows may delay that request.
- Use password output only when the engagement explicitly authorizes collection.
