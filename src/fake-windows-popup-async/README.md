# fake-windows-popup-async BOF-PE

Async copy of [fake-windows-popup](../fake-windows-popup/README.md). It shows the Windows credential prompt over a dimmed desktop, like the original, but runs as an async BOF job. The original runs synchronously and blocks the beacon until the prompt closes, for up to 300 seconds. This copy runs on its own thread, so the beacon stays responsive while the prompt is open.

It uses the async BOF API from Outflank's [Async BOFs](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/) post: `BeaconWakeup` and `BeaconGetStopJobEvent`. The C2 must support both async BOFs and BOF-PE.

## Status

Experimental. Not ready for operational use.

- The capture path was tested in an interactive session on Windows 11 build 26100.
- Known issue: on that build, the timeout and the stop job event do not close the credential dialog. The dialog runs in a separate process (`CredentialUIBroker.exe`), so closing the windows this BOF owns does not close it.

## Differences from the original

| Area | Original | Async copy |
|------|----------|------------|
| Execution | Blocks the beacon thread | Runs as an async job; needs `BeaconGetStopJobEvent` from the C2, and prints an error and returns without it |
| Stopping | Timeout, `Ctrl+Alt+0`, or the user | Also stopping the job in the C2. The BOF prints `[*] Credential prompt stopped by operator`. See the known issue under Status. |
| Timeout | 0 means 60 s, capped at 300 s | 0 means no timeout. There is no upper cap. The minimum is still 10 s. With no arguments at all, the default is still 60 s. |
| COM | Uses whatever apartment the calling thread has | Calls `CoInitializeEx(COINIT_APARTMENTTHREADED)` around the prompt, because a C2-created thread has not joined an apartment. It calls `CoUninitialize` only when `CoInitializeEx` returned `S_OK` or `S_FALSE`. |
| Wakeup | None | `BeaconWakeup` right after a capture, and again when `go` returns |
| Exceptions | Built with `-fno-exceptions` | Built with exceptions. `go` catches `std::exception`. |

## Arguments

Packed format: `ZZiiiii`, the same as the original:

```text
caption message timeout-seconds max-attempts validate include-password persistent
```

The raw string forms for `inline-execute-pe` are also unchanged. In OC2, load `fake_windows_popup_async_bof.s1.py`. It uses `BOFType.ASYNC`, so OC2 sends the BOF as an async job:

```text
fake-windows-popup-async --timeout 0 --attempts 1
```

Stop the job with the OC2 job controls.

## Beacon API header

`beacon/` holds a local copy of the BOF-PE beacon layer (`beacon.h` and the standalone `beacon.dll` source). It adds `BeaconWakeup`, `BeaconGetStopJobEvent`, and a `BEACON_INIT` change that keeps static destructors out of the host process exit table. The shared `external/BOF-PE/beacon` has none of these, so this sample does not use it. The build still takes `common/standalone.cpp` and `link.ld` from `external/BOF-PE`.

## Build

```sh
make -C src/fake-windows-popup-async all
make -C src/fake-windows-popup-async test
make -C src/fake-windows-popup-async inspect
```

The executable is written to `src/fake-windows-popup-async/build-mingw/fake-windows-popup-async.exe`, with the standalone `beacon.dll` beside it. `make all` also copies the PE to `src/fake-windows-popup-async/fake-windows-popup-async.x64.o`, the name OC2 looks up beside the `.s1.py` script.

## Operational constraints

The constraints of the original apply. See [fake-windows-popup](../fake-windows-popup/README.md#operational-constraints).
