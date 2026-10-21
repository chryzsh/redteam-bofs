# fake-windows-popup-async BOF-PE

Shows a native Windows credential prompt over a dimmed desktop. Runs as an async BOF job, so the beacon stays responsive while the prompt is open.

It uses the async BOF API from Outflank's [Async BOFs](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/) post: `BeaconWakeup` and `BeaconGetStopJobEvent`. The C2 must support both async BOFs and BOF-PE.

## Status

Tested on Windows 11 build 26100 (scan-ws03) as a standalone EXE. Capture, stop, and timeout paths all pass. The DLL build has not been run on Windows or under OC2 yet.

## Features

- Runs as an async BOF job. The beacon stays responsive while the prompt is open.
- The C2 can stop the job to dismiss the prompt. The BOF prints `[*] Credential prompt stopped by operator`.
- Timeout 0 means no timeout (wait until capture, cancel, or stop). No upper cap. Minimum 10 s. Default 60 s.
- `CoInitializeEx(COINIT_APARTMENTTHREADED)` around the prompt (a C2-created thread has not joined an apartment).
- `BeaconWakeup` after a capture and when `go` returns.
- Built with exceptions. `go` catches `std::exception`.
- On Windows 11 build 26100+, the credential dialog belongs to `CredentialUIBroker.exe`. The monitor thread terminates the broker to dismiss the dialog on stop or timeout.

## Arguments

Packed format: `ZZiiiii`:

```text
caption message timeout-seconds max-attempts validate persistent force
```

The password is always printed. `go` parses the packed buffer itself (`src/args.cpp`) and accepts both packings. OC2 uses the Cobalt Strike layout: a little-endian total length, then little-endian sizes and ints. BOF-PE's `loader.exe` packs big-endian with no total length. The raw string forms for `inline-execute-pe` are also unchanged. In OC2, load `fake_windows_popup_async_bof.s1.py`. It uses `BOFType.ASYNC`, so OC2 sends the BOF as an async job:

```text
fake-windows-popup-async --timeout 0 --attempts 1
```

Stop the job with the OC2 job controls.

## Persistence modes

`--persistent` reopens the prompt after Cancel or an empty password submission. A wrong password with `--validate` still counts against `--attempts` and stops when the limit is reached. This covers the common case where the prompt should survive an accidental Cancel but a genuine wrong password is accepted and reported.

`--persistent --validate --force` reopens the prompt after Cancel, empty password, and failed validation. The prompt never goes away until the user enters a valid password, the operator stops the job, or the timeout expires. `--attempts` is ignored in this mode. Use this when you need a confirmed valid credential and want the prompt to stay up until the user gets it right.

## Beacon API header

`beacon/` holds a local copy of the BOF-PE beacon layer (`beacon.h` and the standalone `beacon.dll` source) from the `async` branch of [chryzsh/BOF-PE](https://github.com/chryzsh/BOF-PE/tree/async). It adds `BeaconWakeup`, `BeaconGetStopJobEvent`, and the `BOF_PE_DLL` mode. The shared `external/BOF-PE/beacon` has none of these, so this sample does not use it. The build still takes `common/standalone.cpp` from `external/BOF-PE` for the standalone `beacon.dll`.

## Build

```sh
make -C src/fake-windows-popup-async all
make -C src/fake-windows-popup-async test
make -C src/fake-windows-popup-async inspect
```

The BOF-PE is a DLL that exports `go`, because OC2 runs a BOF-PE as a DLL. It is built with `BOF_PE_DLL`, so `BEACON_MAIN` defines no `main` and the MinGW CRT DLL startup initializes the CRT. The DLL is written to `src/fake-windows-popup-async/build-mingw/fake-windows-popup-async.dll`, with the standalone `beacon.dll` beside it. For a standalone test, run it with BOF-PE's `loader.exe`: `loader.exe fake-windows-popup-async.dll ZZiiiii <caption> <message> <timeout> <attempts> <validate> <persistent> <force>`. `make all` also copies the DLL to `src/fake-windows-popup-async/fake-windows-popup-async.x64.o`, the name OC2 looks up beside the `.s1.py` script.

## Operational constraints

Requires a C2 that supports async BOFs and BOF-PE. The BOF must run in an interactive session where the user can see the prompt.
