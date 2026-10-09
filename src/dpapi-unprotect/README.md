# dpapi-unprotect

Minimal BOF that calls `CryptUnprotectData()` on a raw DPAPI blob with an
optional entropy buffer and prints the plaintext as hex, ASCII, and UTF-16LE.

Useful when you've recovered an opaque DPAPI blob from disk, memory, or a
process dump and you need to decrypt it from a user-context implant without
extracting master keys yourself. Windows resolves the master key transparently
for the calling user.

## How it works

1. The wrapper takes the blob (and optional entropy) as hex strings, decodes
   them to bytes, and packs both as `BOFArgumentEncoding.BUFFER`.
2. The BOF calls `CryptUnprotectData(pDataIn, NULL, pOptionalEntropy, NULL,
   NULL, 0, pDataOut)` and frees the output buffer with `HeapFree` after
   printing.
3. Output is shown as hex (always), ASCII (always), and UTF-16LE (when the
   plaintext length is even) so you can identify the encoding by inspection.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `blob` | yes | DPAPI blob as a hex string. Must start with the version DWORD `01000000` followed by the provider GUID `d08c9ddf-0115-d111-8c7a-00c04fc297eb`. |
| `--entropy`, `-e` | no | Optional entropy as a hex string. Pass this if the application protected the blob with a custom entropy parameter. |

## Examples

```bash
# Standard DPAPI blob (no entropy)
dpapi-unprotect 01000000d08c9ddf0115d1118c7a00c04fc297eb...

# Blob protected with an application-specific entropy
dpapi-unprotect 01000000d08c9ddf... -e 5f7531c034393c60adb7440063f2ee46
```

If your stored blob has a custom prefix that isn't part of the standard DPAPI
structure (e.g. an application prepends entropy bytes to its blob on disk),
strip those bytes from `blob` and pass them via `--entropy`.

## Context requirements

- Must run as the user who originally protected the blob. DPAPI is per-user.
- From SYSTEM, impersonate that user's token first (e.g. via `make-token` or
  by stealing a token from one of their processes).
- A common failure code is `0x8007000d` (`ERROR_INVALID_DATA`) — usually means
  wrong/missing entropy or the blob bytes are corrupted. `0x80090005`
  (`NTE_BAD_DATA`) usually means the calling user can't reach the master key
  (wrong user / wrong session).

## Build

```bash
make            # produces dpapi-unprotect.x64.o and dpapi-unprotect.x86.o
make lint       # validate with boflint --loader oc2
make clean
```

## Files

| File | Purpose |
|------|---------|
| `entry.c` | BOF source — single `go()` calling `CryptUnprotectData` |
| `beacon.h` | Minimal Beacon API + Win32 declarations |
| `Makefile` | Build / lint / clean targets |
| `dpapi_unprotect_bof.s1.py` | OC2 wrapper (`dpapi-unprotect` command) |

## OPSEC

- `CryptUnprotectData` is a documented Windows API; usage on its own is not
  unusual. EDRs that monitor DPAPI behaviour may still flag it.
- Plaintext is returned in beacon output — ensure the channel is encrypted.
- No disk writes, no network traffic, no privilege requirements beyond the
  user's own session.
