# listpipes

Minimal Cobalt Strike BOF to list local named pipes via `NtQueryDirectoryFile`.  

Everything in this project was written by ChatGPT.

## Usage
- Load the CNA into Cobalt Strike
- Run the listpipes command

```bash
listpipes
```

Example output:
```bash
[08/06 14:55:04] beacon> listpipes
[08/06 14:55:04] [*] List Named Pipes (BOF)
[08/06 14:55:04] [+] host called home, sent: 3133 bytes
[08/06 14:55:04] [+] received output:
\\.\pipe\InitShutdown
\\.\pipe\lsass
```

## Build

Requirements:
- mingw-w64 toolchains (`x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`)
- `beacon.h` (set its path with `BEACON_INCLUDE`)

```bash
make
```

## Testing

### Architecture Compatibility Testing

This BOF builds for both x86 and x64 architectures. To ensure compatibility across both architectures:

**Build and verify both architectures:**
```bash
# Build both x86 and x64 object files
make all

# Verify the object files are valid COFF format
make check
```

**Test as standalone executables (optional):**
```bash
# Build test executables for both architectures
make test

# On a Windows system, test both:
# listpipes.x64.exe
# listpipes.x86.exe
```

**Key areas to test:**
- Buffer growth logic handles varying numbers of pipes correctly on both architectures
- Pointer arithmetic and SIZE_T calculations work correctly on 32-bit and 64-bit systems
- Memory allocations succeed and are properly freed on both architectures
