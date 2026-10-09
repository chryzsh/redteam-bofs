# Build System

## Quick Start

```bash
# Build all BOFs
make

# Build specific BOF
make enum-logon-events

# List available BOFs
make list

# Clean all artifacts
make clean
```

## Requirements

MinGW-w64 cross-compiler:

```bash
# Debian/Ubuntu
sudo apt install mingw-w64

# macOS
brew install mingw-w64
```

## Build Targets

| Command | Description |
|---------|-------------|
| `make` | Build all production BOFs |
| `make all-dev` | Include development BOFs with known issues |
| `make test` | Build test executables |
| `make clean` | Remove all artifacts |
| `make list` | List available BOFs |
| `make <name>` | Build specific BOF |
| `make help` | Show help |

## Output

Each BOF produces two object files in its directory:
- `*.x64.o` - 64-bit
- `*.x86.o` - 32-bit

## Testing

Test executables can be built for local debugging:

```bash
make test
```

These mock the Beacon API and run standalone. For production, use the `.o` files with your C2 framework.

## Individual BOF

Each BOF has its own Makefile:

```bash
cd src/enum-logon-events/
make          # Build
make test     # Test executable
make clean    # Clean
```

## Troubleshooting

**Compiler not found:**
```bash
which x86_64-w64-mingw32-gcc
which i686-w64-mingw32-gcc
```

**Build fails:** Check the individual BOF's Makefile or build it directly to see errors.
