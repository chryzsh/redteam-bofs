# lsfiles BOF

A Beacon Object File (BOF) for enumerating files in directories with advanced wildcard support for both paths and filenames. Lists only the target directory by default; use `-r` to recurse. Use `--include-dirs` when you also want directory entries. Compatible with Cobalt Strike and OC2 (Operator Console 2).

## Features

- ✅ **Path Wildcards** - Expand wildcards in directory paths (e.g., `C:\Users\*\Downloads`)
- ✅ **Filename Patterns** - Filter files with wildcard patterns (e.g., `*.exe`, `test*.log`)
- ✅ **Optional Directory Listing** - Include directory entries with `--include-dirs` / `--dirs`
- ✅ **Time-Based Filtering** - Filter files by modification date (e.g., `2025`, `2025-11`, `2025-11-13`)
- ✅ **Streaming Output** - Results printed as files are discovered (not batch mode)
- ✅ **Summary Statistics** - Total files, optional directory count, result count, total size with human-readable format (KB/MB/GB)
- ✅ **Non-Recursive Default** - Lists current directory only; use `-r` to recurse
- ✅ **Depth Control** - Limit recursion depth or search unlimited levels
- ✅ **Error Suppression** - Optional quiet mode for access denied errors
- ✅ **Timestamp Conversion** - File times converted to local system timezone
- ✅ **Memory Efficient** - Heap allocation for long paths, proper cleanup
- ✅ **Cross-Architecture** - Compiled for both x64 and x86

## Quick Start

### Cobalt Strike

1. Load the Aggressor script:
   ```
   Cobalt Strike → Script Manager → Load → lsfiles.cna
   ```

2. Execute in beacon console:
   ```
   beacon> lsfiles C:\Users\* --pattern *.zip
   ```

### OC2 (Operator Console 2)

1. Place `lsfiles_bof.s1.py` in your OC2 scripts directory

2. Ensure BOF `.o` files are accessible to OC2

3. Execute:
   ```
   lsfiles C:\Users\* --pattern *.zip
   ```

## Usage

### Basic Syntax

```
lsfiles <path> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `path` | Target directory path (supports wildcards: `*` and `?`) |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--recursive`, `-r` | Recurse into subdirectories | Off (current dir only) |
| `--pattern <pattern>` | Wildcard pattern to filter filenames | `*` (all files) |
| `--exclude <pattern>` | Exclude files matching pattern (can be used multiple times) | None |
| `--exclude-path <pattern>` | Exclude full paths and skip recursing into matching directories | None |
| `--max-depth <depth>` | Maximum recursion depth (-1 for unlimited). Implies `-r`. | `0` |
| `--max-results <count>` | Maximum results to return (-1 for unlimited) | `1000` |
| `--include-dirs`, `--dirs` | Include directory entries in output | `false` |
| `--date-filter <date>` | Filter files by modification date (YYYY, YYYY-MM, or YYYY-MM-DD) | None |
| `--min-size <bytes>` | Minimum file size in bytes (-1 for no minimum) | `-1` |
| `--max-size <bytes>` | Maximum file size in bytes (-1 for no maximum) | `-1` |
| `--suppress-errors` | Suppress error messages for access denied | `false` |

## Examples

### Basic Enumeration

List files in a directory (current directory only, no recursion):
```
lsfiles C:\Users\Public
```

Recursively list all files:
```
lsfiles C:\Users\Public -r
```

Recurse with depth limit:
```
lsfiles C:\Users --max-depth 3
```

List directories in a directory-only share:
```
lsfiles \\test\dept --include-dirs
```

### Path Wildcards

Search all user directories:
```
lsfiles C:\Users\* --pattern *.zip
```

Search Downloads folders for all users:
```
lsfiles C:\Users\*\Downloads --pattern *.exe
```

Search config folders in Windows subdirectories:
```
lsfiles C:\Windows\*\config --pattern *.ini
```

### Filename Patterns

Find all executables (recursive):
```
lsfiles C:\Windows\System32 -r --pattern *.exe
```

Find all log files (current directory only):
```
lsfiles C:\Temp --pattern *.log
```

Find specific patterns (recursive):
```
lsfiles C:\Users -r --pattern *secret*.txt
```

### Exclude Patterns

Exclude temporary files:
```
lsfiles C:\Users --pattern * --exclude *.tmp
```

Exclude multiple file types:
```
lsfiles C:\Temp --pattern * --exclude *.tmp --exclude *.log --exclude *.bak
```

Prune `.git` trees or other specific paths:
```
lsfiles C:\Repo -r --exclude-path *\.git\*
```

Exclude a specific subtree by full path:
```
lsfiles C:\Users -r --exclude-path C:\Users\svc-build\AppData\Local\Temp\*
```

Find executables but exclude system files:
```
lsfiles C:\Windows --pattern *.exe --exclude *system32*
```

### Date Filtering

Find files modified in a specific year:
```
lsfiles C:\Users\Public --pattern *.docx --date-filter 2025
```

Find files modified in a specific month:
```
lsfiles C:\Temp --pattern *.log --date-filter 2025-11
```

Find files modified on a specific date:
```
lsfiles C:\Users\*\Downloads --pattern *.exe --date-filter 2025-11-13
```

### Size Filtering

Find files larger than 1MB:
```
lsfiles C:\Users --pattern *.zip --min-size 1048576
```

Find small log files (< 1KB):
```
lsfiles C:\Temp --pattern *.log --max-size 1024
```

Find files within a size range (1MB to 100MB):
```
lsfiles C:\Downloads --pattern * --min-size 1048576 --max-size 104857600
```

### Advanced Usage

Limit recursion depth:
```
lsfiles "C:\Program Files" --pattern *.dll --max-depth 2
```

Limit number of results (prevents beacon from hanging on massive directories):
```
lsfiles C:\ --pattern *.exe --max-results 500
```

Suppress access denied errors:
```
lsfiles C:\Windows --pattern *.sys --suppress-errors
```

Combine all options:
```
lsfiles C:\Users\*\AppData -r --pattern *.db --exclude *.tmp --max-depth 5 --max-results 2000 --date-filter 2025 --suppress-errors
```

## Wildcard Support

### Path Wildcards

Wildcards can be used in directory paths to expand and search multiple locations:

| Pattern | Description | Example |
|---------|-------------|---------|
| `*` | Matches any directory name | `C:\Users\*` → searches all user directories |
| `?` | Matches single character | `C:\Windows\System??` → matches System32, System64, etc. |

**Path Wildcard Examples:**
- `C:\Users\*` - All user directories
- `C:\Users\*\Downloads` - Downloads folder for all users
- `C:\Windows\*\config` - Config folders in all Windows subdirectories
- `C:\*\Temp` - Temp folders in all root subdirectories

### Filename Patterns

Wildcards for filtering files by name:

| Pattern | Description | Example |
|---------|-------------|---------|
| `*` | Matches any sequence | `*.exe`, `test*.log`, `*report*` |
| `?` | Matches single character | `file?.txt`, `log?.dat` |

**Filename Pattern Examples:**
- `*.exe` - All executable files
- `*.log` - All log files
- `test*.txt` - Files starting with "test"
- `*2024*.pdf` - Files containing "2024"
- `file?.txt` - file1.txt, fileA.txt, etc.

## Output Format

### File Listing

```
[+] Recursive File Listing
[+] Target Path: c:\users\*
[+] Pattern: *.zip
[+] Max Depth: 10
[+] Include Directories: true
[+] Date Filter: 2025-11
[+] Path contains wildcards - expanding...

c:\users\alice\Downloads [DIR] (Modified: 2025-11-13 14:29:10)
c:\users\alice\Downloads\archive.zip (Size: 1048576 bytes, Modified: 2025-11-13 14:30:22)
c:\users\bob\Documents\backup.zip (Size: 2097152 bytes, Modified: 2025-11-12 09:15:44)

[+] Summary:
[+]   Files Found: 2
[+]   Directories Found: 1
[+]   Results Found: 3
[+]   Total Size: 3145728 bytes (3.00 MB)
```

### Summary Statistics

The BOF provides:
- **File Count** - Total number of files matching the pattern
- **Directory Count** - Total directories matching the pattern (when `--include-dirs` is enabled)
- **Result Count** - Total printed results (files + optional directories)
- **Total Size** - Sum of all file sizes with human-readable format:
  - Bytes for < 1 KB
  - KB for >= 1 KB
  - MB for >= 1 MB
  - GB for >= 1 GB
- **Error Count** - Number of access denied or other errors (if not suppressed)

## Technical Details

### BOF Specifications

- **Source Code**: `entry.c` (1000+ lines)
- **Binary Size**: ~10 KB (x64), ~11 KB (x86)
- **Arguments**: `ZZZiiiiZii` (path: wstring, pattern: wstring, excludePatterns: wstring, suppressErrors: int, maxDepth: int, maxResults: int, includeDirs: int, dateFilter: wstring, minSize: int, maxSize: int)
- **Dependencies**: KERNEL32 only (no additional libraries)
- **Default Limits**: 1000 results max (configurable), 100 recursion depth (internal safety)
- **Exclude Patterns**: Pipe-delimited format (e.g., "*.tmp|*.log|*.bak")

### Architecture

```
┌─────────────────────────────────────┐
│  Parse Arguments                    │
│  (path, pattern, flags, depth)      │
└───────────┬─────────────────────────┘
            │
            ▼
┌─────────────────────────────────────┐
│  Check Path for Wildcards           │
└───────────┬─────────────────────────┘
            │
     ┌──────┴──────┐
     │             │
     ▼             ▼
┌─────────┐   ┌─────────────────────┐
│ Direct  │   │ Expand Path         │
│ Enum    │   │ Wildcards           │
└─────────┘   └──────┬──────────────┘
                     │
                     ▼
            ┌────────────────────┐
            │ For Each Match:    │
            │ EnumerateFiles()   │
            └────────────────────┘
                     │
                     ▼
            ┌────────────────────┐
            │ Recurse Dirs       │
            │ Match Filenames    │
            │ Stream Output      │
            └────────────────────┘
```

### Key Functions

- **`PathContainsWildcards()`** - Detects wildcards in path
- **`ExpandPathWildcardsAndEnumerate()`** - Expands path wildcards recursively
- **`EnumerateFiles()`** - Recursive file enumeration with depth control
- **`SimpleWildcardMatch()`** - Pattern matching for `*` and `?` wildcards
- **`FormatFileTime()`** - Convert FILETIME to local timezone string
- **`WideCharToUtf8()`** - Convert Unicode paths to UTF-8 for output

### Memory Management

- Heap allocation for long paths (up to 512 characters for paths)
- Proper cleanup with `HeapFree()` on all code paths
- No memory leaks - all allocations are freed

### OPSEC Considerations

- **No disk writes** - All output via beacon callbacks
- **In-process execution** - No process spawning
- **KERNEL32 only** - Minimal API footprint
- **Fast execution** - Streaming output prevents long beacon blocking
- **Controllable noise** - `--suppress-errors` reduces event log spam

## Compilation

### Prerequisites

- `x86_64-w64-mingw32-gcc` (for x64)
- `i686-w64-mingw32-gcc` (for x86)

### Build

```bash
# Compile BOF object files
make all

# Compile as executable for testing
make test

# Run static analysis
make check

# Clean build artifacts
make clean
```

### Output Files

- `lsfiles.x64.o` - 64-bit BOF
- `lsfiles.x86.o` - 32-bit BOF

## File Structure

```
lsfiles/
├── entry.c                    # BOF implementation
├── beacon.h                   # BOF API declarations
├── Makefile                   # Build configuration
├── lsfiles.x64.o              # Compiled x64 BOF
├── lsfiles.x86.o              # Compiled x86 BOF
├── lsfiles_bof.s1.py          # OC2 Python script
├── lsfiles.cna                # Cobalt Strike Aggressor script
└── README.md                  # This file
```

## Limitations

- Path buffer limited to 512 characters
- Internal safety limit of 100 recursion levels (enforced even with --max-depth=-1)
- Stack usage ~1KB per recursion level
- Exclude patterns are parsed for each file checked (performance may degrade with 1000+ files and 10+ exclude patterns)
- UTF-8 output supports Basic Multilingual Plane only (filenames with emoji or rare Unicode characters may display incorrectly)
- Cannot follow symlinks/junctions (follows physical directories only)
- Does not handle multiple wildcard segments in a single path component (e.g., `C:\*Windows*\` not supported)

## Troubleshooting

### No files found with path wildcards

**Problem**: `lsfiles C:\Users\*\` returns 0 files

**Solution**: Remove trailing slash: `lsfiles C:\Users\*` or specify a subdirectory: `lsfiles C:\Users\*\Downloads`

### Access denied errors

**Problem**: Many access denied messages

**Solution**: Use `--suppress-errors` flag to suppress error output

### BOF appears to hang

**Problem**: No output for extended period

**Solution**: Large directories take time. Consider using `--max-depth` to limit recursion or `--pattern` to filter results

## Credits

Developed using:
- [Cobalt Strike BOF API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)
- [trustedsec/CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) - BOF development patterns

## License

This project is provided as-is for authorized security testing and research purposes only.
