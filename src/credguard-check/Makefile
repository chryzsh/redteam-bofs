# BOF Makefile for credguard-check
#
# Compiles BOF to check Windows security features:
# - Credential Guard
# - HVCI (Hypervisor-protected Code Integrity)
# - LSA Protection (RunAsPPL)
# - VBS (Virtualization-Based Security)

# BOF name
BOFNAME := credguard-check

# Library includes - advapi32 for registry APIs
LIBINCLUDE := -l advapi32

# Compiler definitions
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

# Compilation flags
CFLAGS := -Os -c -DBOF
TEST_CFLAGS := -g

# Default target: compile BOF object files for both architectures
all:
	$(CC_x64) -o $(BOFNAME).x64.o $(CFLAGS) entry.c
	$(CC_x86) -o $(BOFNAME).x86.o $(CFLAGS) entry.c
	strip --strip-unneeded $(BOFNAME).x64.o
	strip --strip-unneeded $(BOFNAME).x86.o
	@echo "[+] BOF object files compiled successfully:"
	@echo "    - $(BOFNAME).x64.o"
	@echo "    - $(BOFNAME).x86.o"

# Test target: compile as executable for local testing
test:
	$(CC_x64) entry.c $(TEST_CFLAGS) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c $(TEST_CFLAGS) $(LIBINCLUDE) -o $(BOFNAME).x86.exe
	@echo "[+] Test executables compiled successfully:"
	@echo "    - $(BOFNAME).x64.exe (run with Wine: wine64 $(BOFNAME).x64.exe)"
	@echo "    - $(BOFNAME).x86.exe (run with Wine: wine $(BOFNAME).x86.exe)"

# Clean target: remove compiled artifacts
clean:
	rm -f $(BOFNAME).*.exe
	rm -f $(BOFNAME).*.o
	@echo "[+] Build artifacts cleaned"

.PHONY: all test clean
