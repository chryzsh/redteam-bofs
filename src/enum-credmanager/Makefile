# Credential Manager Enumeration BOF Makefile
#
# Enumerates Windows Credential Manager credentials for current user
# Requires: advapi32.lib (for CredEnumerateW, CredFree)

# BOF name
BOFNAME := enum-credmanager

# Library includes
LIBINCLUDE := -l advapi32

# Compiler definitions
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

# Compilation flags
CFLAGS := -Os -c -DBOF

# Source file
SOURCE := entry.c

# Default target: compile BOF object files for both architectures
all:
	$(CC_x64) -o $(BOFNAME).x64.o $(CFLAGS) $(SOURCE)
	$(CC_x86) -o $(BOFNAME).x86.o $(CFLAGS) $(SOURCE)
	strip --strip-unneeded $(BOFNAME).x64.o
	strip --strip-unneeded $(BOFNAME).x86.o
	@echo "BOF compiled successfully: $(BOFNAME).x64.o and $(BOFNAME).x86.o"

# Test target: compile as executable for local testing
test:
	$(CC_x64) $(SOURCE) -g $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) $(SOURCE) -g $(LIBINCLUDE) -o $(BOFNAME).x86.exe
	@echo "Test executables created: $(BOFNAME).x64.exe and $(BOFNAME).x86.exe"

# Clean target: remove compiled artifacts
clean:
	rm -f $(BOFNAME).*.exe
	rm -f $(BOFNAME).*.o

.PHONY: all test clean
