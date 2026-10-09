# BOF Makefile for enum-stored-accounts
#
# Compiles the stored-account inventory BOF for x64 and x86 architectures

# BOF name - determines output filename
BOFNAME := enum-stored-accounts

# Common include directory (not used for this standalone BOF)
COMINCLUDE :=

# Library includes - add any required Windows libraries
LIBINCLUDE := -l advapi32

# Compiler definitions
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

# Compilation flags
CFLAGS := -Os -c -DBOF -fPIC
TEST_CFLAGS := -g

# Output directory
OUTPUT_DIR := .

# Default target: compile BOF object files for both architectures
all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) $(CFLAGS) entry.c $(LIBINCLUDE)
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) $(CFLAGS) entry.c $(LIBINCLUDE)
	strip --strip-unneeded $(BOFNAME).x64.o
	strip --strip-unneeded $(BOFNAME).x86.o
	@if [ "$(OUTPUT_DIR)" != "." ]; then \
		mkdir -p $(OUTPUT_DIR) && mv $(BOFNAME)*.o $(OUTPUT_DIR); \
	fi

# Test target: compile as executable for local testing
test:
	$(CC_x64) entry.c $(TEST_CFLAGS) $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c $(TEST_CFLAGS) $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

# Scan-build target: static analysis with clang
scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

# Check target: run cppcheck for additional static analysis
check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

# Clean target: remove compiled executables and object files
clean:
	rm -f $(BOFNAME).*.exe
	rm -f $(BOFNAME).*.o

.PHONY: all test scanbuild check clean
