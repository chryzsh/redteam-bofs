# BOF Makefile for edge-passdump
#
# Compiles the Edge Saved Passwords Dumper BOF for x64 and x86.
# Requires: advapi32 (LookupAccountSidW, OpenProcessToken, GetTokenInformation).

BOFNAME := edge-passdump

LIBINCLUDE := -l advapi32

CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip

CFLAGS := -Os -c -DBOF
TEST_CFLAGS := -g

SOURCE := entry.c

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(CFLAGS) $(SOURCE)
	$(CC_x86) -o $(BOFNAME).x86.o $(CFLAGS) $(SOURCE)
	$(STRIP_x64) --strip-unneeded $(BOFNAME).x64.o
	$(STRIP_x86) --strip-unneeded $(BOFNAME).x86.o
	@echo "BOF compiled successfully: $(BOFNAME).x64.o and $(BOFNAME).x86.o"

test:
	$(CC_x64) $(SOURCE) $(TEST_CFLAGS) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) $(SOURCE) $(TEST_CFLAGS) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

clean:
	rm -f $(BOFNAME).*.exe
	rm -f $(BOFNAME).*.o

.PHONY: all test clean
