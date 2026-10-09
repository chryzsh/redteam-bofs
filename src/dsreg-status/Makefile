# BOF Makefile for dsreg-status

BOFNAME := dsreg-status
COMINCLUDE :=
LIBINCLUDE := -l netapi32 -l crypt32 -l winhttp -l wininet

CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

CFLAGS := -Os -c -DBOF -fPIC
TEST_CFLAGS := -g
OUTPUT_DIR := .

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) $(CFLAGS) entry.c $(LIBINCLUDE)
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) $(CFLAGS) entry.c $(LIBINCLUDE)
	strip --strip-unneeded $(BOFNAME).x64.o
	strip --strip-unneeded $(BOFNAME).x86.o
	@if [ "$(OUTPUT_DIR)" != "." ]; then \
		mkdir -p $(OUTPUT_DIR) && mv $(BOFNAME)*.o $(OUTPUT_DIR); \
	fi

test:
	$(CC_x64) entry.c $(TEST_CFLAGS) $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c $(TEST_CFLAGS) $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm -f $(BOFNAME).*.exe
	rm -f $(BOFNAME).*.o

.PHONY: all test scanbuild check clean
