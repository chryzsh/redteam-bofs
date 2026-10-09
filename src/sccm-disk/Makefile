BOFNAME := sccm-disk
COMINCLUDE := -I .
LIBINCLUDE := -ladvapi32 -lcrypt32

BOFLINT := boflint.py
LOADER  := oc2

CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CFLAGS      := -Os -c -DBOF
TEST_CFLAGS := -g

OUTPUT_DIR := .

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) $(CFLAGS) entry.c
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) $(CFLAGS) entry.c

test:
	$(CC_x64) entry.c $(TEST_CFLAGS) $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe

lint:
	@python3 $(BOFLINT) $(OUTPUT_DIR)/$(BOFNAME).x64.o --loader $(LOADER) || true
	@python3 $(BOFLINT) $(OUTPUT_DIR)/$(BOFNAME).x86.o --loader $(LOADER) || true

clean:
	rm -f $(BOFNAME).*.o $(BOFNAME).*.exe

.PHONY: all test lint clean
