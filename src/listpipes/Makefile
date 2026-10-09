# Makefile — Build BOF object(s) for Cobalt Strike
# Usage:
#   make            # Builds x64 + x86
#   make x64        # Builds x64 only
#   make x86        # Builds x86 only
#   make check      # sanity-check .text and COFF format
#   make clean

# ---- config ----
SRC            ?= entry.c
BOFNAME        ?= listpipes
BEACON_INCLUDE ?= ./include     # path containing beacon.h
LIBINCLUDE     ?=               # No additional libraries required

MINGW_PREFIX64 ?= x86_64-w64-mingw32
MINGW_PREFIX32 ?= i686-w64-mingw32

CC64 := $(MINGW_PREFIX64)-gcc
CC32 := $(MINGW_PREFIX32)-gcc

COMMON_CFLAGS := -c -Os -fno-asynchronous-unwind-tables -fno-exceptions \
                 -fno-ident -fomit-frame-pointer -fshort-wchar -Wall -Wextra \
                 -Wno-cast-function-type -I$(BEACON_INCLUDE)

OBJ64 := $(BOFNAME).x64.o
OBJ32 := $(BOFNAME).x86.o

.PHONY: all x64 x86 clean check test

all: $(OBJ64) $(OBJ32)
x64: $(OBJ64)
x86: $(OBJ32)

$(OBJ64): $(SRC)
	$(CC64) $(COMMON_CFLAGS) -o $@ $<
	$(MINGW_PREFIX64)-strip --strip-unneeded $@

$(OBJ32): $(SRC)
	$(CC32) $(COMMON_CFLAGS) -o $@ $<
	$(MINGW_PREFIX32)-strip --strip-unneeded $@

check: all
	@echo "[x64]"; $(MINGW_PREFIX64)-objdump -h $(OBJ64) | grep '\.text' || true; \
	$(MINGW_PREFIX64)-objdump -f $(OBJ64) | grep 'file format'
	@echo "[x86]"; $(MINGW_PREFIX32)-objdump -h $(OBJ32) | grep '\.text' || true; \
	$(MINGW_PREFIX32)-objdump -f $(OBJ32) | grep 'file format'

# Test target: compile as executable for local testing
test:
	$(CC64) $(SRC) -g -I$(BEACON_INCLUDE) -o $(BOFNAME).x64.exe
	$(CC32) $(SRC) -g -I$(BEACON_INCLUDE) -o $(BOFNAME).x86.exe
	@echo "Test executables created: $(BOFNAME).x64.exe and $(BOFNAME).x86.exe"

clean:
	rm -f $(BOFNAME).*.o
	rm -f $(BOFNAME).*.exe

