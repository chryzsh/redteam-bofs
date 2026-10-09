# Makefile — Build BOF object(s) for OC2/Cobalt Strike
# Usage:
#   make            # Builds x64 + x86
#   make x64        # Builds x64 only
#   make x86        # Builds x86 only
#   make clean

# ---- config ----
SRC            ?= entry.c
OUT_BASENAME   ?= curl

MINGW_PREFIX64 ?= x86_64-w64-mingw32
MINGW_PREFIX32 ?= i686-w64-mingw32

CC64 := $(MINGW_PREFIX64)-gcc
CC32 := $(MINGW_PREFIX32)-gcc
STRIP64 := $(MINGW_PREFIX64)-strip
STRIP32 := $(MINGW_PREFIX32)-strip

COMMON_CFLAGS := -c -Os -masm=intel -fno-asynchronous-unwind-tables \
                 -fno-ident -fomit-frame-pointer -Wall -Wextra

CFLAGS64 := $(COMMON_CFLAGS)
CFLAGS32 := $(COMMON_CFLAGS) -DWOW64 -fno-leading-underscore

OBJ64 := $(OUT_BASENAME).x64.o
OBJ32 := $(OUT_BASENAME).x86.o

.PHONY: all x64 x86 clean test

all: $(OBJ64) $(OBJ32)
x64: $(OBJ64)
x86: $(OBJ32)

$(OBJ64): $(SRC)
	$(CC64) $(CFLAGS64) -o $@ $<
	$(STRIP64) --strip-unneeded $@

$(OBJ32): $(SRC)
	$(CC32) $(CFLAGS32) -o $@ $<
	$(STRIP32) --strip-unneeded $@

# Test target: compile as executable for local testing
test:
	$(CC64) $(SRC) -g -o $(OUT_BASENAME).x64.exe
	$(CC32) $(SRC) -g -o $(OUT_BASENAME).x86.exe
	@echo "Test executables created: $(OUT_BASENAME).x64.exe and $(OUT_BASENAME).x86.exe"

clean:
	rm -f $(OUT_BASENAME).*.o
	rm -f $(OUT_BASENAME).*.exe
