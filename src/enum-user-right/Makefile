BOFNAME := enum-user-right

CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip

CFLAGS := -c -Os -fPIC -fno-asynchronous-unwind-tables -fno-ident -fomit-frame-pointer -Wall -Wextra

all:
	$(CC_x64) $(CFLAGS) -o $(BOFNAME).x64.o entry.c
	$(CC_x86) $(CFLAGS) -fno-leading-underscore -o $(BOFNAME).x86.o entry.c
	$(STRIP_x64) --strip-unneeded $(BOFNAME).x64.o
	$(STRIP_x86) --strip-unneeded $(BOFNAME).x86.o

clean:
	rm -f $(BOFNAME).x64.o $(BOFNAME).x86.o

.PHONY: all clean
