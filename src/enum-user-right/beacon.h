#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

#endif
