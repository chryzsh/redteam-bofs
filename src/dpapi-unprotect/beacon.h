/*
 * Beacon Object File (BOF) API Header
 * Minimal subset used by dpapi-unprotect.
 */
#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void  __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int   __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT char* __cdecl BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT void  __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void  __cdecl BeaconOutput(int type, char* data, int len);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);

#endif /* BEACON_H */
