/*
 * Beacon Object File (BOF) API Header
 *
 * Common declarations for BOF development with Cobalt Strike
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Beacon callback types */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* Data parser structure */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

/* Format buffer structure for building output */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} formatp;

/* Beacon API function declarations */
DECLSPEC_IMPORT void __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short __cdecl BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int __cdecl BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char* __cdecl BeaconDataExtract(datap* parser, int* size);

DECLSPEC_IMPORT void __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void __cdecl BeaconOutput(int type, char* data, int len);

DECLSPEC_IMPORT void __cdecl BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void __cdecl BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void __cdecl BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void __cdecl BeaconFormatAppend(formatp* format, char* text, int len);
DECLSPEC_IMPORT void __cdecl BeaconFormatPrintf(formatp* format, char* fmt, ...);
DECLSPEC_IMPORT char* __cdecl BeaconFormatToString(formatp* format, int* size);
DECLSPEC_IMPORT void __cdecl BeaconFormatInt(formatp* format, int value);

/* Commonly used Win32 APIs - extend as needed */
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* MSVCRT functions for string operations */
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

/* Convenience macros for cleaner code */
#define GetProcAddress KERNEL32$GetProcAddress
#define LoadLibraryA KERNEL32$LoadLibraryA
#define GetModuleHandleA KERNEL32$GetModuleHandleA
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define CloseHandle KERNEL32$CloseHandle
#define GetLastError KERNEL32$GetLastError

#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
#define strlen MSVCRT$strlen
#define wcslen MSVCRT$wcslen
#define strcpy MSVCRT$strcpy
#define strcmp MSVCRT$strcmp
#define wcscpy MSVCRT$wcscpy
#define _wcsicmp MSVCRT$_wcsicmp

#endif /* BEACON_H */
