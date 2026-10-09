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

/* Beacon API function declarations */
DECLSPEC_IMPORT void __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short __cdecl BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int __cdecl BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char* __cdecl BeaconDataExtract(datap* parser, int* size);

DECLSPEC_IMPORT void __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void __cdecl BeaconOutput(int type, char* data, int len);

/* Memory management */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);

/* File operations */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

/* String operations - Wide char */
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);

/* Time operations */
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SystemTimeToTzSpecificLocalTime(LPTIME_ZONE_INFORMATION, LPSYSTEMTIME, LPSYSTEMTIME);

/* MSVCRT functions for string operations */
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);

/* Convenience macros for cleaner code */
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define CloseHandle KERNEL32$CloseHandle
#define FindFirstFileW KERNEL32$FindFirstFileW
#define FindNextFileW KERNEL32$FindNextFileW
#define FindClose KERNEL32$FindClose
#define GetFileAttributesW KERNEL32$GetFileAttributesW
#define GetLastError KERNEL32$GetLastError
#define lstrlenW KERNEL32$lstrlenW
#define lstrcpyW KERNEL32$lstrcpyW
#define lstrcatW KERNEL32$lstrcatW
#define lstrcmpW KERNEL32$lstrcmpW
#define lstrcmpiW KERNEL32$lstrcmpiW
#define FileTimeToSystemTime KERNEL32$FileTimeToSystemTime
#define SystemTimeToTzSpecificLocalTime KERNEL32$SystemTimeToTzSpecificLocalTime

#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
#define _snprintf MSVCRT$_snprintf
#define _snwprintf MSVCRT$_snwprintf

#endif /* BEACON_H */
