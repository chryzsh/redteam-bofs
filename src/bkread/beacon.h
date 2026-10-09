/*
 * Beacon Object File (BOF) API Header
 *
 * Common declarations for BOF development with Cobalt Strike
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>
#include <winternl.h>

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

/* Process and token APIs */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

/* File operations */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

/* String operations - Wide char */
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);

/* MSVCRT functions for string operations */
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);

/* Native APIs */
DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

/* Convenience macros for cleaner code */
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define GetCurrentProcess KERNEL32$GetCurrentProcess
#define OpenProcessToken ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueW ADVAPI32$LookupPrivilegeValueW
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define CreateFileW KERNEL32$CreateFileW
#define ReadFile KERNEL32$ReadFile
#define GetFileSizeEx KERNEL32$GetFileSizeEx
#define GetFileAttributesW KERNEL32$GetFileAttributesW
#define GetLastError KERNEL32$GetLastError
#define CloseHandle KERNEL32$CloseHandle
#define lstrlenW KERNEL32$lstrlenW

#define memset MSVCRT$memset
#define _snprintf MSVCRT$_snprintf
#define _snwprintf MSVCRT$_snwprintf

#define RtlInitUnicodeString NTDLL$RtlInitUnicodeString
#define NtCreateFile NTDLL$NtCreateFile

#endif /* BEACON_H */
