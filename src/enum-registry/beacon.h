/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Additional BOF resources are available here:
 *   - https://github.com/Cobalt-Strike/bof_template
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 */

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);


/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Windows API - Registry Operations */
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidW(LPCWSTR, PSID*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

/* Windows API - Heap Memory */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);

/* Windows API - String Operations */
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcatA(LPSTR, LPCSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);

/* MSVCRT - C Runtime Functions */
DECLSPEC_IMPORT void* CDECL MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* CDECL MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int CDECL MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int CDECL MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int CDECL MSVCRT$sprintf(char*, const char*, ...);

/* Convenience macros for cleaner code */
#define RegOpenKeyExA ADVAPI32$RegOpenKeyExA
#define RegOpenKeyExW ADVAPI32$RegOpenKeyExW
#define RegQueryValueExA ADVAPI32$RegQueryValueExA
#define RegQueryValueExW ADVAPI32$RegQueryValueExW
#define RegEnumKeyExA ADVAPI32$RegEnumKeyExA
#define RegEnumKeyExW ADVAPI32$RegEnumKeyExW
#define RegEnumValueA ADVAPI32$RegEnumValueA
#define RegEnumValueW ADVAPI32$RegEnumValueW
#define RegCloseKey ADVAPI32$RegCloseKey
#define ConvertStringSidToSidW ADVAPI32$ConvertStringSidToSidW
#define LookupAccountSidW ADVAPI32$LookupAccountSidW
#define LocalFree KERNEL32$LocalFree
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define lstrcpyA KERNEL32$lstrcpyA
#define lstrcatA KERNEL32$lstrcatA
#define lstrcmpA KERNEL32$lstrcmpA
#define lstrlenA KERNEL32$lstrlenA
#define lstrcpyW KERNEL32$lstrcpyW
#define lstrcatW KERNEL32$lstrcatW
#define lstrcmpW KERNEL32$lstrcmpW
#define lstrlenW KERNEL32$lstrlenW
#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
#define _snprintf MSVCRT$_snprintf
#define _snwprintf MSVCRT$_snwprintf
#define sprintf MSVCRT$sprintf
