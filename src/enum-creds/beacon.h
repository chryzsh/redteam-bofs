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

/* Windows API - File System */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetWindowsDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

/* Windows API - Time Conversion */
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SystemTimeToTzSpecificLocalTime(
    LPTIME_ZONE_INFORMATION, LPSYSTEMTIME, LPSYSTEMTIME);

/* Windows API - Heap Memory */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);

/* Windows API - String Operations */
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);

/* MSVCRT - C Runtime Functions */
DECLSPEC_IMPORT void* CDECL MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int CDECL MSVCRT$_snprintf(char*, size_t, const char*, ...);

/* Convenience macros for cleaner code */
#define FindFirstFileW KERNEL32$FindFirstFileW
#define FindNextFileW KERNEL32$FindNextFileW
#define FindClose KERNEL32$FindClose
#define CreateFileW KERNEL32$CreateFileW
#define ReadFile KERNEL32$ReadFile
#define GetFileSizeEx KERNEL32$GetFileSizeEx
#define CloseHandle KERNEL32$CloseHandle
#define GetLastError KERNEL32$GetLastError
#define ExpandEnvironmentStringsW KERNEL32$ExpandEnvironmentStringsW
#define GetWindowsDirectoryW KERNEL32$GetWindowsDirectoryW
#define RegOpenKeyExW ADVAPI32$RegOpenKeyExW
#define RegQueryValueExW ADVAPI32$RegQueryValueExW
#define RegCloseKey ADVAPI32$RegCloseKey
#define FileTimeToSystemTime KERNEL32$FileTimeToSystemTime
#define SystemTimeToTzSpecificLocalTime KERNEL32$SystemTimeToTzSpecificLocalTime
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define lstrcpyW KERNEL32$lstrcpyW
#define lstrcatW KERNEL32$lstrcatW
#define lstrcmpW KERNEL32$lstrcmpW
#define lstrlenW KERNEL32$lstrlenW
#define memset MSVCRT$memset
#define _snprintf MSVCRT$_snprintf
