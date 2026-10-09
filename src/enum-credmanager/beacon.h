/*
 * Beacon Object Files (BOF) Header
 *
 * Beacon API and Windows API declarations for credential-manager-enum BOF
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* ==================== Beacon Data Parser API ==================== */

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* ==================== Beacon Format API ==================== */

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* ==================== Beacon Output Functions ==================== */

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);
DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);

/* ==================== Beacon Token Functions ==================== */

DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* ==================== Windows API - Credential Manager ==================== */

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CredEnumerateW(
    LPCWSTR Filter,
    DWORD Flags,
    DWORD *Count,
    PCREDENTIALW **Credentials
);

DECLSPEC_IMPORT VOID WINAPI ADVAPI32$CredFree(
    PVOID Buffer
);

/* ==================== Windows API - Kernel32 ==================== */

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(
    HANDLE hHeap,
    DWORD dwFlags,
    LPVOID lpMem
);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCSTR lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToLocalFileTime(
    const FILETIME *lpFileTime,
    LPFILETIME lpLocalFileTime
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(
    const FILETIME *lpFileTime,
    LPSYSTEMTIME lpSystemTime
);

/* ==================== Convenience macros ==================== */

#define CredEnumerateW         ADVAPI32$CredEnumerateW
#define CredFree              ADVAPI32$CredFree
#define HeapAlloc             KERNEL32$HeapAlloc
#define HeapFree              KERNEL32$HeapFree
#define GetProcessHeap        KERNEL32$GetProcessHeap
#define GetLastError          KERNEL32$GetLastError
#define MultiByteToWideChar   KERNEL32$MultiByteToWideChar
#define FileTimeToLocalFileTime KERNEL32$FileTimeToLocalFileTime
#define FileTimeToSystemTime  KERNEL32$FileTimeToSystemTime

#endif /* BEACON_H */
