/*
 * Beacon Object Files (BOF) Header
 *
 * Beacon API and Windows API declarations for logon-events BOF
 * Includes Windows Event Log API (wevtapi.dll)
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

/* ==================== Windows API - Event Log (wevtapi.dll) ==================== */

// EVT_HANDLE is a handle to event log objects
typedef HANDLE EVT_HANDLE, *PEVT_HANDLE;

// Event rendering flags
typedef enum _EVT_RENDER_FLAGS {
    EvtRenderEventValues = 0,
    EvtRenderEventXml = 1,
    EvtRenderBookmark = 2
} EVT_RENDER_FLAGS;

// Event query flags
typedef enum _EVT_QUERY_FLAGS {
    EvtQueryChannelPath = 0x1,
    EvtQueryFilePath = 0x2,
    EvtQueryForwardDirection = 0x100,
    EvtQueryReverseDirection = 0x200
} EVT_QUERY_FLAGS;

// Event variant types
typedef enum _EVT_VARIANT_TYPE {
    EvtVarTypeNull = 0,
    EvtVarTypeString = 1,
    EvtVarTypeAnsiString = 2,
    EvtVarTypeSByte = 3,
    EvtVarTypeByte = 4,
    EvtVarTypeInt16 = 5,
    EvtVarTypeUInt16 = 6,
    EvtVarTypeInt32 = 7,
    EvtVarTypeUInt32 = 8,
    EvtVarTypeInt64 = 9,
    EvtVarTypeUInt64 = 10,
    EvtVarTypeSingle = 11,
    EvtVarTypeDouble = 12,
    EvtVarTypeBoolean = 13,
    EvtVarTypeBinary = 14,
    EvtVarTypeGuid = 15,
    EvtVarTypeSizeT = 16,
    EvtVarTypeFileTime = 17,
    EvtVarTypeSysTime = 18,
    EvtVarTypeSid = 19,
    EvtVarTypeHexInt32 = 20,
    EvtVarTypeHexInt64 = 21,
    EvtVarTypeEvtHandle = 32,
    EvtVarTypeEvtXml = 35
} EVT_VARIANT_TYPE;

// Event variant structure
typedef struct _EVT_VARIANT {
    union {
        BOOL        BooleanVal;
        INT8        SByteVal;
        INT16       Int16Val;
        INT32       Int32Val;
        INT64       Int64Val;
        UINT8       ByteVal;
        UINT16      UInt16Val;
        UINT32      UInt32Val;
        UINT64      UInt64Val;
        float       SingleVal;
        double      DoubleVal;
        ULONGLONG   FileTimeVal;
        SYSTEMTIME* SysTimeVal;
        GUID*       GuidVal;
        LPCWSTR     StringVal;
        LPCSTR      AnsiStringVal;
        PBYTE       BinaryVal;
        PSID        SidVal;
        SIZE_T      SizeTVal;
        BOOL*       BooleanArr;
        INT8*       SByteArr;
        INT16*      Int16Arr;
        INT32*      Int32Arr;
        INT64*      Int64Arr;
        UINT8*      ByteArr;
        UINT16*     UInt16Arr;
        UINT32*     UInt32Arr;
        UINT64*     UInt64Arr;
        float*      SingleArr;
        double*     DoubleArr;
        FILETIME*   FileTimeArr;
        SYSTEMTIME* SysTimeArr;
        GUID*       GuidArr;
        LPWSTR*     StringArr;
        LPSTR*      AnsiStringArr;
        PSID*       SidArr;
        SIZE_T*     SizeTArr;
        EVT_HANDLE  EvtHandleVal;
        LPCWSTR     XmlVal;
        LPCWSTR*    XmlValArr;
    };
    DWORD Count;
    DWORD Type;
} EVT_VARIANT, *PEVT_VARIANT;

// Event Log API functions
DECLSPEC_IMPORT EVT_HANDLE WINAPI WEVTAPI$EvtQuery(
    EVT_HANDLE Session,
    LPCWSTR Path,
    LPCWSTR Query,
    DWORD Flags
);

DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtNext(
    EVT_HANDLE ResultSet,
    DWORD EventsSize,
    PEVT_HANDLE Events,
    DWORD Timeout,
    DWORD Flags,
    PDWORD Returned
);

DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtRender(
    EVT_HANDLE Context,
    EVT_HANDLE Fragment,
    DWORD Flags,
    DWORD BufferSize,
    PVOID Buffer,
    PDWORD BufferUsed,
    PDWORD PropertyCount
);

DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtClose(
    EVT_HANDLE Object
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

DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(
    LPSYSTEMTIME lpSystemTime
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SystemTimeToFileTime(
    const SYSTEMTIME *lpSystemTime,
    LPFILETIME lpFileTime
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(
    const FILETIME *lpFileTime,
    LPSYSTEMTIME lpSystemTime
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToLocalFileTime(
    const FILETIME *lpFileTime,
    LPFILETIME lpLocalFileTime
);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpW(
    LPCWSTR lpString1,
    LPCWSTR lpString2
);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(
    LPCWSTR lpString
);

/* ==================== MSVCRT - C Runtime Functions ==================== */

DECLSPEC_IMPORT void* CDECL MSVCRT$memset(
    void* dest,
    int c,
    size_t count
);

DECLSPEC_IMPORT int CDECL MSVCRT$_snwprintf(
    wchar_t* buffer,
    size_t count,
    const wchar_t* format,
    ...
);

DECLSPEC_IMPORT wchar_t* CDECL MSVCRT$wcsstr(
    const wchar_t* str,
    const wchar_t* substr
);

DECLSPEC_IMPORT wchar_t* CDECL MSVCRT$wcsncpy(
    wchar_t* dest,
    const wchar_t* src,
    size_t count
);

DECLSPEC_IMPORT unsigned long CDECL MSVCRT$wcstoul(
    const wchar_t* str,
    wchar_t** endptr,
    int base
);

DECLSPEC_IMPORT int CDECL MSVCRT$swscanf(
    const wchar_t* buffer,
    const wchar_t* format,
    ...
);

/* ==================== Convenience macros ==================== */

#define EvtQuery                WEVTAPI$EvtQuery
#define EvtNext                 WEVTAPI$EvtNext
#define EvtRender               WEVTAPI$EvtRender
#define EvtClose                WEVTAPI$EvtClose
#define HeapAlloc               KERNEL32$HeapAlloc
#define HeapFree                KERNEL32$HeapFree
#define GetProcessHeap          KERNEL32$GetProcessHeap
#define GetLastError            KERNEL32$GetLastError
#define GetSystemTime           KERNEL32$GetSystemTime
#define SystemTimeToFileTime    KERNEL32$SystemTimeToFileTime
#define FileTimeToSystemTime    KERNEL32$FileTimeToSystemTime
#define FileTimeToLocalFileTime KERNEL32$FileTimeToLocalFileTime
#define lstrcmpW                KERNEL32$lstrcmpW
#define lstrlenW                KERNEL32$lstrlenW
#define memset                  MSVCRT$memset
#define _snwprintf              MSVCRT$_snwprintf
#define wcsstr                  MSVCRT$wcsstr
#define wcsncpy                 MSVCRT$wcsncpy
#define wcstoul                 MSVCRT$wcstoul
#define swscanf                 MSVCRT$swscanf

#endif /* BEACON_H */
