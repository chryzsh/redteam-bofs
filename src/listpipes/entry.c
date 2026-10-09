// listpipes.c — BOF: list local named pipes with a single output block
#include <windows.h>
#include "beacon.h"

#define FileDirectoryInformation        1
#define STATUS_SUCCESS                  0x00000000L
#define STATUS_NO_MORE_FILES            0x80000006L
#define STATUS_BUFFER_OVERFLOW          0x80000005L
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004L

// KERNEL32 / MSVCRT imports for BOF
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
DECLSPEC_IMPORT VOID    WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT,DWORD,LPCWCH,int,LPSTR,int,LPCCH,LPBOOL);

DECLSPEC_IMPORT void*   __cdecl  MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl  MSVCRT$memset(void*, int, size_t);

#define intAlloc(sz) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define intFree(p)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

typedef struct { LONG Status; ULONG Information; } IO_STATUS_BLOCK;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength; // bytes
    WCHAR         FileName[1];    // not null-terminated
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef LONG (NTAPI *NtQueryDirectoryFile_t)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    IO_STATUS_BLOCK* IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, BOOL ReturnSingleEntry, PVOID FileName, BOOL RestartScan
);

static void list_pipes(void) {
    // Resolve NtQueryDirectoryFile
    HMODULE ntdll = KERNEL32$LoadLibraryA("ntdll.dll");
    if (!ntdll) { BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(ntdll) failed"); return; }
    NtQueryDirectoryFile_t NtQueryDirectoryFile =
        (NtQueryDirectoryFile_t)KERNEL32$GetProcAddress(ntdll, "NtQueryDirectoryFile");
    if (!NtQueryDirectoryFile) { BeaconPrintf(CALLBACK_ERROR, "GetProcAddress(NtQueryDirectoryFile) failed"); return; }

    // Open \\.\pipe\ pseudo-directory
    HANDLE h = KERNEL32$CreateFileW(L"\\\\.\\pipe\\",
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_ERROR, "CreateFileW(\\\\.\\pipe\\) failed"); return; }

    // NT query buffer (grows if needed)
    SIZE_T enumCap = 0x4000;  // 16KB instead of 64KB
    PVOID  enumBuf = intAlloc(enumCap);
    if (!enumBuf) { KERNEL32$CloseHandle(h); BeaconPrintf(CALLBACK_ERROR, "alloc failed"); return; }

    // Output buffer (UTF-8). Start at 64 KB; grow if needed.
    SIZE_T outCap = 64 * 1024;
    SIZE_T outUsed = 0;
    char  *outBuf = (char*)intAlloc(outCap);
    if (!outBuf) { intFree(enumBuf); KERNEL32$CloseHandle(h); BeaconPrintf(CALLBACK_ERROR, "alloc failed"); return; }

    static const char *prefix = "\\\\.\\pipe\\";
    const SIZE_T prefixLen = 9; // strlen("\\\\.\\pipe\\")

    IO_STATUS_BLOCK ios;
    BOOL restart = TRUE;

    for (;;) {
        LONG st = NtQueryDirectoryFile(h, NULL, NULL, NULL, &ios, enumBuf, (ULONG)enumCap,
                                       FileDirectoryInformation, FALSE, NULL, restart);
        if (st == (LONG)STATUS_BUFFER_OVERFLOW || st == (LONG)STATUS_INFO_LENGTH_MISMATCH) {
            intFree(enumBuf);
            enumCap *= 2;
            enumBuf = intAlloc(enumCap);
            if (!enumBuf) { BeaconPrintf(CALLBACK_ERROR, "alloc failed"); goto done; }
            KERNEL32$Sleep(10);
            continue;
        }
        if (st == (LONG)STATUS_NO_MORE_FILES) break;
        if (st != (LONG)STATUS_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "NtQueryDirectoryFile error: 0x%08lx", st); goto done; }

        PFILE_DIRECTORY_INFORMATION cur = (PFILE_DIRECTORY_INFORMATION)enumBuf;
        for (;;) {
            ULONG wlenBytes = cur->FileNameLength;
            ULONG wlenChars = wlenBytes / sizeof(WCHAR);

            WCHAR *wtmp = (WCHAR*)intAlloc((wlenChars + 1) * sizeof(WCHAR));
            if (!wtmp) { BeaconPrintf(CALLBACK_ERROR, "alloc failed"); goto done; }
            MSVCRT$memcpy(wtmp, cur->FileName, wlenBytes);
            wtmp[wlenChars] = L'\0';

            // wide -> UTF-8 (CP_UTF8)
            int need = KERNEL32$WideCharToMultiByte(65001, 0, wtmp, -1, NULL, 0, NULL, NULL);
            if (need > 0) {
                // ensure capacity: prefix + name(without terminal NUL) + '\n'
                SIZE_T add = prefixLen + (SIZE_T)(need - 1) + 1;
                if (outUsed + add > outCap) {
                    SIZE_T newCap = outCap * 2;
                    if (newCap < outUsed + add) newCap = outUsed + add + 0x10000;
                    char *newBuf = (char*)intAlloc(newCap);
                    if (!newBuf) { intFree(wtmp); BeaconPrintf(CALLBACK_ERROR, "alloc failed"); goto done; }
                    MSVCRT$memcpy(newBuf, outBuf, outUsed);
                    MSVCRT$memset(outBuf, 0, outCap);
                    intFree(outBuf);
                    outBuf = newBuf; outCap = newCap;
                }
                // copy prefix
                MSVCRT$memcpy(outBuf + outUsed, prefix, prefixLen); outUsed += prefixLen;
                // convert into place
                KERNEL32$WideCharToMultiByte(65001, 0, wtmp, -1, outBuf + outUsed, need, NULL, NULL);
                outUsed += (SIZE_T)(need - 1); // don't count NUL
                // newline
                outBuf[outUsed++] = '\n';
            }
            intFree(wtmp);

            if (cur->NextEntryOffset == 0) break;
            cur = (PFILE_DIRECTORY_INFORMATION)((BYTE*)cur + cur->NextEntryOffset);
        }
        restart = FALSE;
    }

done:
    if (outUsed > 0) {
        BeaconOutput(CALLBACK_OUTPUT, outBuf, (int)outUsed); // one block
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "(no pipes found)");
    }

    if (outBuf) { MSVCRT$memset(outBuf, 0, outCap); intFree(outBuf); }
    if (enumBuf){ MSVCRT$memset(enumBuf, 0, enumCap); intFree(enumBuf); }
    KERNEL32$CloseHandle(h);
}

// Entry point for listpipes BOF
// Lists all named pipes on the local system via NtQueryDirectoryFile
// Arguments: None (args/alen are unused)
void go(char *args, int alen) {
    (void)args; (void)alen;
    list_pipes();
}

