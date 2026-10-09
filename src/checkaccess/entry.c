#include <windows.h>
#include "beacon.h"

/*
 * checkaccess BOF
 *
 * Probes directory read access for a single path (UNC or local).
 * Output format mirrors enumshares verdict style.
 */

#define MAX_PATH_LENGTH 512
#define MAX_VERDICT_LENGTH 128

// Convert wide string to UTF-8 for output
int WideCharToUtf8(LPCWSTR wide, char* buffer, int bufferSize) {
    int i = 0;
    int j = 0;

    while (wide[i] && j < bufferSize - 1) {
        if (wide[i] < 0x80) {
            buffer[j++] = (char)wide[i];
        } else if (wide[i] < 0x800) {
            if (j + 1 >= bufferSize - 1) break;
            buffer[j++] = 0xC0 | (wide[i] >> 6);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        } else {
            if (j + 2 >= bufferSize - 1) break;
            buffer[j++] = 0xE0 | (wide[i] >> 12);
            buffer[j++] = 0x80 | ((wide[i] >> 6) & 0x3F);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        }
        i++;
    }

    buffer[j] = '\0';
    return j;
}

// Check whether a UNC path targets the IPC$ share
BOOL IsIpcSharePath(LPCWSTR path) {
    const WCHAR* p;
    WCHAR shareName[64];
    int shareLen = 0;

    if (!path || path[0] != L'\\' || path[1] != L'\\') {
        return FALSE;
    }

    // Skip leading "\\"
    p = path + 2;

    // Skip server component
    while (*p && *p != L'\\') {
        p++;
    }

    if (*p != L'\\') {
        return FALSE;
    }

    // Move to share component
    p++;

    // Extract share name
    while (*p && *p != L'\\' && shareLen < 63) {
        shareName[shareLen++] = *p;
        p++;
    }
    shareName[shareLen] = L'\0';

    if (shareLen == 0) {
        return FALSE;
    }

    return lstrcmpiW(shareName, L"IPC$") == 0;
}

void SetVerdictFromError(DWORD errorCode, char* verdict, int verdictSize) {
    if (errorCode == ERROR_ACCESS_DENIED ||
        errorCode == ERROR_LOGON_FAILURE ||
        errorCode == ERROR_SHARING_VIOLATION) {
        _snprintf(verdict, verdictSize, "[-] Access denied");
        return;
    }

    if (errorCode == ERROR_BAD_NETPATH ||
        errorCode == ERROR_BAD_NET_NAME ||
        errorCode == ERROR_NETWORK_UNREACHABLE ||
        errorCode == ERROR_HOST_UNREACHABLE) {
        _snprintf(verdict, verdictSize, "[-] Network path not found");
        return;
    }

    if (errorCode == ERROR_PATH_NOT_FOUND || errorCode == ERROR_FILE_NOT_FOUND) {
        _snprintf(verdict, verdictSize, "[-] Path not found");
        return;
    }

    _snprintf(verdict, verdictSize, "[-] Error: %lu", errorCode);
}

BOOL CheckDirectoryReadAccess(LPCWSTR targetPath, char* verdict, int verdictSize) {
    DWORD attributes;
    DWORD lastError;
    LPWSTR searchPath;
    int targetLen;
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    if (IsIpcSharePath(targetPath)) {
        _snprintf(verdict, verdictSize, "[!] No file system access");
        return FALSE;
    }

    attributes = GetFileAttributesW(targetPath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        SetVerdictFromError(GetLastError(), verdict, verdictSize);
        return FALSE;
    }

    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        _snprintf(verdict, verdictSize, "[-] Not a directory");
        return FALSE;
    }

    targetLen = lstrlenW(targetPath);
    if (targetLen >= MAX_PATH_LENGTH - 3) {
        _snprintf(verdict, verdictSize, "[-] Path too long");
        return FALSE;
    }

    searchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   (targetLen + 4) * sizeof(WCHAR));
    if (!searchPath) {
        _snprintf(verdict, verdictSize, "[-] Memory allocation failed");
        return FALSE;
    }

    lstrcpyW(searchPath, targetPath);
    if (targetLen > 0 &&
        targetPath[targetLen - 1] != L'\\' &&
        targetPath[targetLen - 1] != L'/') {
        lstrcatW(searchPath, L"\\");
    }
    lstrcatW(searchPath, L"*");

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        HeapFree(GetProcessHeap(), 0, searchPath);
        _snprintf(verdict, verdictSize, "[+] Accessible");
        return TRUE;
    }

    lastError = GetLastError();
    HeapFree(GetProcessHeap(), 0, searchPath);

    // Empty directory can still indicate valid list access in this probe model
    if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_NO_MORE_FILES) {
        _snprintf(verdict, verdictSize, "[+] Accessible");
        return TRUE;
    }

    SetVerdictFromError(lastError, verdict, verdictSize);
    return FALSE;
}

BOOL IsAccessDeniedVerdict(const char* verdict) {
    const char* denied = "[-] Access denied";
    int i;

    if (!verdict) {
        return FALSE;
    }

    for (i = 0; denied[i] != '\0'; i++) {
        if (verdict[i] != denied[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL IsDotEntry(LPCWSTR name) {
    return (lstrcmpW(name, L".") == 0 || lstrcmpW(name, L"..") == 0);
}

typedef struct _PROBE_OPTIONS {
    BOOL suppressAccessDenied;
    BOOL recursive;
    BOOL foundAny;
    int suppressedDeniedCount;
    int skippedLongPaths;
    int skippedReparsePoints;
} PROBE_OPTIONS;

void EnumerateSubdirectories(LPCWSTR parentPath, PROBE_OPTIONS* options) {
    LPWSTR searchPath;
    int parentLen;
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    parentLen = lstrlenW(parentPath);
    if (parentLen >= MAX_PATH_LENGTH - 3) {
        options->skippedLongPaths++;
        return;
    }

    searchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   (parentLen + 4) * sizeof(WCHAR));
    if (!searchPath) {
        char pathUtf8[MAX_PATH_LENGTH * 2];

        if (WideCharToUtf8(parentPath, pathUtf8, sizeof(pathUtf8)) <= 0) {
            _snprintf(pathUtf8, sizeof(pathUtf8), "<path-conversion-failed>");
        }
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  [!] Failed to allocate memory while enumerating %s\n",
                     pathUtf8);
        return;
    }

    lstrcpyW(searchPath, parentPath);
    if (parentLen > 0 &&
        parentPath[parentLen - 1] != L'\\' &&
        parentPath[parentLen - 1] != L'/') {
        lstrcatW(searchPath, L"\\");
    }
    lstrcatW(searchPath, L"*");

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();

        HeapFree(GetProcessHeap(), 0, searchPath);

        if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_NO_MORE_FILES) {
            return;
        }

        // Non-empty enumeration failures are reported at per-child probe level.
        return;
    }

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !IsDotEntry(findData.cFileName)) {
            WCHAR childPath[MAX_PATH_LENGTH];
            int childLen;
            char verdict[MAX_VERDICT_LENGTH];
            char childPathUtf8[MAX_PATH_LENGTH * 2];
            BOOL childAccessible;
            BOOL isReparsePoint;

            childLen = parentLen + lstrlenW(findData.cFileName) + 2;
            if (childLen >= MAX_PATH_LENGTH) {
                options->skippedLongPaths++;
                continue;
            }

            lstrcpyW(childPath, parentPath);
            if (parentLen > 0 &&
                parentPath[parentLen - 1] != L'\\' &&
                parentPath[parentLen - 1] != L'/') {
                lstrcatW(childPath, L"\\");
            }
            lstrcatW(childPath, findData.cFileName);

            memset(verdict, 0, sizeof(verdict));
            childAccessible = CheckDirectoryReadAccess(childPath, verdict, sizeof(verdict));

            if (options->suppressAccessDenied && IsAccessDeniedVerdict(verdict)) {
                options->suppressedDeniedCount++;
                continue;
            }

            if (WideCharToUtf8(childPath, childPathUtf8, sizeof(childPathUtf8)) <= 0) {
                _snprintf(childPathUtf8, sizeof(childPathUtf8), "<path-conversion-failed>");
            }

            BeaconPrintf(CALLBACK_OUTPUT, "Path: %s <- %s\n", childPathUtf8, verdict);
            options->foundAny = TRUE;

            isReparsePoint = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            if (options->recursive && childAccessible) {
                if (isReparsePoint) {
                    options->skippedReparsePoints++;
                } else {
                    EnumerateSubdirectories(childPath, options);
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    HeapFree(GetProcessHeap(), 0, searchPath);
}

void ProbeSubdirectories(LPCWSTR parentPath, BOOL suppressAccessDenied, BOOL recursive) {
    PROBE_OPTIONS options;

    memset(&options, 0, sizeof(options));
    options.suppressAccessDenied = suppressAccessDenied;
    options.recursive = recursive;

    if (recursive) {
        BeaconPrintf(CALLBACK_OUTPUT, "Subfolders (recursive):\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Subfolders (depth 1):\n");
    }

    EnumerateSubdirectories(parentPath, &options);

    if (!options.foundAny) {
        BeaconPrintf(CALLBACK_OUTPUT, "  (no subdirectories found)\n");
    }

    if (options.suppressedDeniedCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  [i] Suppressed %d access-denied subdirectory result(s)\n",
                     options.suppressedDeniedCount);
    }

    if (options.skippedLongPaths > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  [!] Skipped %d subdirectories due to path length limits\n",
                     options.skippedLongPaths);
    }

    if (options.skippedReparsePoints > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  [i] Skipped recursion into %d reparse point(s)\n",
                     options.skippedReparsePoints);
    }
}

#ifdef BOF
void go(char* args, int len) {
    datap parser;
    LPWSTR targetPath;
    char verdict[MAX_VERDICT_LENGTH];
    char pathUtf8[MAX_PATH_LENGTH * 2];
    int suppressAccessDenied = 0;
    int recursive = 0;
    BOOL rootAccessible;

    BeaconDataParse(&parser, args, len);
    targetPath = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (BeaconDataLength(&parser) >= sizeof(int)) {
        suppressAccessDenied = BeaconDataInt(&parser);
    }
    if (BeaconDataLength(&parser) >= sizeof(int)) {
        recursive = BeaconDataInt(&parser);
    }

    if (!targetPath || lstrlenW(targetPath) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: checkaccess <path>");
        return;
    }

    if (lstrlenW(targetPath) >= MAX_PATH_LENGTH) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] Target path exceeds maximum length (%d characters)",
                     MAX_PATH_LENGTH);
        return;
    }

    memset(verdict, 0, sizeof(verdict));
    if (WideCharToUtf8(targetPath, pathUtf8, sizeof(pathUtf8)) <= 0) {
        _snprintf(pathUtf8, sizeof(pathUtf8), "<path-conversion-failed>");
    }

    rootAccessible = CheckDirectoryReadAccess(targetPath, verdict, sizeof(verdict));
    BeaconPrintf(CALLBACK_OUTPUT, "Path: %s <- %s\n", pathUtf8, verdict);

    if (rootAccessible) {
        ProbeSubdirectories(targetPath, suppressAccessDenied != 0, recursive != 0);
    }
}
#else
#include <stdio.h>
int main(void) {
    printf("Build with -DBOF for Beacon mode.\n");
    return 0;
}
#endif
