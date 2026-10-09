#include <windows.h>
#include "beacon.h"

/**
 * Stored Account Inventory BOF (enum-stored-accounts)
 *
 * Answers "whose credentials are stored on this box, and where" after
 * gaining admin, without touching LSASS or decrypting anything:
 *
 *   SERVICES (0x01) - services whose ObjectName is a real account rather
 *                     than LocalSystem / NT AUTHORITY / NT SERVICE. Their
 *                     passwords live in LSA secrets as _SC_<ServiceName>.
 *   TASKS    (0x02) - scheduled tasks whose XML has LogonType Password or
 *                     InteractiveTokenOrPassword. Their passwords live in
 *                     the Credential Manager of the task scheduler (SYSTEM).
 *   DPAPI    (0x04) - per profile under C:\Users: Credential Manager blobs,
 *                     DPAPI masterkeys (with SID -> account), vault entries,
 *                     and whether that user's hive is currently loaded.
 *
 * SAFETY NOTES:
 * - Read-only registry and file access
 * - Heap allocation for large buffers, bounded recursion and file caps
 */

// Keep stack frames under 4 KB so gcc does not emit a ___chkstk_ms probe,
// which BOF loaders cannot resolve. Large buffers go on the heap.
#define MAX_PATH_LENGTH 512
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_DATA 8192
#define MAX_TASK_FILES 3000
#define MAX_TASK_DEPTH 8
#define MAX_TASK_XML_BYTES 262144
#define MAX_PROFILES 256

#define INV_SERVICES 0x01
#define INV_TASKS    0x02
#define INV_DPAPI    0x04
#define INV_ALL      0xFF

#define SERVICE_KERNEL_DRIVER_TYPE 0x01
#define SERVICE_FS_DRIVER_TYPE     0x02

typedef struct {
    DWORD serviceAccounts;
    DWORD taskAccounts;
    DWORD profilesWithCreds;
    DWORD taskFilesScanned;
} InventoryStats;

/* ------------------------------------------------------------------ */
/* Wide-string helpers                                                  */
/* ------------------------------------------------------------------ */

static WCHAR LowerW(WCHAR c) {
    if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
    return c;
}

static BOOL EqualsIW(LPCWSTR a, LPCWSTR b) {
    int i = 0;
    while (a[i] && b[i]) {
        if (LowerW(a[i]) != LowerW(b[i])) return FALSE;
        i++;
    }
    return a[i] == L'\0' && b[i] == L'\0';
}

static BOOL StartsWithIW(LPCWSTR value, LPCWSTR prefix) {
    int i = 0;
    while (prefix[i]) {
        if (value[i] == L'\0') return FALSE;
        if (LowerW(value[i]) != LowerW(prefix[i])) return FALSE;
        i++;
    }
    return TRUE;
}

static BOOL SafeCopyW(LPWSTR dest, LPCWSTR src, int destSize) {
    if (lstrlenW(src) + 1 > destSize) return FALSE;
    lstrcpyW(dest, src);
    return TRUE;
}

static BOOL SafeConcatW(LPWSTR dest, LPCWSTR src, int destSize) {
    if (lstrlenW(dest) + lstrlenW(src) + 1 > destSize) return FALSE;
    lstrcatW(dest, src);
    return TRUE;
}

static BOOL IsDotDir(LPCWSTR name) {
    return lstrcmpW(name, L".") == 0 || lstrcmpW(name, L"..") == 0;
}

// Null-terminate a REG_SZ value returned in bytes.
static void TerminateRegStringW(WCHAR* buf, DWORD bufChars, DWORD dataBytes) {
    DWORD chars = dataBytes / sizeof(WCHAR);
    if (chars >= bufChars) chars = bufChars - 1;
    buf[chars] = L'\0';
}

static void ResolveSidAccount(LPCWSTR sidString, WCHAR* out, DWORD outChars) {
    PSID psid = NULL;
    WCHAR name[128];
    WCHAR domain[128];
    DWORD nameLen = 128;
    DWORD domainLen = 128;
    SID_NAME_USE use;

    SafeCopyW(out, sidString, outChars);

    if (!ConvertStringSidToSidW(sidString, &psid) || !psid) return;

    if (LookupAccountSidW(NULL, psid, name, &nameLen, domain, &domainLen, &use)) {
        if (domainLen > 0) {
            _snwprintf(out, outChars, L"%s\\%s", domain, name);
        } else {
            _snwprintf(out, outChars, L"%s", name);
        }
        out[outChars - 1] = L'\0';
    }

    LocalFree(psid);
}

/* ------------------------------------------------------------------ */
/* SERVICES: HKLM\SYSTEM\CurrentControlSet\Services\*\ObjectName          */
/* ------------------------------------------------------------------ */

static BOOL IsBuiltinServiceAccount(LPCWSTR objectName) {
    if (objectName[0] == L'\0') return TRUE;
    if (EqualsIW(objectName, L"LocalSystem")) return TRUE;
    if (StartsWithIW(objectName, L"NT AUTHORITY\\")) return TRUE;
    if (StartsWithIW(objectName, L"NT SERVICE\\")) return TRUE;   // virtual account, no secret
    if (StartsWithIW(objectName, L"NT Virtual Machine\\")) return TRUE;
    if (StartsWithIW(objectName, L"Window Manager\\")) return TRUE;
    if (StartsWithIW(objectName, L"Font Driver Host\\")) return TRUE;
    return FALSE;
}

static const char* StartTypeString(DWORD start) {
    switch (start) {
        case 0: return "Boot";
        case 1: return "System";
        case 2: return "Auto";
        case 3: return "Manual";
        case 4: return "Disabled";
        default: return "?";
    }
}

static void EnumerateServiceAccounts(InventoryStats* stats) {
    HKEY hServices;
    HKEY hSvc;
    DWORD index = 0;
    WCHAR keyName[MAX_KEY_LENGTH];
    DWORD keyNameLen;
    LONG result;
    HANDLE hHeap = GetProcessHeap();
    WCHAR* objectName = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_VALUE_DATA);
    WCHAR* displayName = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_VALUE_DATA);
    WCHAR* imagePath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_VALUE_DATA);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Services running as a stored account (LSA secret _SC_<name>):\n");

    if (!objectName || !displayName || !imagePath) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] allocation failed\n");
        goto cleanup;
    }

    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hServices);
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Could not open Services key: %ld\n", result);
        goto cleanup;
    }

    while (1) {
        DWORD type = 0;
        DWORD start = 0;
        DWORD valueType;
        DWORD size;

        keyNameLen = MAX_KEY_LENGTH;
        result = RegEnumKeyExW(hServices, index, keyName, &keyNameLen, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) break;
        index++;
        if (result != ERROR_SUCCESS) continue;

        if (RegOpenKeyExW(hServices, keyName, 0, KEY_READ, &hSvc) != ERROR_SUCCESS) continue;

        size = sizeof(type);
        if (RegQueryValueExW(hSvc, L"Type", NULL, &valueType, (BYTE*)&type, &size) != ERROR_SUCCESS ||
            valueType != REG_DWORD) {
            type = 0;
        }
        if (type == SERVICE_KERNEL_DRIVER_TYPE || type == SERVICE_FS_DRIVER_TYPE) {
            RegCloseKey(hSvc);
            continue;
        }

        size = MAX_VALUE_DATA - sizeof(WCHAR);
        if (RegQueryValueExW(hSvc, L"ObjectName", NULL, &valueType, (BYTE*)objectName, &size) != ERROR_SUCCESS ||
            (valueType != REG_SZ && valueType != REG_EXPAND_SZ)) {
            RegCloseKey(hSvc);
            continue;
        }
        TerminateRegStringW(objectName, MAX_VALUE_DATA / sizeof(WCHAR), size);

        if (IsBuiltinServiceAccount(objectName)) {
            RegCloseKey(hSvc);
            continue;
        }

        size = sizeof(start);
        if (RegQueryValueExW(hSvc, L"Start", NULL, &valueType, (BYTE*)&start, &size) != ERROR_SUCCESS ||
            valueType != REG_DWORD) {
            start = 0xFFFFFFFF;
        }

        displayName[0] = L'\0';
        size = MAX_VALUE_DATA - sizeof(WCHAR);
        if (RegQueryValueExW(hSvc, L"DisplayName", NULL, &valueType, (BYTE*)displayName, &size) == ERROR_SUCCESS &&
            (valueType == REG_SZ || valueType == REG_EXPAND_SZ)) {
            TerminateRegStringW(displayName, MAX_VALUE_DATA / sizeof(WCHAR), size);
        } else {
            displayName[0] = L'\0';
        }

        imagePath[0] = L'\0';
        size = MAX_VALUE_DATA - sizeof(WCHAR);
        if (RegQueryValueExW(hSvc, L"ImagePath", NULL, &valueType, (BYTE*)imagePath, &size) == ERROR_SUCCESS &&
            (valueType == REG_SZ || valueType == REG_EXPAND_SZ)) {
            TerminateRegStringW(imagePath, MAX_VALUE_DATA / sizeof(WCHAR), size);
        } else {
            imagePath[0] = L'\0';
        }

        RegCloseKey(hSvc);

        {
            int nameLen = lstrlenW(objectName);
            const char* note = "";
            if (nameLen > 0 && objectName[nameLen - 1] == L'$') {
                note = "  (gMSA/computer account: no password in LSA secrets)";
            }

            BeaconPrintf(CALLBACK_OUTPUT, "    [SVC] %S\n", keyName);
            BeaconPrintf(CALLBACK_OUTPUT, "          Account:  %S%s\n", objectName, note);
            BeaconPrintf(CALLBACK_OUTPUT, "          Start:    %s\n", StartTypeString(start));
            if (displayName[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "          Name:     %S\n", displayName);
            }
            if (imagePath[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "          Image:    %S\n", imagePath);
            }
        }

        stats->serviceAccounts++;
    }

    RegCloseKey(hServices);

    if (stats->serviceAccounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] None found\n");
    }

cleanup:
    if (objectName) HeapFree(hHeap, 0, objectName);
    if (displayName) HeapFree(hHeap, 0, displayName);
    if (imagePath) HeapFree(hHeap, 0, imagePath);
}

/* ------------------------------------------------------------------ */
/* TASKS: %WINDIR%\System32\Tasks\** with LogonType Password            */
/* ------------------------------------------------------------------ */

// Read a task XML file into a NUL-terminated wide buffer. Task files are
// normally UTF-16LE with a BOM; anything else is widened byte-for-byte,
// which is enough to find the ASCII tags we care about.
static WCHAR* ReadTaskXml(LPCWSTR path) {
    HANDLE hHeap = GetProcessHeap();
    HANDLE hFile;
    LARGE_INTEGER size;
    DWORD toRead;
    DWORD got = 0;
    BYTE* raw = NULL;
    WCHAR* wide = NULL;

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0) {
        CloseHandle(hFile);
        return NULL;
    }
    toRead = size.QuadPart > MAX_TASK_XML_BYTES ? MAX_TASK_XML_BYTES : (DWORD)size.QuadPart;

    raw = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, toRead + 2);
    if (!raw) {
        CloseHandle(hFile);
        return NULL;
    }

    while (got < toRead) {
        DWORD n = 0;
        if (!ReadFile(hFile, raw + got, toRead - got, &n, NULL) || n == 0) break;
        got += n;
    }
    CloseHandle(hFile);

    if (got >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        DWORD chars = (got - 2) / 2;
        wide = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (chars + 1) * sizeof(WCHAR));
        if (wide) {
            for (DWORD i = 0; i < chars; i++) {
                wide[i] = (WCHAR)(raw[2 + i * 2] | (raw[3 + i * 2] << 8));
            }
            wide[chars] = L'\0';
        }
    } else {
        wide = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (got + 1) * sizeof(WCHAR));
        if (wide) {
            for (DWORD i = 0; i < got; i++) {
                wide[i] = (WCHAR)raw[i];
            }
            wide[got] = L'\0';
        }
    }

    HeapFree(hHeap, 0, raw);
    return wide;
}

// Copy the text between <tag> and </tag> into out. Returns FALSE if absent.
static BOOL ExtractTagW(LPCWSTR xml, LPCWSTR openTag, LPCWSTR closeTag, WCHAR* out, int outChars) {
    LPCWSTR start = wcsstr(xml, openTag);
    LPCWSTR end;
    int len;

    out[0] = L'\0';
    if (!start) return FALSE;
    start += lstrlenW(openTag);
    end = wcsstr(start, closeTag);
    if (!end) return FALSE;
    len = (int)(end - start);
    if (len <= 0) return FALSE;
    if (len >= outChars) len = outChars - 1;
    for (int i = 0; i < len; i++) out[i] = start[i];
    out[len] = L'\0';
    return TRUE;
}

static void InspectTaskFile(LPCWSTR path, LPCWSTR displayPath, InventoryStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* xml = ReadTaskXml(path);
    WCHAR logonType[64];
    WCHAR userId[256];
    WCHAR runLevel[64];
    WCHAR enabled[16];

    if (!xml) return;
    stats->taskFilesScanned++;

    if (!ExtractTagW(xml, L"<LogonType>", L"</LogonType>", logonType, 64)) {
        HeapFree(hHeap, 0, xml);
        return;
    }

    if (!EqualsIW(logonType, L"Password") && !EqualsIW(logonType, L"InteractiveTokenOrPassword")) {
        HeapFree(hHeap, 0, xml);
        return;
    }

    ExtractTagW(xml, L"<UserId>", L"</UserId>", userId, 256);
    ExtractTagW(xml, L"<RunLevel>", L"</RunLevel>", runLevel, 64);
    ExtractTagW(xml, L"<Enabled>", L"</Enabled>", enabled, 16);

    BeaconPrintf(CALLBACK_OUTPUT, "    [TASK] %S\n", displayPath);
    BeaconPrintf(CALLBACK_OUTPUT, "           Account:   %S\n", userId[0] ? userId : L"(not in XML, see principal SID)");
    BeaconPrintf(CALLBACK_OUTPUT, "           LogonType: %S%s\n", logonType,
                 enabled[0] && EqualsIW(enabled, L"false") ? "  (task disabled)" : "");
    if (runLevel[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "           RunLevel:  %S\n", runLevel);
    }

    stats->taskAccounts++;
    HeapFree(hHeap, 0, xml);
}

static void WalkTaskFolder(LPCWSTR dir, LPCWSTR displayPrefix, int depth, InventoryStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* fullPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* displayPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW fd;
    HANDLE hFind;

    if (!searchPath || !fullPath || !displayPath) goto cleanup;
    if (depth > MAX_TASK_DEPTH) goto cleanup;

    if (!SafeCopyW(searchPath, dir, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, L"\\*", MAX_PATH_LENGTH)) goto cleanup;

    hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) goto cleanup;

    do {
        if (IsDotDir(fd.cFileName)) continue;
        if (stats->taskFilesScanned >= MAX_TASK_FILES) break;

        if (!SafeCopyW(fullPath, dir, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(fullPath, L"\\", MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(fullPath, fd.cFileName, MAX_PATH_LENGTH)) continue;

        if (!SafeCopyW(displayPath, displayPrefix, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(displayPath, L"\\", MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(displayPath, fd.cFileName, MAX_PATH_LENGTH)) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            WalkTaskFolder(fullPath, displayPath, depth + 1, stats);
        } else {
            InspectTaskFile(fullPath, displayPath, stats);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

cleanup:
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (fullPath) HeapFree(hHeap, 0, fullPath);
    if (displayPath) HeapFree(hHeap, 0, displayPath);
}

static void EnumerateTaskAccounts(LPCWSTR winDir, InventoryStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* tasksDir = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Scheduled tasks with a stored password (LogonType Password):\n");

    if (!tasksDir) return;
    if (!SafeCopyW(tasksDir, winDir, MAX_PATH_LENGTH) ||
        !SafeConcatW(tasksDir, L"\\System32\\Tasks", MAX_PATH_LENGTH)) {
        HeapFree(hHeap, 0, tasksDir);
        return;
    }

    WalkTaskFolder(tasksDir, L"", 0, stats);
    HeapFree(hHeap, 0, tasksDir);

    if (stats->taskFilesScanned == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] No task files readable (needs admin)\n");
    } else if (stats->taskAccounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] None found (%lu task files scanned)\n", stats->taskFilesScanned);
    } else if (stats->taskFilesScanned >= MAX_TASK_FILES) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Scan capped at %d task files\n", MAX_TASK_FILES);
    }
}

/* ------------------------------------------------------------------ */
/* DPAPI: per-profile credential blobs, masterkeys, vaults               */
/* ------------------------------------------------------------------ */

static BOOL ShouldSkipProfile(LPCWSTR name) {
    if (IsDotDir(name)) return TRUE;
    if (EqualsIW(name, L"Public")) return TRUE;
    if (EqualsIW(name, L"Default")) return TRUE;
    if (EqualsIW(name, L"Default User")) return TRUE;
    if (EqualsIW(name, L"All Users")) return TRUE;
    return FALSE;
}

// Count regular files under dir matching pattern, skipping names in skipName.
static DWORD CountFiles(LPCWSTR dir, LPCWSTR pattern, LPCWSTR skipName) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW* fd = (WIN32_FIND_DATAW*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(WIN32_FIND_DATAW));
    HANDLE hFind;
    DWORD count = 0;

    if (!searchPath || !fd) goto cleanup;
    if (!SafeCopyW(searchPath, dir, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, L"\\", MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, pattern, MAX_PATH_LENGTH)) goto cleanup;

    hFind = FindFirstFileW(searchPath, fd);
    if (hFind == INVALID_HANDLE_VALUE) goto cleanup;

    do {
        if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (skipName && EqualsIW(fd->cFileName, skipName)) continue;
        count++;
    } while (FindNextFileW(hFind, fd));

    FindClose(hFind);

cleanup:
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (fd) HeapFree(hHeap, 0, fd);
    return count;
}

static BOOL IsHiveLoaded(LPCWSTR sid) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_USERS, sid, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    // Access denied still means the hive exists (another user, no admin).
    return result == ERROR_ACCESS_DENIED;
}

static void InspectProfile(LPCWSTR profilePath, LPCWSTR profileName, InventoryStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* path = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* account = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 320 * sizeof(WCHAR));
    WIN32_FIND_DATAW* fdp = (WIN32_FIND_DATAW*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(WIN32_FIND_DATAW));
    HANDLE hFind;
    DWORD roamingCreds = 0;
    DWORD localCreds = 0;
    DWORD vaults = 0;
    DWORD masterkeys = 0;
    BOOL printedHeader = FALSE;

    if (!path || !searchPath || !account || !fdp) goto cleanup;

    if (SafeCopyW(path, profilePath, MAX_PATH_LENGTH) &&
        SafeConcatW(path, L"\\AppData\\Roaming\\Microsoft\\Credentials", MAX_PATH_LENGTH)) {
        roamingCreds = CountFiles(path, L"*", NULL);
    }
    if (SafeCopyW(path, profilePath, MAX_PATH_LENGTH) &&
        SafeConcatW(path, L"\\AppData\\Local\\Microsoft\\Credentials", MAX_PATH_LENGTH)) {
        localCreds = CountFiles(path, L"*", NULL);
    }

    // Vault: AppData\Local\Microsoft\Vault\<GUID>\*.vcrd
    if (SafeCopyW(searchPath, profilePath, MAX_PATH_LENGTH) &&
        SafeConcatW(searchPath, L"\\AppData\\Local\\Microsoft\\Vault\\*", MAX_PATH_LENGTH)) {
        hFind = FindFirstFileW(searchPath, fdp);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fdp->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (IsDotDir(fdp->cFileName)) continue;
                if (SafeCopyW(path, profilePath, MAX_PATH_LENGTH) &&
                    SafeConcatW(path, L"\\AppData\\Local\\Microsoft\\Vault\\", MAX_PATH_LENGTH) &&
                    SafeConcatW(path, fdp->cFileName, MAX_PATH_LENGTH)) {
                    vaults += CountFiles(path, L"*.vcrd", NULL);
                }
            } while (FindNextFileW(hFind, fdp));
            FindClose(hFind);
        }
    }

    // Masterkeys: AppData\Roaming\Microsoft\Protect\<SID>\<GUID>
    if (SafeCopyW(searchPath, profilePath, MAX_PATH_LENGTH) &&
        SafeConcatW(searchPath, L"\\AppData\\Roaming\\Microsoft\\Protect\\S-1-*", MAX_PATH_LENGTH)) {
        hFind = FindFirstFileW(searchPath, fdp);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                DWORD keys;
                if (!(fdp->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (!SafeCopyW(path, profilePath, MAX_PATH_LENGTH)) continue;
                if (!SafeConcatW(path, L"\\AppData\\Roaming\\Microsoft\\Protect\\", MAX_PATH_LENGTH)) continue;
                if (!SafeConcatW(path, fdp->cFileName, MAX_PATH_LENGTH)) continue;

                keys = CountFiles(path, L"*-*-*-*-*", L"Preferred");
                masterkeys += keys;

                if (!printedHeader) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    [USER] %S\n", profileName);
                    printedHeader = TRUE;
                }
                ResolveSidAccount(fdp->cFileName, account, 320);
                BeaconPrintf(CALLBACK_OUTPUT, "           SID:        %S (%S)  hive loaded: %s\n",
                             fdp->cFileName, account, IsHiveLoaded(fdp->cFileName) ? "yes" : "no");
                BeaconPrintf(CALLBACK_OUTPUT, "           Masterkeys: %lu\n", keys);
            } while (FindNextFileW(hFind, fdp));
            FindClose(hFind);
        }
    }

    if (roamingCreds + localCreds + vaults == 0 && masterkeys == 0) {
        goto cleanup;
    }

    if (!printedHeader) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [USER] %S\n", profileName);
        BeaconPrintf(CALLBACK_OUTPUT, "           SID:        (no Protect folder readable)\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "           CredBlobs:  %lu (%lu roaming, %lu local)\n",
                 roamingCreds + localCreds, roamingCreds, localCreds);
    BeaconPrintf(CALLBACK_OUTPUT, "           Vault:      %lu entries\n", vaults);

    if (roamingCreds + localCreds + vaults > 0) {
        stats->profilesWithCreds++;
    }

cleanup:
    if (path) HeapFree(hHeap, 0, path);
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (account) HeapFree(hHeap, 0, account);
    if (fdp) HeapFree(hHeap, 0, fdp);
}

static void EnumerateDpapiMaterial(LPCWSTR usersRoot, InventoryStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* profilePath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW* fd = (WIN32_FIND_DATAW*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(WIN32_FIND_DATAW));
    HANDLE hFind;
    DWORD profiles = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] DPAPI material per profile under %S:\n", usersRoot);

    if (!searchPath || !profilePath || !fd) goto cleanup;

    if (!SafeCopyW(searchPath, usersRoot, MAX_PATH_LENGTH) ||
        !SafeConcatW(searchPath, L"\\*", MAX_PATH_LENGTH)) {
        goto cleanup;
    }

    hFind = FindFirstFileW(searchPath, fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Cannot list %S: %lu\n", usersRoot, GetLastError());
        goto cleanup;
    }

    do {
        if (!(fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (ShouldSkipProfile(fd->cFileName)) continue;
        if (profiles >= MAX_PROFILES) break;

        if (!SafeCopyW(profilePath, usersRoot, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, L"\\", MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, fd->cFileName, MAX_PATH_LENGTH)) continue;

        profiles++;
        InspectProfile(profilePath, fd->cFileName, stats);
    } while (FindNextFileW(hFind, fd));

    FindClose(hFind);

    if (profiles == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] No profiles found\n");
    } else if (stats->profilesWithCreds == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] %lu profiles checked, none hold credential blobs or vault entries\n", profiles);
    }

cleanup:
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (profilePath) HeapFree(hHeap, 0, profilePath);
    if (fd) HeapFree(hHeap, 0, fd);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

#ifdef BOF
void go(char* args, int len) {
    datap parser;
    int flags = 0;
    LPWSTR usersRootArg = NULL;
    HANDLE hHeap = GetProcessHeap();
    WCHAR* winDir = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* usersRoot = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    InventoryStats stats;
    UINT n;

    memset(&stats, 0, sizeof(stats));

    if (!winDir || !usersRoot) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
        if (winDir) HeapFree(hHeap, 0, winDir);
        if (usersRoot) HeapFree(hHeap, 0, usersRoot);
        return;
    }

    BeaconDataParse(&parser, args, len);
    if (len >= 4) {
        flags = BeaconDataInt(&parser);
        usersRootArg = (LPWSTR)BeaconDataExtract(&parser, NULL);
    }
    if (flags == 0) flags = INV_ALL;

    n = GetWindowsDirectoryW(winDir, MAX_PATH_LENGTH);
    if (n == 0 || n >= MAX_PATH_LENGTH) {
        lstrcpyW(winDir, L"C:\\Windows");
    }

    if (usersRootArg && lstrlenW(usersRootArg) > 0 && lstrlenW(usersRootArg) < MAX_PATH_LENGTH) {
        lstrcpyW(usersRoot, usersRootArg);
    } else {
        usersRoot[0] = winDir[0];
        usersRoot[1] = L':';
        usersRoot[2] = L'\\';
        usersRoot[3] = L'\0';
        lstrcatW(usersRoot, L"Users");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Stored Account Inventory\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Sections: %s%s%s\n",
                 (flags & INV_SERVICES) ? "services " : "",
                 (flags & INV_TASKS) ? "tasks " : "",
                 (flags & INV_DPAPI) ? "dpapi" : "");

    if (flags & INV_SERVICES) {
        EnumerateServiceAccounts(&stats);
    }
    if (flags & INV_TASKS) {
        EnumerateTaskAccounts(winDir, &stats);
    }
    if (flags & INV_DPAPI) {
        EnumerateDpapiMaterial(usersRoot, &stats);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Summary:\n");
    if (flags & INV_SERVICES) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Services with stored account:   %lu\n", stats.serviceAccounts);
    }
    if (flags & INV_TASKS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Tasks with stored password:     %lu (of %lu scanned)\n",
                     stats.taskAccounts, stats.taskFilesScanned);
    }
    if (flags & INV_DPAPI) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Profiles with cred/vault blobs: %lu\n", stats.profilesWithCreds);
    }

    HeapFree(hHeap, 0, winDir);
    HeapFree(hHeap, 0, usersRoot);
}

#else
#include <stdio.h>

int main(int argc, char** argv) {
    printf("Stored Account Inventory BOF - Test Mode\n");
    printf("Compile with -DBOF for BOF mode\n");
    printf("Usage: enum-stored-accounts.exe <flags> [users_root]\n");
    printf("  flags: SERVICES=0x01, TASKS=0x02, DPAPI=0x04, ALL=0xFF\n");
    return 0;
}
#endif
