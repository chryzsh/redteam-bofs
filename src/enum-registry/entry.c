#include <windows.h>
#include "beacon.h"

/**
 * Registry Intel BOF
 *
 * Gathers intelligence from Windows Registry:
 * - RDP connection history (every loaded user hive)
 * - Installed software enumeration
 * - Environment variables (system + every loaded user hive)
 * - WSL/Docker detection (WSL per loaded user hive)
 *
 * Per-user data is read by walking HKEY_USERS rather than HKEY_CURRENT_USER,
 * so with admin rights every logged-on user's hive is covered. Without admin
 * only the caller's own hive opens; the others are reported as access denied.
 *
 * SAFETY NOTES:
 * - Read-only registry operations
 * - Heap allocation for buffers
 * - Proper error handling on all registry calls
 */

// Safety limits
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_DATA 32768
#define MAX_USER_HIVES 64
#define SID_MAX_CHARS 128
#define ACCOUNT_MAX_CHARS 320
#define PATH_MAX_CHARS 768

// Intel type flags
#define INTEL_TYPE_RDP      0x01
#define INTEL_TYPE_SOFTWARE 0x02
#define INTEL_TYPE_ENV      0x04
#define INTEL_TYPE_WSL      0x08
#define INTEL_TYPE_ALL      0xFF

// Statistics structure
typedef struct {
    DWORD rdpCount;
    DWORD softwareCount;
    DWORD envCount;
    DWORD wslDetected;
} RegistryStats;

// One loaded hive under HKEY_USERS
typedef struct {
    WCHAR sid[SID_MAX_CHARS];
    WCHAR account[ACCOUNT_MAX_CHARS];
    WCHAR prefix[SID_MAX_CHARS + 2];   // "<sid>\\"
} UserHive;

// Forward declarations
void EnumerateRDPHistory(RegistryStats* stats, const UserHive* hives, DWORD hiveCount);
void EnumerateSoftware(RegistryStats* stats);
void EnumerateEnvironmentVariables(RegistryStats* stats, const UserHive* hives, DWORD hiveCount);
void DetectWSLDocker(RegistryStats* stats, const UserHive* hives, DWORD hiveCount);

// Ensure a registry-returned wide-string buffer is null-terminated.
void EnsureNullTerminatedW(BYTE* buffer, const DWORD bufferBytes, const DWORD dataBytes) {
    if (!buffer || bufferBytes < sizeof(WCHAR)) {
        return;
    }

    const DWORD maxChars = bufferBytes / sizeof(WCHAR);
    DWORD charLen = dataBytes / sizeof(WCHAR);
    if (charLen >= maxChars) {
        charLen = maxChars - 1;
    }

    ((WCHAR*)buffer)[charLen] = L'\0';
}

/* ------------------------------------------------------------------ */
/* Wide-string helpers (ASCII case-insensitive)                        */
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

static BOOL EndsWithIW(LPCWSTR value, LPCWSTR suffix) {
    int vl = lstrlenW(value);
    int sl = lstrlenW(suffix);
    if (sl > vl) return FALSE;
    for (int i = 0; i < sl; i++) {
        if (LowerW(value[vl - sl + i]) != LowerW(suffix[i])) return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* HKEY_USERS hive discovery                                           */
/* ------------------------------------------------------------------ */

// Skip the service hives and the *_Classes companions; keep real accounts.
static BOOL IsUserHiveName(LPCWSTR name) {
    if (EqualsIW(name, L".DEFAULT")) return FALSE;
    if (EndsWithIW(name, L"_Classes")) return FALSE;
    if (EqualsIW(name, L"S-1-5-18")) return FALSE;
    if (EqualsIW(name, L"S-1-5-19")) return FALSE;
    if (EqualsIW(name, L"S-1-5-20")) return FALSE;
    return TRUE;
}

static void ResolveSidAccount(LPCWSTR sidString, WCHAR* out, DWORD outChars) {
    PSID psid = NULL;
    WCHAR name[128];
    WCHAR domain[128];
    DWORD nameLen = 128;
    DWORD domainLen = 128;
    SID_NAME_USE use;

    lstrcpyW(out, sidString);

    if (!ConvertStringSidToSidW(sidString, &psid) || !psid) {
        return;
    }

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

static DWORD CollectUserHives(UserHive* hives, DWORD maxHives) {
    DWORD index = 0;
    DWORD count = 0;
    WCHAR keyName[MAX_KEY_LENGTH];
    DWORD keyNameLen;
    LONG result;

    while (count < maxHives) {
        keyNameLen = MAX_KEY_LENGTH;
        result = RegEnumKeyExW(HKEY_USERS, index, keyName, &keyNameLen,
                               NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) break;
        index++;
        if (result != ERROR_SUCCESS) continue;
        if (!IsUserHiveName(keyName)) continue;
        if (lstrlenW(keyName) >= SID_MAX_CHARS) continue;

        lstrcpyW(hives[count].sid, keyName);
        ResolveSidAccount(keyName, hives[count].account, ACCOUNT_MAX_CHARS);
        _snwprintf(hives[count].prefix, SID_MAX_CHARS + 2, L"%s\\", keyName);
        hives[count].prefix[SID_MAX_CHARS + 1] = L'\0';
        count++;
    }

    return count;
}

/* ------------------------------------------------------------------ */
/* RDP history                                                         */
/* ------------------------------------------------------------------ */

// root + prefix locate the hive: (HKEY_USERS, "<sid>\\") or (HKEY_CURRENT_USER, "").
static void RdpForHive(HKEY root, LPCWSTR prefix, LPCWSTR label, RegistryStats* stats) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    DWORD hiveRdpCount = 0;
    WCHAR serverName[MAX_KEY_LENGTH];
    DWORD serverNameLen;
    FILETIME lastWriteTime;
    WCHAR path[PATH_MAX_CHARS];

    _snwprintf(path, PATH_MAX_CHARS, L"%sSoftware\\Microsoft\\Terminal Server Client\\Servers", prefix);
    path[PATH_MAX_CHARS - 1] = L'\0';

    result = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
    if (result == ERROR_ACCESS_DENIED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [User] %S: access denied\n", label);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    [User] %S\n", label);

    if (result == ERROR_SUCCESS) {
        while (1) {
            serverNameLen = MAX_KEY_LENGTH;
            result = RegEnumKeyExW(hKey, index, serverName, &serverNameLen,
                                   NULL, NULL, NULL, &lastWriteTime);
            if (result == ERROR_NO_MORE_ITEMS) break;

            if (result == ERROR_SUCCESS) {
                HKEY hServerKey;
                WCHAR* username;
                DWORD usernameLen = MAX_VALUE_DATA;
                DWORD valueType;

                username = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_DATA * sizeof(WCHAR));
                if (!username) {
                    BeaconPrintf(CALLBACK_OUTPUT, "      [RDP] %S\n", serverName);
                    hiveRdpCount++;
                    index++;
                    continue;
                }

                _snwprintf(path, PATH_MAX_CHARS,
                    L"%sSoftware\\Microsoft\\Terminal Server Client\\Servers\\%s", prefix, serverName);
                path[PATH_MAX_CHARS - 1] = L'\0';

                if (RegOpenKeyExW(root, path, 0, KEY_READ, &hServerKey) == ERROR_SUCCESS) {
                    result = RegQueryValueExW(hServerKey, L"UsernameHint", NULL, &valueType,
                                              (BYTE*)username, &usernameLen);
                    if (result == ERROR_SUCCESS && valueType == REG_SZ && usernameLen > 0) {
                        EnsureNullTerminatedW((BYTE*)username, MAX_VALUE_DATA * sizeof(WCHAR), usernameLen);
                        BeaconPrintf(CALLBACK_OUTPUT, "      [RDP] %S (User: %S)\n", serverName, username);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "      [RDP] %S\n", serverName);
                    }
                    RegCloseKey(hServerKey);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "      [RDP] %S\n", serverName);
                }

                HeapFree(GetProcessHeap(), 0, username);
                hiveRdpCount++;
            }

            index++;
        }

        RegCloseKey(hKey);
    }

    // Default MRU list
    _snwprintf(path, PATH_MAX_CHARS, L"%sSoftware\\Microsoft\\Terminal Server Client\\Default", prefix);
    path[PATH_MAX_CHARS - 1] = L'\0';

    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR* valueName = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_NAME * sizeof(WCHAR));
        BYTE* valueData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_DATA);

        if (valueName && valueData) {
            index = 0;
            while (1) {
                DWORD valueNameLen = MAX_VALUE_NAME;
                DWORD valueDataLen = MAX_VALUE_DATA;
                DWORD valueType;

                result = RegEnumValueW(hKey, index, valueName, &valueNameLen,
                                       NULL, &valueType, valueData, &valueDataLen);
                if (result == ERROR_NO_MORE_ITEMS) break;

                if (result == ERROR_SUCCESS && valueType == REG_SZ &&
                    valueName[0] == L'M' && valueName[1] == L'R' && valueName[2] == L'U') {
                    EnsureNullTerminatedW(valueData, MAX_VALUE_DATA, valueDataLen);
                    BeaconPrintf(CALLBACK_OUTPUT, "      [MRU] %S: %S\n", valueName, (WCHAR*)valueData);
                    hiveRdpCount++;
                }

                index++;
            }
        }

        if (valueName) HeapFree(GetProcessHeap(), 0, valueName);
        if (valueData) HeapFree(GetProcessHeap(), 0, valueData);
        RegCloseKey(hKey);
    }

    if (hiveRdpCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "      [*] No RDP connections found\n");
    }

    if (stats->rdpCount + hiveRdpCount < stats->rdpCount) {
        stats->rdpCount = 0xFFFFFFFF;
    } else {
        stats->rdpCount += hiveRdpCount;
    }
}

void EnumerateRDPHistory(RegistryStats* stats, const UserHive* hives, DWORD hiveCount) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] RDP Connection History:\n");

    if (hiveCount == 0) {
        RdpForHive(HKEY_CURRENT_USER, L"", L"current user (HKCU)", stats);
        return;
    }

    for (DWORD i = 0; i < hiveCount; i++) {
        RdpForHive(HKEY_USERS, hives[i].prefix, hives[i].account, stats);
    }
}

/* ------------------------------------------------------------------ */
/* Installed software (HKLM only)                                      */
/* ------------------------------------------------------------------ */

void EnumerateSoftware(RegistryStats* stats) {
    HKEY hKey;
    LONG result;
    DWORD index;
    WCHAR subKeyName[MAX_KEY_LENGTH];
    DWORD subKeyNameLen;
    const WCHAR* uninstallPaths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };
    int pathCount = 2;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Installed Software:\n");

    for (int p = 0; p < pathCount; p++) {
        result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, uninstallPaths[p], 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            continue;
        }

        index = 0;
        while (1) {
            subKeyNameLen = MAX_KEY_LENGTH;
            result = RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameLen,
                                   NULL, NULL, NULL, NULL);
            if (result == ERROR_NO_MORE_ITEMS) {
                break;
            }

            if (result == ERROR_SUCCESS) {
                HKEY hSubKey;
                WCHAR fullPath[512];
                _snwprintf(fullPath, sizeof(fullPath) / sizeof(WCHAR), L"%s\\%s", uninstallPaths[p], subKeyName);
                fullPath[511] = L'\0';

                result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hSubKey);
                if (result == ERROR_SUCCESS) {
                    BYTE* displayName = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_DATA);
                    if (!displayName) {
                        RegCloseKey(hSubKey);
                        index++;
                        continue;
                    }

                    DWORD displayNameLen = MAX_VALUE_DATA;
                    DWORD valueType;

                    result = RegQueryValueExW(hSubKey, L"DisplayName", NULL, &valueType,
                                              displayName, &displayNameLen);

                    if (result == ERROR_SUCCESS && valueType == REG_SZ && displayNameLen > 1) {
                        EnsureNullTerminatedW(displayName, MAX_VALUE_DATA, displayNameLen);

                        WCHAR version[256];
                        DWORD versionLen = sizeof(version);
                        DWORD versionType = 0;

                        if (RegQueryValueExW(hSubKey, L"DisplayVersion", NULL, &versionType, (BYTE*)version, &versionLen) == ERROR_SUCCESS &&
                            (versionType == REG_SZ || versionType == REG_EXPAND_SZ)) {
                            EnsureNullTerminatedW((BYTE*)version, sizeof(version), versionLen);
                            BeaconPrintf(CALLBACK_OUTPUT, "    [SW] %S (v%S)\n", (WCHAR*)displayName, version);
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "    [SW] %S\n", (WCHAR*)displayName);
                        }

                        stats->softwareCount++;
                    }

                    HeapFree(GetProcessHeap(), 0, displayName);
                    RegCloseKey(hSubKey);
                }
            }

            index++;
        }

        RegCloseKey(hKey);
    }

    if (stats->softwareCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] No software found (may require elevated privileges)\n");
    }
}

/* ------------------------------------------------------------------ */
/* Environment variables                                               */
/* ------------------------------------------------------------------ */

static void PrintEnvironmentKey(HKEY root, LPCWSTR path, LPCWSTR label, RegistryStats* stats) {
    HKEY hKey;
    LONG result;
    DWORD index;

    result = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
    if (result == ERROR_ACCESS_DENIED) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n    [%S Environment] access denied\n", label);
        return;
    }
    if (result != ERROR_SUCCESS) {
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n    [%S Environment]\n", label);

    WCHAR* valueName = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_NAME * sizeof(WCHAR));
    BYTE* valueData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUE_DATA);

    if (!valueName || !valueData) {
        if (valueName) HeapFree(GetProcessHeap(), 0, valueName);
        if (valueData) HeapFree(GetProcessHeap(), 0, valueData);
        RegCloseKey(hKey);
        return;
    }

    index = 0;
    while (1) {
        DWORD valueNameLen = MAX_VALUE_NAME;
        DWORD valueDataLen = MAX_VALUE_DATA;
        DWORD valueType;

        result = RegEnumValueW(hKey, index, valueName, &valueNameLen,
                               NULL, &valueType, valueData, &valueDataLen);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (result == ERROR_SUCCESS) {
            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                EnsureNullTerminatedW(valueData, MAX_VALUE_DATA, valueDataLen);

                WCHAR* valueStr = (WCHAR*)valueData;
                DWORD charLen = valueDataLen / sizeof(WCHAR);
                if (charLen > 200) {
                    valueStr[197] = L'.';
                    valueStr[198] = L'.';
                    valueStr[199] = L'.';
                    valueStr[200] = L'\0';
                }
                BeaconPrintf(CALLBACK_OUTPUT, "      %S = %S\n", valueName, valueStr);
                stats->envCount++;
            }
        }

        index++;
    }

    HeapFree(GetProcessHeap(), 0, valueName);
    HeapFree(GetProcessHeap(), 0, valueData);
    RegCloseKey(hKey);
}

void EnumerateEnvironmentVariables(RegistryStats* stats, const UserHive* hives, DWORD hiveCount) {
    WCHAR path[PATH_MAX_CHARS];

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Environment Variables:\n");

    PrintEnvironmentKey(HKEY_LOCAL_MACHINE,
                        L"System\\CurrentControlSet\\Control\\Session Manager\\Environment",
                        L"SYSTEM", stats);

    if (hiveCount == 0) {
        PrintEnvironmentKey(HKEY_CURRENT_USER, L"Environment", L"USER current user (HKCU)", stats);
    } else {
        for (DWORD i = 0; i < hiveCount; i++) {
            WCHAR label[ACCOUNT_MAX_CHARS + 8];
            _snwprintf(path, PATH_MAX_CHARS, L"%sEnvironment", hives[i].prefix);
            path[PATH_MAX_CHARS - 1] = L'\0';
            _snwprintf(label, ACCOUNT_MAX_CHARS + 8, L"USER %s", hives[i].account);
            label[ACCOUNT_MAX_CHARS + 7] = L'\0';
            PrintEnvironmentKey(HKEY_USERS, path, label, stats);
        }
    }

    if (stats->envCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] No environment variables found\n");
    }
}

/* ------------------------------------------------------------------ */
/* WSL / Docker                                                        */
/* ------------------------------------------------------------------ */

static BOOL WslForHive(HKEY root, LPCWSTR prefix, LPCWSTR label, RegistryStats* stats) {
    HKEY hKey;
    LONG result;
    WCHAR path[PATH_MAX_CHARS];

    _snwprintf(path, PATH_MAX_CHARS, L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\Lxss", prefix);
    path[PATH_MAX_CHARS - 1] = L'\0';

    result = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    [!] WSL detected for %S\n", label);
    stats->wslDetected++;

    DWORD index = 0;
    WCHAR distroGuid[MAX_KEY_LENGTH];
    DWORD distroGuidLen;

    while (1) {
        distroGuidLen = MAX_KEY_LENGTH;
        result = RegEnumKeyExW(hKey, index, distroGuid, &distroGuidLen, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (result == ERROR_SUCCESS) {
            HKEY hDistroKey;
            _snwprintf(path, PATH_MAX_CHARS,
                       L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\Lxss\\%s", prefix, distroGuid);
            path[PATH_MAX_CHARS - 1] = L'\0';

            if (RegOpenKeyExW(root, path, 0, KEY_READ, &hDistroKey) == ERROR_SUCCESS) {
                WCHAR distroName[256];
                DWORD distroNameLen = sizeof(distroName);

                if (RegQueryValueExW(hDistroKey, L"DistributionName", NULL, NULL, (BYTE*)distroName, &distroNameLen) == ERROR_SUCCESS) {
                    EnsureNullTerminatedW((BYTE*)distroName, sizeof(distroName), distroNameLen);
                    BeaconPrintf(CALLBACK_OUTPUT, "      [WSL] Distribution: %S\n", distroName);
                }

                RegCloseKey(hDistroKey);
            }
        }

        index++;
    }

    RegCloseKey(hKey);
    return TRUE;
}

void DetectWSLDocker(RegistryStats* stats, const UserHive* hives, DWORD hiveCount) {
    HKEY hKey;
    BOOL wslFound = FALSE;
    BOOL dockerFound = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] WSL/Docker Detection:\n");

    if (hiveCount == 0) {
        wslFound = WslForHive(HKEY_CURRENT_USER, L"", L"current user (HKCU)", stats);
    } else {
        for (DWORD i = 0; i < hiveCount; i++) {
            if (WslForHive(HKEY_USERS, hives[i].prefix, hives[i].account, stats)) {
                wslFound = TRUE;
            }
        }
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Docker Inc.\\Docker\\1.0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dockerFound = TRUE;
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Docker Desktop detected (HKLM\\Software\\Docker Inc.\\Docker\\1.0)\n");
        stats->wslDetected++;
        RegCloseKey(hKey);
    }

    if (!wslFound && !dockerFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] No WSL or Docker installations detected\n");
    }
}

#ifdef BOF
// BOF entry point
void go(char* args, int len) {
    datap parser;
    int intelTypeFlags = 0;
    RegistryStats stats;
    UserHive* hives = NULL;
    DWORD hiveCount = 0;

    memset(&stats, 0, sizeof(RegistryStats));

    // Parse arguments: intelTypeFlags (int)
    BeaconDataParse(&parser, args, len);
    if (len >= 4) {
        intelTypeFlags = BeaconDataInt(&parser);
    }

    if (intelTypeFlags == 0) {
        intelTypeFlags = INTEL_TYPE_ALL;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry Intel BOF\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Gathering: ");

    BOOL first = TRUE;
    if (intelTypeFlags & INTEL_TYPE_RDP) {
        BeaconPrintf(CALLBACK_OUTPUT, "RDP");
        first = FALSE;
    }
    if (intelTypeFlags & INTEL_TYPE_SOFTWARE) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "Software");
        first = FALSE;
    }
    if (intelTypeFlags & INTEL_TYPE_ENV) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "Environment");
        first = FALSE;
    }
    if (intelTypeFlags & INTEL_TYPE_WSL) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "WSL/Docker");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    // Per-user sections walk every loaded hive under HKEY_USERS.
    if (intelTypeFlags & (INTEL_TYPE_RDP | INTEL_TYPE_ENV | INTEL_TYPE_WSL)) {
        hives = (UserHive*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_USER_HIVES * sizeof(UserHive));
        if (hives) {
            hiveCount = CollectUserHives(hives, MAX_USER_HIVES);
        }

        if (hiveCount > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded user hives: %lu\n", hiveCount);
            for (DWORD i = 0; i < hiveCount; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "    %S (%S)\n", hives[i].account, hives[i].sid);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not enumerate HKEY_USERS, falling back to HKEY_CURRENT_USER\n");
        }
    }

    if (intelTypeFlags & INTEL_TYPE_RDP) {
        EnumerateRDPHistory(&stats, hives, hiveCount);
    }

    if (intelTypeFlags & INTEL_TYPE_SOFTWARE) {
        EnumerateSoftware(&stats);
    }

    if (intelTypeFlags & INTEL_TYPE_ENV) {
        EnumerateEnvironmentVariables(&stats, hives, hiveCount);
    }

    if (intelTypeFlags & INTEL_TYPE_WSL) {
        DetectWSLDocker(&stats, hives, hiveCount);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Summary:\n");
    if (intelTypeFlags & INTEL_TYPE_RDP) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   RDP Connections: %d\n", stats.rdpCount);
    }
    if (intelTypeFlags & INTEL_TYPE_SOFTWARE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Software Installed: %d\n", stats.softwareCount);
    }
    if (intelTypeFlags & INTEL_TYPE_ENV) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Environment Variables: %d\n", stats.envCount);
    }
    if (intelTypeFlags & INTEL_TYPE_WSL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   WSL/Docker Detected: %s\n", stats.wslDetected > 0 ? "Yes" : "No");
    }

    if (hives) {
        HeapFree(GetProcessHeap(), 0, hives);
    }
}

#else
// Test harness for local execution
#include <stdio.h>

int main(int argc, char** argv) {
    printf("Registry Intel BOF - Test Mode\n");
    printf("Compile with -DBOF for BOF mode\n");
    printf("Usage: enum-registry.exe <intel_type_flags>\n");
    printf("Example: enum-registry.exe 0xFF\n");
    return 0;
}
#endif
