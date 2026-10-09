/*
 * sccm-local-recon BOF — SCCM RECON-7 local client enumeration
 *
 * Enumerates SCCM local client paths (logs, ccmcache, ccmsetup), lists the
 * client cache with per-user read/write permissions, reads the ManagementPoints
 * registry value, and scrapes the CCM logs for candidate UNC paths and URLs.
 * Runs in the current user's context (no SYSTEM impersonation).
 *
 * Self-contained port of sccm-bofs (src/bofs/sccm_recon.c +
 * src/common/sccm_recon_local.c + the shared file/registry helpers it uses).
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

typedef void (*FILE_CALLBACK)(const wchar_t* full_path, void* ctx);

typedef struct {
    char** items;
    int count;
    int capacity;
} STRING_LIST;

typedef struct {
    BOOL urls;
    BOOL uncs;
} LOG_SCAN_MODE;

/* ========================================================================
 * Shared helpers
 * ======================================================================== */

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

static BOOL get_reg_key_value(HKEY root, const wchar_t* path, const wchar_t* name,
                              BYTE** out_data, DWORD* out_len) {
    HKEY hKey = NULL;
    LONG status;
    DWORD type = 0, size = 0;

    if (!out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;

#ifdef BOF
    status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#else
    status = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#endif
    if (status != ERROR_SUCCESS) return FALSE;

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#endif
    if (status != ERROR_SUCCESS || size == 0) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

    BYTE* data = (BYTE*)intAlloc(size);
    if (!data) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    ADVAPI32$RegCloseKey(hKey);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    RegCloseKey(hKey);
#endif

    if (status != ERROR_SUCCESS) {
        intFree(data);
        return FALSE;
    }

    *out_data = data;
    *out_len = size;
    return TRUE;
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

static void concat_wstr(wchar_t* out, int out_cap, const wchar_t* prefix, const wchar_t* suffix) {
    int plen;
    int slen;

    if (!out || out_cap <= 0) return;
    plen = (prefix && *prefix) ? (int)wcslen(prefix) : 0;
    slen = (suffix && *suffix) ? (int)wcslen(suffix) : 0;

    if (plen + 1 >= out_cap) { out[0] = L'\0'; return; }
    memcpy(out, prefix, plen * sizeof(wchar_t));
    out[plen] = L'\\';

    int scopy = slen;
    int avail = out_cap - plen - 2;
    if (scopy > avail) scopy = avail;
    if (scopy < 0) scopy = 0;
    memcpy(out + plen + 1, suffix, scopy * sizeof(wchar_t));
    out[plen + 1 + scopy] = L'\0';
}

/* ========================================================================
 * File enumeration
 * ======================================================================== */
static void enumerate_files(const wchar_t* dir, const wchar_t* pattern,
                            FILE_CALLBACK callback, void* ctx) {
    wchar_t search[MAX_PATH * 2];
    concat_wstr(search, (int)(sizeof(search) / sizeof(wchar_t)), dir, pattern ? pattern : L"*");

    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        concat_wstr(full_path, (int)(sizeof(full_path) / sizeof(wchar_t)), dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        concat_wstr(full_path, (int)(sizeof(full_path) / sizeof(wchar_t)), dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

/* ========================================================================
 * String list
 * ======================================================================== */

static void string_list_init(STRING_LIST* list) {
    if (!list) return;
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void string_list_free(STRING_LIST* list) {
    if (!list) return;
    if (list->items) {
        for (int i = 0; i < list->count; i++) {
            if (list->items[i]) intFree(list->items[i]);
        }
        intFree(list->items);
    }
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static BOOL string_list_contains(const STRING_LIST* list, const char* value) {
    if (!list || !value) return FALSE;
    for (int i = 0; i < list->count; i++) {
        if (list->items[i] && strcmp(list->items[i], value) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL string_list_add_unique(STRING_LIST* list, const char* value) {
    char** new_items;
    char* copy;
    int new_capacity;

    if (!list || !value || value[0] == '\0') return FALSE;
    if (string_list_contains(list, value)) return TRUE;

    if (list->count == list->capacity) {
        new_capacity = (list->capacity == 0) ? 8 : (list->capacity * 2);
        new_items = (char**)intAlloc(sizeof(char*) * new_capacity);
        if (!new_items) return FALSE;
        memset(new_items, 0, sizeof(char*) * new_capacity);
        if (list->items && list->count > 0) {
            memcpy(new_items, list->items, sizeof(char*) * list->count);
            intFree(list->items);
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    copy = (char*)intAlloc(strlen(value) + 1);
    if (!copy) return FALSE;
    strcpy(copy, value);
    list->items[list->count++] = copy;
    return TRUE;
}

/* ========================================================================
 * Log token collection
 * ======================================================================== */

static void trim_log_token(char* value) {
    int len;

    if (!value) return;
    len = (int)strlen(value);
    while (len > 0) {
        char c = value[len - 1];
        if (c == '.' || c == ',' || c == ';' || c == ':' ||
            c == ')' || c == ']' || c == '}' || c == '"' ||
            c == '\'' || c == '>') {
            value[--len] = '\0';
            continue;
        }
        break;
    }
}

static BOOL is_log_delim(char c) {
    return (c == '\0' || c == '\r' || c == '\n' || c == '\t' || c == ' ' ||
            c == '"' || c == '\'' || c == '<' || c == '>' || c == '(' || c == ')');
}

static void collect_url_tokens(const char* text, STRING_LIST* matches) {
    const char* prefixes[] = { "http://", "https://" };
    int text_len;

    if (!text || !matches) return;
    text_len = (int)strlen(text);

    for (int p = 0; p < 2; p++) {
        const char* prefix = prefixes[p];
        int prefix_len = (int)strlen(prefix);

        for (int i = 0; i < text_len; i++) {
            int j;
            int len;
            char* token;

            if (i + prefix_len > text_len) break;
            if (memcmp(text + i, prefix, prefix_len) != 0) continue;
            j = i + prefix_len;
            while (!is_log_delim(text[j])) j++;
            len = j - i;
            if (len < prefix_len + 3 || len > 2048) continue;

            token = extract_ascii((const BYTE*)text, i, j);
            if (!token) continue;
            trim_log_token(token);
            if (strchr(token + prefix_len, '.')) {
                string_list_add_unique(matches, token);
            }
            intFree(token);
            i = j;
        }
    }
}

static void collect_unc_tokens(const char* text, STRING_LIST* matches) {
    if (!text || !matches) return;

    for (int i = 0; text[i] != '\0'; i++) {
        int j;
        int len;
        char* token;

        if (!(text[i] == '\\' && text[i + 1] == '\\')) continue;

        j = i + 2;
        while (!is_log_delim(text[j])) j++;
        len = j - i;
        if (len < 5 || len > 2048) continue;

        token = extract_ascii((const BYTE*)text, i, j);
        if (!token) continue;
        trim_log_token(token);
        if (strchr(token + 2, '\\')) {
            string_list_add_unique(matches, token);
        }
        intFree(token);
        i = j;
    }
}

static void search_log_file_cb(const wchar_t* full_path, void* ctx) {
    BYTE* data = NULL;
    int data_len = 0;
    char* path_utf8 = NULL;
    char* text = NULL;
    STRING_LIST matches;
    LOG_SCAN_MODE* mode = (LOG_SCAN_MODE*)ctx;

    string_list_init(&matches);

    if (!mode) goto cleanup;
    if (!read_file_bytes(full_path, &data, &data_len)) goto cleanup;
    if (data_len <= 0 || data_len > (8 * 1024 * 1024)) goto cleanup;

    text = (char*)intAlloc(data_len + 1);
    if (!text) goto cleanup;
    memcpy(text, data, data_len);
    text[data_len] = '\0';

    if (mode->urls) collect_url_tokens(text, &matches);
    if (mode->uncs) collect_unc_tokens(text, &matches);

    if (matches.count > 0) {
        path_utf8 = wide_to_utf8(full_path);
        BeaconPrintf(CALLBACK_OUTPUT, "    Found match in %s\n", path_utf8 ? path_utf8 : "?");
        for (int i = 0; i < matches.count; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", matches.items[i]);
        }
    }

cleanup:
    if (path_utf8) intFree(path_utf8);
    if (text) intFree(text);
    if (data) intFree(data);
    string_list_free(&matches);
}

/* ========================================================================
 * Path access and directory listing
 * ======================================================================== */

static void probe_path_access(const wchar_t* path, BOOL is_dir, BOOL* can_read, BOOL* can_write) {
    DWORD read_access = is_dir ? FILE_LIST_DIRECTORY : GENERIC_READ;
    DWORD write_access = is_dir ? FILE_ADD_FILE : GENERIC_WRITE;
    DWORD flags = is_dir ? FILE_FLAG_BACKUP_SEMANTICS : 0;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (can_read) *can_read = FALSE;
    if (can_write) *can_write = FALSE;

#ifdef BOF
    h = KERNEL32$CreateFileW(path, read_access,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        if (can_read) *can_read = TRUE;
        KERNEL32$CloseHandle(h);
    }

    h = KERNEL32$CreateFileW(path, write_access,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        if (can_write) *can_write = TRUE;
        KERNEL32$CloseHandle(h);
    }
#else
    h = CreateFileW(path, read_access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        if (can_read) *can_read = TRUE;
        CloseHandle(h);
    }

    h = CreateFileW(path, write_access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        if (can_write) *can_write = TRUE;
        CloseHandle(h);
    }
#endif
}

static void format_access_string(BOOL is_dir, BOOL can_read, BOOL can_write, char out[4]) {
    if (!out) return;
    out[0] = is_dir ? 'd' : '-';
    out[1] = can_read ? 'r' : '-';
    out[2] = can_write ? 'w' : '-';
    out[3] = '\0';
}

static char* format_short_size(ULONGLONG size) {
    static const char* suffixes[] = { "B", "KB", "MB", "GB", "TB" };
    double value = (double)size;
    int suffix = 0;
    char* out;

    while (value >= 1024.0 && suffix < 4) {
        value /= 1024.0;
        suffix++;
    }

    out = (char*)intAlloc(32);
    if (!out) return NULL;
    sprintf(out, "%.1f%s", value, suffixes[suffix]);
    return out;
}

static void print_dir_entry(const wchar_t* full_path, const WIN32_FIND_DATAW* ffd) {
    BOOL can_read = FALSE;
    BOOL can_write = FALSE;
    BOOL is_dir;
    char perms[4];
    char* size_text = NULL;
    char* path_utf8 = NULL;
    ULONGLONG size = 0;

    if (!full_path || !ffd) return;

    is_dir = ((ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    probe_path_access(full_path, is_dir, &can_read, &can_write);
    format_access_string(is_dir, can_read, can_write, perms);

    if (!is_dir) {
        size = (((ULONGLONG)ffd->nFileSizeHigh) << 32) | ffd->nFileSizeLow;
        size_text = format_short_size(size);
    }

    path_utf8 = wide_to_utf8(full_path);
    BeaconPrintf(CALLBACK_OUTPUT, "    %s  %8s  %s\n",
                 perms,
                 is_dir ? "" : (size_text ? size_text : "?"),
                 path_utf8 ? path_utf8 : "?");

    if (size_text) intFree(size_text);
    if (path_utf8) intFree(path_utf8);
}

static void list_dir_tree(const wchar_t* dir_path, int max_depth, int depth) {
    wchar_t search[MAX_PATH * 2];
    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

    if (!dir_path || depth > max_depth) return;

    concat_wstr(search, (int)(sizeof(search) / sizeof(wchar_t)), dir_path, L"*");

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        wchar_t full_path[MAX_PATH * 2];
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;
        concat_wstr(full_path, (int)(sizeof(full_path) / sizeof(wchar_t)), dir_path, ffd.cFileName);
        print_dir_entry(full_path, &ffd);
        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && depth < max_depth) {
            list_dir_tree(full_path, max_depth, depth + 1);
        }
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        wchar_t full_path[MAX_PATH * 2];
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;
        concat_wstr(full_path, (int)(sizeof(full_path) / sizeof(wchar_t)), dir_path, ffd.cFileName);
        print_dir_entry(full_path, &ffd);
        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && depth < max_depth) {
            list_dir_tree(full_path, max_depth, depth + 1);
        }
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

static void print_path_summary(const wchar_t* path) {
    WIN32_FIND_DATAW ffd;
    HANDLE hFind;
    BOOL can_read = FALSE;
    BOOL can_write = FALSE;
    BOOL exists = FALSE;
    BOOL is_dir = FALSE;
    char perms[4];
    char* path_utf8 = NULL;

    if (!path) return;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(path, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        exists = TRUE;
        is_dir = ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        KERNEL32$FindClose(hFind);
    }
#else
    hFind = FindFirstFileW(path, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        exists = TRUE;
        is_dir = ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        FindClose(hFind);
    }
#endif

    path_utf8 = wide_to_utf8(path);
    if (!exists) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] %s does not exist\n", path_utf8 ? path_utf8 : "?");
        if (path_utf8) intFree(path_utf8);
        return;
    }

    probe_path_access(path, is_dir, &can_read, &can_write);
    format_access_string(is_dir, can_read, can_write, perms);
    BeaconPrintf(CALLBACK_OUTPUT, "    %s  %s\n", perms, path_utf8 ? path_utf8 : "?");
    if (path_utf8) intFree(path_utf8);
}

static void print_registry_management_points(void) {
    static const wchar_t reg_path[] = L"SOFTWARE\\Microsoft\\SMS\\DP";
    static const wchar_t reg_name[] = L"ManagementPoints";
    BYTE* data = NULL;
    DWORD data_len = 0;
    const wchar_t* current;
    int printed = 0;

    if (!get_reg_key_value(HKEY_LOCAL_MACHINE, reg_path, reg_name, &data, &data_len) ||
        !data || data_len < sizeof(wchar_t)) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] Registry ManagementPoints value was not present at HKLM\\%S\\%S\n",
                     reg_path, reg_name);
        if (data) intFree(data);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Registry ManagementPoints:\n");
    current = (const wchar_t*)data;
    while (((BYTE*)current) < (data + data_len) && *current != L'\0') {
        char* utf8 = wide_to_utf8(current);
        if (utf8 && utf8[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", utf8);
            printed++;
        }
        if (utf8) intFree(utf8);
        current += wcslen(current) + 1;
    }

    if (printed == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    <empty>\n");
    }

    intFree(data);
}

/* ========================================================================
 * Entry point
 * ======================================================================== */

static BOOL triage_sccm_recon(void) {
    static const wchar_t logs_dir[] = L"C:\\Windows\\CCM\\Logs";
    static const wchar_t cache_dir[] = L"C:\\Windows\\ccmcache";
    static const wchar_t setup_dir[] = L"C:\\Windows\\ccmsetup";
    LOG_SCAN_MODE unc_mode;
    LOG_SCAN_MODE url_mode;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM local paths:\n");
    print_path_summary(logs_dir);
    print_path_summary(cache_dir);
    print_path_summary(setup_dir);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Client cache contents and permissions for the current user:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Perms      Size  Name\n");
    list_dir_tree(cache_dir, 2, 0);

    print_registry_management_points();

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Searching logs for possible UNC paths:\n");
    unc_mode.urls = FALSE;
    unc_mode.uncs = TRUE;
    enumerate_files(logs_dir, L"*", search_log_file_cb, &unc_mode);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Searching logs for possible URLs:\n");
    url_mode.urls = TRUE;
    url_mode.uncs = FALSE;
    enumerate_files(logs_dir, L"*", search_log_file_cb, &url_mode);

    return TRUE;
}

#ifdef BOF
void go(char* args, int args_len) {
    if (args_len > 0) {
        datap parser;
        BeaconDataParse(&parser, args, args_len);
        char* unused = BeaconDataExtract(&parser, NULL);
        if (unused && strlen(unused) > 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Usage: sccm-local-recon (no arguments)\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM RECON-7 (BOF) ===\n");
    triage_sccm_recon();
}
#else
int main(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM RECON-7 (BOF) ===\n");
    triage_sccm_recon();
    return 0;
}
#endif
