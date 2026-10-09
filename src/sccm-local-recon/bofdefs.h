/*
 * BOF Dynamic Function Resolution (DFR) Definitions
 * All Win32 API calls must go through these macros in BOF context.
 */
#ifndef _BOFDEFS_H_
#define _BOFDEFS_H_

#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <winldap.h>
#include <ntldap.h>

/* ========================================================================
 * Types missing from MinGW-w64 cross-compile headers.
 * Only define what windows.h/wincrypt.h/etc. don't already provide.
 * ======================================================================== */

/* --- LSA types (ntsecapi.h not fully in MinGW) --- */
typedef PVOID LSA_HANDLE;
typedef LSA_HANDLE* PLSA_HANDLE;
typedef UNICODE_STRING LSA_UNICODE_STRING;
typedef UNICODE_STRING* PLSA_UNICODE_STRING;

typedef struct _LSA_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

/* --- Domain Controller Info (lmds.h not always available) --- */
typedef struct _DOMAIN_CONTROLLER_INFOW {
    LPWSTR DomainControllerName;
    LPWSTR DomainControllerAddress;
    ULONG  DomainControllerAddressType;
    GUID   DomainGuid;
    LPWSTR DomainName;
    LPWSTR DnsForestName;
    ULONG  Flags;
    LPWSTR DcSiteName;
    LPWSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOW, *PDOMAIN_CONTROLLER_INFOW;

#ifndef DS_DIRECTORY_SERVICE_REQUIRED
#define DS_DIRECTORY_SERVICE_REQUIRED  0x00000010
#endif
#ifndef DS_RETURN_DNS_NAME
#define DS_RETURN_DNS_NAME             0x40000000
#endif

/* --- CALG constants for DPAPI (may not be in MinGW) --- */
#ifndef CALG_3DES
#define CALG_3DES          0x00006603
#endif
#ifndef CALG_3DES_112
#define CALG_3DES_112      0x00006609
#endif
#ifndef CALG_AES_128
#define CALG_AES_128       0x0000660e
#endif
#ifndef CALG_AES_192
#define CALG_AES_192       0x0000660f
#endif
#ifndef CALG_AES_256
#define CALG_AES_256       0x00006610
#endif
#ifndef CALG_SHA1
#define CALG_SHA1          0x00008004
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256       0x0000800c
#endif
#ifndef CALG_SHA_512
#define CALG_SHA_512       0x0000800e
#endif
#ifndef CALG_HMAC
#define CALG_HMAC          0x00008009
#endif
#ifndef CALG_MD4
#define CALG_MD4           0x00008002
#endif

/* --- BCrypt algorithm string constants --- */
#ifndef BCRYPT_SHA1_ALGORITHM
#define BCRYPT_SHA1_ALGORITHM     L"SHA1"
#define BCRYPT_SHA256_ALGORITHM   L"SHA256"
#define BCRYPT_SHA512_ALGORITHM   L"SHA512"
#define BCRYPT_MD4_ALGORITHM      L"MD4"
#define BCRYPT_MD5_ALGORITHM      L"MD5"
#define BCRYPT_AES_ALGORITHM      L"AES"
#define BCRYPT_3DES_ALGORITHM     L"3DES"
#define BCRYPT_CHAIN_MODE_CBC     L"ChainingModeCBC"
#define BCRYPT_CHAIN_MODE_ECB     L"ChainingModeECB"
#define BCRYPT_CHAIN_MODE_GCM     L"ChainingModeGCM"
#define BCRYPT_CHAINING_MODE      L"ChainingMode"
#define BCRYPT_OBJECT_LENGTH      L"ObjectLength"
#define BCRYPT_AUTH_TAG_LENGTH    L"AuthTagLength"
#endif

#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG  0x00000008
#endif

/* --- BCrypt handle types (if not defined via bcrypt.h) --- */
#ifndef BCRYPT_ALG_HANDLE
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;
typedef PVOID BCRYPT_HANDLE;
#endif

/* --- BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO for AES-GCM --- */
#ifndef BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
#define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION 1
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#endif

/* --- Security types --- */
#ifndef SECURITY_STATUS
typedef LONG SECURITY_STATUS;
#endif

/* --- NCrypt handle types --- */
#ifndef NCRYPT_PROV_HANDLE
typedef ULONG_PTR NCRYPT_HANDLE;
typedef ULONG_PTR NCRYPT_PROV_HANDLE;
typedef ULONG_PTR NCRYPT_KEY_HANDLE;
#endif

#ifdef BOF
/* ========================================================================
 * When compiling as a BOF, resolve functions dynamically.
 * Cobalt Strike resolves these at load time via the IAT.
 * ======================================================================== */

/* --- kernel32.dll --- */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void    WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlCopyMemory(PVOID, const VOID*, SIZE_T);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlFillMemory(PVOID, SIZE_T, BYTE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT void    WINAPI KERNEL32$Sleep(DWORD);

/* --- advapi32.dll --- */
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ULONG, PLSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaRetrievePrivateData(LSA_HANDLE, PLSA_UNICODE_STRING, PLSA_UNICODE_STRING*);
DECLSPEC_IMPORT ULONG   WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaClose(LSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaFreeMemory(PVOID);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$DuplicateToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryInfoKeyW(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$IsTextUnicode(const VOID*, int, LPINT);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT PDWORD  WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT PUCHAR  WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL*, LPBOOL);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);

/* --- ncrypt.dll --- */
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptImportKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptExportKey(NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptSetProperty(NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptFinalizeKey(NCRYPT_KEY_HANDLE, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptFreeObject(NCRYPT_HANDLE);

/* --- bcrypt.dll --- */
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptEncrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, ULONGLONG, PUCHAR, ULONG, ULONG);

/* --- crypt32.dll --- */
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT DWORD   WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);

/* --- cryptdll.dll --- */
DECLSPEC_IMPORT int     WINAPI CRYPTDLL$CDLocateCSystem(DWORD, void**);

/* --- netapi32.dll --- */
DECLSPEC_IMPORT DWORD   WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD   WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* --- wldap32.dll --- */
DECLSPEC_IMPORT LDAP*   LDAPAPI WLDAP32$ldap_initW(const PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_connect(LDAP*, struct l_timeval*);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_unbind_s(LDAP*);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWCHAR, PWCHAR, ULONG);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_search_ext_sW(LDAP*, PWCHAR, ULONG, PWCHAR, PWCHAR[], ULONG, PLDAPControlW*, PLDAPControlW*, struct l_timeval*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT struct berval** LDAPAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, const PWCHAR);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT PWCHAR  LDAPAPI WLDAP32$ldap_err2stringW(ULONG);
DECLSPEC_IMPORT VOID    LDAPAPI WLDAP32$ldap_memfreeW(PWCHAR);

/* --- shlwapi.dll --- */
DECLSPEC_IMPORT BOOL    WINAPI SHLWAPI$PathIsUNCW(LPCWSTR);

/* --- rpcrt4.dll --- */
DECLSPEC_IMPORT long    WINAPI RPCRT4$RpcStringBindingComposeW(wchar_t*, wchar_t*, wchar_t*, wchar_t*, wchar_t*, wchar_t**);
DECLSPEC_IMPORT long    WINAPI RPCRT4$RpcBindingFromStringBindingW(wchar_t*, void**);
DECLSPEC_IMPORT long    WINAPI RPCRT4$RpcStringFreeW(wchar_t**);
DECLSPEC_IMPORT long    WINAPI RPCRT4$RpcBindingFree(void**);
DECLSPEC_IMPORT long    WINAPI RPCRT4$RpcBindingSetAuthInfoExW(void*, wchar_t*, unsigned long, unsigned long, void*, unsigned long, RPC_SECURITY_QOS*);
DECLSPEC_IMPORT void*   __cdecl RPCRT4$NdrClientCall2(void*, void*, ...);

/* --- msvcrt.dll (CRT-like functions available in Windows) --- */
DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$printf(const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsncpy(wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcschr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memmove(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void    __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$atoi(const char*);
DECLSPEC_IMPORT long    __cdecl MSVCRT$strtol(const char*, char**, int);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$strtoul(const char*, char**, int);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strtok(char*, const char*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$tolower(int);
DECLSPEC_IMPORT int     __cdecl MSVCRT$toupper(int);
DECLSPEC_IMPORT int     __cdecl MSVCRT$isalpha(int);
DECLSPEC_IMPORT int     __cdecl MSVCRT$isdigit(int);
DECLSPEC_IMPORT int     __cdecl MSVCRT$isxdigit(int);

/* ========================================================================
 * Convenience macros — map standard names to DFR names
 * ======================================================================== */

/* Memory */
#define intAlloc(size)          KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)   KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size)
#define intFree(ptr)            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr)

/* String / memory functions via MSVCRT */
#define sprintf                 MSVCRT$sprintf
#define _snprintf               MSVCRT$_snprintf
#define swprintf                MSVCRT$swprintf
#define _snwprintf              MSVCRT$_snwprintf
#define strcmp                   MSVCRT$strcmp
#define wcscmp                  MSVCRT$wcscmp
#define _stricmp                MSVCRT$_stricmp
#define _wcsicmp                MSVCRT$_wcsicmp
#define strlen                  MSVCRT$strlen
#define wcslen                  MSVCRT$wcslen
#define strcpy                  MSVCRT$strcpy
#define wcscpy                  MSVCRT$wcscpy
#define strncpy                 MSVCRT$strncpy
#define wcsncpy                 MSVCRT$wcsncpy
#define strcat                  MSVCRT$strcat
#define wcscat                  MSVCRT$wcscat
#define strstr                  MSVCRT$strstr
#define wcsstr                  MSVCRT$wcsstr
#define strchr                  MSVCRT$strchr
#define wcschr                  MSVCRT$wcschr
#define memcpy                  MSVCRT$memcpy
#define memmove                 MSVCRT$memmove
#define memset                  MSVCRT$memset
#define memcmp                  MSVCRT$memcmp
#define calloc                  MSVCRT$calloc
#define malloc                  MSVCRT$malloc
#define realloc                 MSVCRT$realloc
#define free                    MSVCRT$free
#define atoi                    MSVCRT$atoi
#define strtol                  MSVCRT$strtol
#define strtoul                 MSVCRT$strtoul
#define strtok                  MSVCRT$strtok
#define sscanf                  MSVCRT$sscanf
#define tolower                 MSVCRT$tolower
#define toupper                 MSVCRT$toupper

#else
/* ========================================================================
 * Non-BOF compilation: use standard headers and linking
 * ======================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define intAlloc(size)          HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)   HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size)
#define intFree(ptr)            HeapFree(GetProcessHeap(), 0, ptr)

#endif /* BOF */

#endif /* _BOFDEFS_H_ */
