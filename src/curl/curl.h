#pragma once

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

// MSVCRT
WINBASEAPI char * __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI void * __cdecl MSVCRT$memmove(void *dest, const void *src, size_t count);
WINBASEAPI char * __cdecl MSVCRT$strtok(char *str, const char *delim);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char *dest, const char *src);
WINBASEAPI void * __cdecl MSVCRT$calloc(size_t num, size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void *ptr);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *str);
WINBASEAPI void * __cdecl MSVCRT$memmove(void *dest, const void *src, size_t count);
WINBASEAPI void* __cdecl MSVCRT$realloc(void *ptr, size_t size);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscat(wchar_t *dest, const wchar_t *src);

// small custom memset implementation
void * __cdecl my_memset(void *dest, int ch, size_t count) {
    unsigned char *p = (unsigned char *)dest;
    for (size_t i = 0; i < count; i++) {
        p[i] = (unsigned char)ch;
    }
    return dest;
}

#define MSVCRT$memset my_memset
void *memset(void *dest, int ch, size_t count) {
    return my_memset(dest, ch, count);
}

// WINHTTP_QUERY_RAW_HEADERS_CRLF
#ifndef WINHTTP_QUERY_RAW_HEADERS_CRLF
#define WINHTTP_QUERY_RAW_HEADERS_CRLF 22
#endif

// Declare WinHttpQueryHeaders
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryHeaders(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPCWSTR   pwszName,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
);

// Declare WinHttpSetOption 
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSetOption(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
);
#ifndef WINHTTP_OPTION_REDIRECT_POLICY
#define WINHTTP_OPTION_REDIRECT_POLICY 131
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS
#define WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS 2
#endif
#ifndef WINHTTP_OPTION_SECURITY_FLAGS
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#endif


// Declare WideCharToMultiByte
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(
    UINT   CodePage,
    DWORD  dwFlags,
    LPCWSTR lpWideCharStr,
    int    cchWideChar,
    LPSTR  lpMultiByteStr,
    int    cbMultiByte,
    LPCSTR lpDefaultChar,
    LPBOOL lpUsedDefaultChar
);

// Declare MultiByteToWideChar
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(
    UINT   CodePage,
    DWORD  dwFlags,
    LPCSTR lpMultiByteStr,
    int    cbMultiByte,
    LPWSTR lpWideCharStr,
    int    cchWideChar
);

// CRYPT32 
WINBASEAPI DWORD WINAPI CRYPT32$CertGetNameStringA(
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    DWORD dwFlags,
    void *pvTypePara,
    LPSTR pszNameString,
    DWORD cchNameString
);
WINBASEAPI BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
#define CERT_NAME_SIMPLE_DISPLAY_TYPE 4
#define CERT_NAME_ISSUER_FLAG         0x1

// WINHTTP security flags for ignoring certificate errors
#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA        0x00000100
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  0x00000200
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

// WINHTTP
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpCrackUrl(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryOption(HINTERNET, DWORD, LPVOID, LPDWORD);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET, LPVOID, DWORD, LPDWORD);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);
#define WINHTTP_NO_ADDITIONAL_HEADERS NULL

// KERNEL32 
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

#define _stricmp KERNEL32$lstrcmpiA
