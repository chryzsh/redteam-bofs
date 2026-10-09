#ifdef _WIN64
// Minimal stub for stack probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include "beacon.h"
#include "curl.h"


// Default User-Agent (Microsoft Edge)
const char *DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0";

// Buffer size constants
#define MAX_TITLE_SIZE 256
#define MAX_HOSTNAME_SIZE 256
#define MAX_URLPATH_SIZE 512
#define HTTP_READ_BUFFER_SIZE 8192
#define STREAM_CHUNK_SIZE 1024
#define MAX_USER_AGENT_SIZE 512
#define MAX_URL_LENGTH 2048


/**
 * Removes surrounding double quotes from a wide string in-place.
 *
 * @param str Wide string to process (modified in-place)
 *
 * If the string starts and ends with double quotes, they are removed by:
 * 1. Null-terminating the position of the closing quote
 * 2. Moving the content (excluding opening quote) to the beginning
 */
void remove_quotes(wchar_t *str) {
    if (!str) return;
    size_t len = MSVCRT$wcslen(str);
    if (len > 1 && str[0] == L'"' && str[len - 1] == L'"') {
        str[len - 1] = L'\0';
        // Move (len - 1) characters to avoid reading past buffer
        MSVCRT$memmove(str, str + 1, (len - 1) * sizeof(wchar_t));
    }
}

/**
 * Converts a multi-byte (ANSI) string to wide character (Unicode) string.
 *
 * @param src Source multi-byte string (ANSI code page)
 * @param dest Destination wide character buffer
 * @param destSize Size of destination buffer in wide characters
 *
 * Uses Windows MultiByteToWideChar API for proper conversion including
 * extended ASCII and multi-byte sequences. Ensures null termination on failure.
 */
void convertToWideChar(const char *src, wchar_t *dest, size_t destSize) {
    if (!src || !dest || destSize == 0) return;

    // Use proper Windows API for character conversion
    // CP_ACP = ANSI code page, supports extended ASCII and multi-byte sequences
    int result = KERNEL32$MultiByteToWideChar(
        CP_ACP,           // Code page (ANSI)
        0,                // No special flags
        src,              // Source multi-byte string
        -1,               // Process entire null-terminated string
        dest,             // Destination wide-char buffer
        (int)destSize     // Size of destination buffer in wide chars
    );

    // Ensure null termination on failure
    if (result == 0 && destSize > 0) {
        dest[0] = L'\0';
    }
}


/**
 * Case-insensitive wide string comparison.
 *
 * @param s1 First wide string to compare
 * @param s2 Second wide string to compare
 * @return 0 if strings match (case-insensitive), non-zero otherwise
 *
 * Custom implementation to avoid linking issues with _wcsicmp.
 * Converts A-Z to lowercase for comparison (simple ASCII comparison).
 */
static int MyWcsICmp(const wchar_t *s1, const wchar_t *s2)
{
    while (*s1 && *s2) {
        wchar_t c1 = *s1++;
        wchar_t c2 = *s2++;
        // convert uppercase A-Z to lowercase
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2) {
            return (c1 - c2);
        }
    }
    return (*s1 - *s2);
}


/**
 * Extracts the page title from HTML content and adds it to the output buffer.
 *
 * @param html HTML content as null-terminated string
 * @param output Beacon format buffer to append output to
 *
 * Searches for <title>...</title> tags in the HTML and extracts the content.
 * Handles oversized titles by truncating to MAX_TITLE_SIZE.
 * Reports error if no title tags are found.
 */
void extract_title(const char *html, formatp *output) {
    const char *start = MSVCRT$strstr(html, "<title>");
    if (!start) {
        BeaconFormatPrintf(output, "[-] No <title> found.\n");
        return;
    }
    start += 7; // Skip "<title>"
    const char *end = MSVCRT$strstr(start, "</title>");
    if (!end) {
        BeaconFormatPrintf(output, "[-] No closing </title> found.\n");
        return;
    }
    char title[MAX_TITLE_SIZE];
    // Validate buffer size before calculating length to prevent overflow
    if (end < start || (size_t)(end - start) >= sizeof(title)) {
        size_t titleLen = sizeof(title) - 1;
        MSVCRT$memcpy(title, start, titleLen);
        title[titleLen] = '\0';
    } else {
        size_t titleLen = end - start;
        MSVCRT$memcpy(title, start, titleLen);
        title[titleLen] = '\0';
    }
    BeaconFormatPrintf(output, "[+] Page Title\t\t: %s\n", title);
}

/**
 * Extracts and displays TLS certificate information.
 *
 * @param pCertContext Pointer to certificate context from WinHTTP
 * @param output Beacon format buffer to append output to
 *
 * Extracts and displays:
 * - Certificate subject (CN)
 * - Certificate issuer
 * - Validity period (NotBefore and NotAfter dates)
 *
 * Reports error if certificate is NULL or information cannot be retrieved.
 */
void print_cert_info(PCCERT_CONTEXT pCertContext, formatp *output) {
    if (!pCertContext) {
        BeaconFormatPrintf(output, "[-] No certificate found.\n");
        return;
    }
    char subjectName[256] = {0};
    DWORD subjectSize = CRYPT32$CertGetNameStringA(
        pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
        subjectName, sizeof(subjectName)
    );
    if (subjectSize > 1)
        BeaconFormatPrintf(output, "[+] TLS Certificate Subject: %s\n", subjectName);
    char issuerName[256] = {0};
    DWORD issuerSize = CRYPT32$CertGetNameStringA(
        pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL,
        issuerName, sizeof(issuerName)
    );
    if (issuerSize > 1)
        BeaconFormatPrintf(output, "[+] TLS Certificate Issuer\t: %s\n", issuerName);
    SYSTEMTIME stNotBefore, stNotAfter;
    if (KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &stNotBefore) &&
        KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stNotAfter)) {
        BeaconFormatPrintf(output, "[+] Valid From\t\t: %02d/%02d/%04d\n",
            stNotBefore.wDay, stNotBefore.wMonth, stNotBefore.wYear);
        BeaconFormatPrintf(output, "[+] Valid Until\t\t: %02d/%02d/%04d\n",
            stNotAfter.wDay, stNotAfter.wMonth, stNotAfter.wYear);
    }
}


/**
 * Performs HTTP/HTTPS fingerprinting on a target URL.
 *
 * @param url Target URL (HTTP or HTTPS)
 * @param userAgent User-Agent string to use for the request
 *
 * Retrieves and displays:
 * - HTTP response headers
 * - TLS certificate information (for HTTPS)
 * - HTML page title
 *
 * Uses heap allocation for large buffers to avoid stack overflow.
 * Properly cleans up all WinHTTP handles and allocated memory.
 */
void doFinger(const wchar_t *url, const wchar_t *userAgent) {
    formatp output;
    BeaconFormatAlloc(&output, 4096);

    // Validate URL before parsing
    if (!url || MSVCRT$wcslen(url) == 0 || MSVCRT$wcslen(url) > MAX_URL_LENGTH) {
        BeaconFormatPrintf(&output, "[-] Invalid URL (null, empty, or too long).\n");
        goto out;
    }

    // Parse URL components.
    URL_COMPONENTS urlComp;
    MSVCRT$memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[MAX_HOSTNAME_SIZE] = {0};
    wchar_t urlPath[MAX_URLPATH_SIZE] = {0};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = MAX_HOSTNAME_SIZE;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = MAX_URLPATH_SIZE;

    if (!WINHTTP$WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        BeaconFormatPrintf(&output, "[-] Failed to parse URL.\n");
        goto out;
    }

    HINTERNET hSession = WINHTTP$WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconFormatPrintf(&output, "[-] WinHttpOpen failed.\n");
        goto out;
    }

    HINTERNET hConnect = WINHTTP$WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        BeaconFormatPrintf(&output, "[-] WinHttpConnect failed.\n");
        WINHTTP$WinHttpCloseHandle(hSession);
        goto out;
    }

    HINTERNET hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, NULL, NULL,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        BeaconFormatPrintf(&output, "[-] WinHttpOpenRequest failed.\n");
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        goto out;
    }

    // Ignore TLS certificate errors for HTTPS (self-signed, expired, wrong hostname)
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                       | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WINHTTP$WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        BeaconFormatPrintf(&output, "[-] WinHttpSendRequest failed (Error %lu).\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconFormatPrintf(&output, "[-] WinHttpReceiveResponse failed (Error %lu).\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    // Retrieve response headers dynamically
    {
        DWORD headerSize = 0;
        BOOL result = WINHTTP$WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &headerSize, NULL);

        if (!result && KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            BeaconFormatPrintf(&output, "[-] Failed to query header size (Error %lu).\n", KERNEL32$GetLastError());
            goto cleanup;
        }

        if (headerSize == 0) {
            BeaconFormatPrintf(&output, "[-] Headers size is unavailable.\n");
            goto cleanup;
        }

        // Allocate buffer dynamically based on required size
        wchar_t *wHeadersBuffer = (wchar_t *) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, headerSize);
        if (!wHeadersBuffer) {
            BeaconFormatPrintf(&output, "[-] Failed to allocate memory for headers.\n");
            goto cleanup;
        }

        if (WINHTTP$WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, wHeadersBuffer, &headerSize, NULL)) {
            DWORD convSize = KERNEL32$WideCharToMultiByte(CP_ACP, 0, wHeadersBuffer, -1, NULL, 0, NULL, NULL);
            if (convSize > 0) {
                char *aHeadersBuffer = (char *) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, convSize);
                if (aHeadersBuffer) {
                    KERNEL32$WideCharToMultiByte(CP_ACP, 0, wHeadersBuffer, -1, aHeadersBuffer, convSize, NULL, NULL);
                    BeaconFormatPrintf(&output, "[+] Response Headers:\n%s\n", aHeadersBuffer);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, aHeadersBuffer);
                } else {
                    BeaconFormatPrintf(&output, "[-] Failed to allocate memory for ANSI headers.\n");
                }
            } else {
                BeaconFormatPrintf(&output, "[-] Failed to convert headers to ANSI.\n");
            }
        } else {
            BeaconFormatPrintf(&output, "[-] Failed to retrieve headers (Error %lu)\n", KERNEL32$GetLastError());
        }

        // Free dynamically allocated memory
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, wHeadersBuffer);
    }

    // If HTTPS, query for the certificate
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        PCCERT_CONTEXT pCertContext = NULL;
        DWORD certSize = sizeof(pCertContext);
        if (WINHTTP$WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCertContext, &certSize)) {
            print_cert_info(pCertContext, &output);
            CRYPT32$CertFreeCertificateContext(pCertContext);
        } else {
            BeaconFormatPrintf(&output, "[-] Failed to retrieve TLS certificate.\n");
        }
    }

    // Read HTML and extract <title>
    // Use heap allocation for large buffer to avoid stack overflow
    {
        const DWORD bufferSize = HTTP_READ_BUFFER_SIZE;
        char *buffer = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer) {
            BeaconFormatPrintf(&output, "[-] Failed to allocate buffer for HTML data.\n");
        } else {
            DWORD bytesRead = 0;
            if (WINHTTP$WinHttpReadData(hRequest, buffer, bufferSize - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                extract_title(buffer, &output);
            } else {
                BeaconFormatPrintf(&output, "[-] Failed to read HTML data.\n");
            }
            // Free heap-allocated buffer
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
        }
    }

cleanup:
    WINHTTP$WinHttpCloseHandle(hRequest);
    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hSession);

out:
    int outSize = 0;
    char *outStr = BeaconFormatToString(&output, &outSize);
    BeaconOutput(CALLBACK_OUTPUT, outStr, outSize);
    BeaconFormatFree(&output);
}



/**
 * Fetches and displays the raw content from a URL.
 *
 * @param url Target URL (HTTP or HTTPS)
 * @param userAgent User-Agent string to use for the request
 *
 * Performs an HTTP GET request and streams the response content directly
 * to the beacon output in STREAM_CHUNK_SIZE (1024 byte) chunks.
 *
 * Follows redirects automatically via WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS.
 * Properly cleans up all WinHTTP handles before returning.
 */
void doPrint(const wchar_t *url, const wchar_t *userAgent) {
    HINTERNET hSession, hConnect, hRequest;
    URL_COMPONENTS urlComp;
    wchar_t hostName[MAX_HOSTNAME_SIZE] = {0}, urlPath[MAX_URLPATH_SIZE] = {0};

    // Validate URL before parsing
    if (!url || MSVCRT$wcslen(url) == 0 || MSVCRT$wcslen(url) > MAX_URL_LENGTH) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Invalid URL (null, empty, or too long).\n");
        return;
    }

    MSVCRT$memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = MAX_HOSTNAME_SIZE;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = MAX_URLPATH_SIZE;
    if (!WINHTTP$WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to parse URL.\n");
        return;
    }

    hSession = WINHTTP$WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpOpen failed.\n");
        return;
    }

    // Optionally set redirection if needed
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WINHTTP$WinHttpSetOption(hSession, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    hConnect = WINHTTP$WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpConnect failed.\n");
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, NULL, NULL,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpOpenRequest failed.\n");
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    // Ignore TLS certificate errors for HTTPS (self-signed, expired, wrong hostname)
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                       | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WINHTTP$WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    if (!WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpSendRequest failed (Error %lu).\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] WinHttpReceiveResponse failed (Error %lu).\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        return;
    }

    // Stream response in fixed-size chunks
    char szBuffer[STREAM_CHUNK_SIZE];
    DWORD dwRead = 0;
    while (WINHTTP$WinHttpReadData(hRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead > 0) {
        szBuffer[dwRead] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "%s", szBuffer);
        dwRead = 0;
    }

    WINHTTP$WinHttpCloseHandle(hRequest);
    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hSession);

}



/**
 * BOF Entry Point: curl
 *
 * Performs HTTP/HTTPS requests for fingerprinting and content retrieval.
 *
 * Commands:
 *   - finger: Retrieve TLS certificate, response headers, and page title
 *   - print:  Fetch and display raw page content
 *
 * Arguments:
 *   @param args Packed argument data from Beacon
 *   @param length Length of packed argument data
 *
 * Expected argument format: <command> <url> [user-agent tokens...]
 *   - command: "finger" or "print"
 *   - url: Target URL (HTTP or HTTPS)
 *   - user-agent: Optional user-agent string (space-separated tokens)
 *                 If not provided, uses DEFAULT_USER_AGENT
 *
 * Example usage:
 *   curl finger https://example.com
 *   curl print https://example.com Mozilla/5.0 Custom Agent
 */
void go(char *args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);

    // Extract arguments
    wchar_t *cmd = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *urlArg = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *uaArg = NULL;
    wchar_t *uaArgAllocated = NULL;  // Track if we allocated memory
    size_t uaLength = 0;
    wchar_t *temp = NULL;
    wchar_t wDefaultUA[MAX_USER_AGENT_SIZE];

    // Rebuild the user-agent from remaining arguments
    while ((temp = (wchar_t *)BeaconDataExtract(&parser, NULL)) != NULL) {
        size_t tempLen = MSVCRT$wcslen(temp);
        if (!uaArgAllocated) {
            uaArgAllocated = (wchar_t *)MSVCRT$calloc(tempLen + 1, sizeof(wchar_t));
            if (!uaArgAllocated) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed for user-agent");
                return;
            }
            uaArg = uaArgAllocated;
        } else {
            wchar_t *newUaArg = (wchar_t *)MSVCRT$realloc(uaArgAllocated, (uaLength + tempLen + 2) * sizeof(wchar_t));
            if (!newUaArg) {
                MSVCRT$free(uaArgAllocated);
                BeaconPrintf(CALLBACK_ERROR, "[-] Memory reallocation failed for user-agent");
                return;
            }
            uaArgAllocated = newUaArg;
            uaArg = uaArgAllocated;
            MSVCRT$wcscat(uaArg, L" ");
        }
        MSVCRT$wcscat(uaArg, temp);
        uaLength += tempLen + 1;
    }

    if (!cmd || !urlArg) {
        if (uaArgAllocated) MSVCRT$free(uaArgAllocated);
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing required arguments: <command> <url> [user-agent]");
        return;
    }

    // Remove surrounding quotes from URL and User-Agent (internally)
    remove_quotes(urlArg);
    if (uaArg) {
        remove_quotes(uaArg);
    }

    // Use default user-agent if not provided or empty
    if (!uaArg || MSVCRT$wcslen(uaArg) == 0) {
        convertToWideChar(DEFAULT_USER_AGENT, wDefaultUA, MAX_USER_AGENT_SIZE);
        uaArg = wDefaultUA;
    }

    if (MyWcsICmp(cmd, L"finger") == 0) {
        doFinger(urlArg, uaArg);
    } else if (MyWcsICmp(cmd, L"print") == 0) {
        doPrint(urlArg, uaArg);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown command: %ls", cmd);
    }

    // Free dynamically allocated user-agent string
    if (uaArgAllocated) {
        MSVCRT$free(uaArgAllocated);
    }
}
