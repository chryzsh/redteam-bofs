#include <windows.h>
#include <lm.h>
#include "beacon.h"

// Output buffering (based on TrustedSec BOF print pattern)
#ifndef bufsize
#define bufsize 8192
#endif
static char *output = NULL;
static WORD currentoutsize = 0;

static int bofstart() {
    output = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    if (output == NULL) return 0;
    currentoutsize = 0;
    return 1;
}

static void printoutput(BOOL done) {
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if (done) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, output);
        output = NULL;
    }
}

static void internal_printf(const char* format, ...) {
    int buffersize = 0;
    int transfersize = 0;
    char *curloc = NULL;
    char *intBuffer = NULL;
    va_list args;

    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1) return;

    intBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);
    if (intBuffer == NULL) return;

    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);

    if (buffersize + currentoutsize < bufsize) {
        MSVCRT$memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while (buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize) {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize) {
                printoutput(FALSE);
            }
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, intBuffer);
}


static void listShares(wchar_t *servername) {
    PSHARE_INFO_1 pShareInfo = NULL;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    internal_printf("\n\nListing shares for: %ls\n", servername);
    internal_printf("=====================================================\n");

    do {
        nStatus = NETAPI32$NetShareEnum(servername, 1, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                internal_printf("Share Name: %-10ls <- ", pShareInfo[i].shi1_netname);

                if (KERNEL32$lstrcmpW(pShareInfo[i].shi1_netname, L"IPC$") == 0) {
                    internal_printf("[!] No file system access\n");
                    continue;
                }

                wchar_t fullPath[MAX_PATH];
                WIN32_FIND_DATAW findData;
                HANDLE hFind;
                MSVCRT$_snwprintf(fullPath, MAX_PATH - 1, L"\\\\%s\\%s\\*",
                    servername ? servername : L"localhost",
                    pShareInfo[i].shi1_netname);
                fullPath[MAX_PATH - 1] = L'\0';

                hFind = KERNEL32$FindFirstFileW(fullPath, &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    internal_printf("[+] Accessible\n");
                    KERNEL32$FindClose(hFind);
                } else {
                    internal_printf("[-] Access denied\n");
                }
            }

            NETAPI32$NetApiBufferFree(pShareInfo);
            pShareInfo = NULL;
        } else {
            if (nStatus == ERROR_BAD_NETPATH) {
                internal_printf("Connection error: ERROR_BAD_NETPATH\n");
            } else if (nStatus == ERROR_ACCESS_DENIED) {
                internal_printf("Connection error: ERROR_ACCESS_DENIED\n");
            } else {
                internal_printf("Connection error code: %d\n", nStatus);
            }
            break;
        }
    } while (nStatus == ERROR_MORE_DATA);
}

int go(char *args, int len) {
    char *inlineHost;
    int iHostLen = 0;
    char *hostFileBytes;
    int iBytesLen = 0;
    char *hostname;
    char *nextHostname;
    WCHAR wHostname[MAX_PATH];
    datap parser;

    BeaconDataParse(&parser, args, len);
    inlineHost = BeaconDataExtract(&parser, &iHostLen);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
    if (!bofstart()) return 0;

    if (iHostLen > 1) {
        // Inline single-hostname mode
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, inlineHost, -1, wHostname, MAX_PATH);
        listShares(wHostname);
        printoutput(TRUE);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished enumerating!\n");
    } else if (iBytesLen != 0) {
        // File-upload multi-host mode
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded hostname file in memory with a size of %d bytes\n", iBytesLen);

        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
        while (hostname != NULL) {
            nextHostname = MSVCRT$strtok(NULL, "\r\n");

            KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, MAX_PATH);
            listShares(wHostname);
            hostname = nextHostname;

            if (nextHostname == NULL) {
                break;
            }
        }
        printoutput(TRUE);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished enumerating!\n");
    } else {
        printoutput(TRUE);
        BeaconPrintf(CALLBACK_ERROR, "No hostname or hostnames file provided.\n");
    }

    return 0;
}
