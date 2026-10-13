#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include "beacon.h"

// Queries in flight at once. WaitForMultipleObjects caps this at 64.
#define MAX_INFLIGHT   64
// A query older than this is cancelled and counted as timed out.
#define QUERY_TIMEOUT  5000
// How long a cancelled query gets to call back before its slot is abandoned.
#define CANCEL_GRACE   10000
#define MAX_NAME       256

#ifndef DNS_REQUEST_PENDING
#define DNS_REQUEST_PENDING 9506L
#endif

// mingw-w64 windns.h does not ship the DnsQueryEx types, so declare them here.
typedef struct {
    CHAR  MaxSa[32];
    DWORD DnsAddrUserDword[8];
} BOF_DNS_ADDR;

typedef struct {
    DWORD MaxCount;
    DWORD AddrCount;
    DWORD Tag;
    WORD  Family;
    WORD  WordReserved;
    DWORD Flags;
    DWORD MatchFlag;
    DWORD Reserved1;
    DWORD Reserved2;
    BOF_DNS_ADDR AddrArray[1];
} BOF_DNS_ADDR_ARRAY;

typedef struct {
    ULONG   Version;
    PCWSTR  QueryName;
    WORD    QueryType;
    ULONG64 QueryOptions;
    BOF_DNS_ADDR_ARRAY *pDnsServerList;
    ULONG   InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE pQueryCompletionCallback;
    PVOID   pQueryContext;
} BOF_DNS_QUERY_REQUEST;

typedef struct {
    CHAR Reserved[32];
} BOF_DNS_QUERY_CANCEL;

/* DNSAPI */
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQueryEx(BOF_DNS_QUERY_REQUEST *pQueryRequest, PDNS_QUERY_RESULT pQueryResults, BOF_DNS_QUERY_CANCEL *pCancelHandle);
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsCancelQuery(BOF_DNS_QUERY_CANCEL *pCancelHandle);
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree(PVOID pData, DNS_FREE_TYPE FreeType);

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetEvent(HANDLE hEvent);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ResetEvent(HANDLE hEvent);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

/* WS2_32 */
DECLSPEC_IMPORT INT WSAAPI WS2_32$inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short hostshort);

/* MSVCRT */
DECLSPEC_IMPORT int __cdecl MSVCRT$vsnprintf(char *buffer, size_t count, const char *format, va_list arg);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);

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


typedef struct {
    BOF_DNS_QUERY_REQUEST request;
    DNS_QUERY_RESULT      result;
    BOF_DNS_QUERY_CANCEL  cancel;
    HANDLE      event;
    char       *name;
    WCHAR       wname[MAX_NAME];
    DWORD       started;
    BOOL        busy;
    BOOL        cancelled;
    BOOL        abandoned;
    DNS_STATUS  status;
    PDNS_RECORD records;
} query_slot;

typedef struct {
    DWORD resolved;
    DWORD notfound;
    DWORD timedout;
    DWORD failed;
} query_stats;

// Runs on a DNS client thread pool thread. Only record the result and signal;
// Beacon output functions must stay on the BOF thread.
static VOID WINAPI query_done(PVOID context, PDNS_QUERY_RESULT result) {
    query_slot *slot = (query_slot*)context;
    slot->status = result->QueryStatus;
    slot->records = result->pQueryRecords;
    KERNEL32$SetEvent(slot->event);
}

// Returns the first whitespace-separated token of the next non-empty line,
// NUL-terminated in place, or NULL at the end of the buffer. The rest of the
// line is ignored, so lines like "host 10.0.0.1" also work.
static char *next_host(char **cursor) {
    char *p = *cursor;
    char *start;
    char *end;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == '\0') {
        *cursor = p;
        return NULL;
    }

    start = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
    end = p;
    while (*p && *p != '\n') p++;
    if (*p) p++;
    *end = '\0';

    *cursor = p;
    return start;
}

static void report(query_slot *slot, query_stats *stats) {
    PDNS_RECORD rec;
    DWORD count = 0;

    if (slot->cancelled) {
        stats->timedout++;
    } else if (slot->status == ERROR_SUCCESS) {
        // One line per host: "name<TAB>ip[,ip...]"
        for (rec = slot->records; rec != NULL; rec = rec->pNext) {
            if (rec->wType != DNS_TYPE_A) continue;
            DWORD ip = rec->Data.A.IpAddress;
            if (count == 0) {
                internal_printf("%s\t", slot->name);
            } else {
                internal_printf(",");
            }
            internal_printf("%lu.%lu.%lu.%lu",
                ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
            count++;
        }
        if (count > 0) {
            internal_printf("\n");
            stats->resolved++;
        } else {
            stats->notfound++;
        }
    } else if (slot->status == DNS_ERROR_RCODE_NAME_ERROR || slot->status == DNS_INFO_NO_RECORDS) {
        stats->notfound++;
    } else {
        stats->failed++;
    }

    if (slot->records != NULL) {
        DNSAPI$DnsFree(slot->records, DnsFreeRecordList);
        slot->records = NULL;
    }
}

// Starts a query in a free slot. Returns TRUE if the query is pending and the
// slot is now busy. Returns FALSE if the query finished (or failed) at once,
// in which case it has already been reported.
static BOOL start_query(query_slot *slot, char *name, BOF_DNS_ADDR_ARRAY *server, query_stats *stats) {
    DNS_STATUS ret;

    slot->name = name;
    slot->cancelled = FALSE;
    slot->records = NULL;
    slot->status = 0;
    MSVCRT$memset(&slot->request, 0, sizeof(slot->request));
    MSVCRT$memset(&slot->result, 0, sizeof(slot->result));
    MSVCRT$memset(&slot->cancel, 0, sizeof(slot->cancel));
    KERNEL32$ResetEvent(slot->event);

    if (KERNEL32$MultiByteToWideChar(CP_ACP, 0, name, -1, slot->wname, MAX_NAME) == 0) {
        stats->failed++;
        return FALSE;
    }

    slot->request.Version = DNS_QUERY_REQUEST_VERSION1;
    slot->request.QueryName = slot->wname;
    slot->request.QueryType = DNS_TYPE_A;
    // Skip LLMNR and NetBIOS fallback. They are slow and noisy on the wire.
    slot->request.QueryOptions = DNS_QUERY_NO_MULTICAST | DNS_QUERY_NO_NETBT;
    slot->request.pDnsServerList = server;
    slot->request.pQueryCompletionCallback = query_done;
    slot->request.pQueryContext = slot;
    slot->result.Version = DNS_QUERY_RESULTS_VERSION1;

    slot->started = KERNEL32$GetTickCount();
    ret = DNSAPI$DnsQueryEx(&slot->request, &slot->result, &slot->cancel);
    if (ret == DNS_REQUEST_PENDING) {
        slot->busy = TRUE;
        return TRUE;
    }

    // Completed synchronously (cache hit or immediate error). No callback runs.
    slot->status = ret;
    slot->records = (ret == ERROR_SUCCESS) ? slot->result.pQueryRecords : NULL;
    report(slot, stats);
    return FALSE;
}

// Returns the number of abandoned queries. When non-zero, the caller must not
// free anything the DNS client may still read (the server list).
static DWORD resolve_all(char *hosts, BOF_DNS_ADDR_ARRAY *server) {
    query_slot *slots = NULL;
    HANDLE waitlist[MAX_INFLIGHT];
    query_stats stats = {0};
    char *cursor = hosts;
    char *host;
    DWORD active = 0;
    DWORD abandoned = 0;
    DWORD i;

    slots = (query_slot*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(query_slot) * MAX_INFLIGHT);
    if (slots == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        return 0;
    }
    for (i = 0; i < MAX_INFLIGHT; i++) {
        slots[i].event = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
        if (slots[i].event == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "CreateEvent failed\n");
            goto cleanup;
        }
    }

    host = next_host(&cursor);
    while (host != NULL || active > 0) {
        // Fill free slots
        for (i = 0; i < MAX_INFLIGHT && host != NULL; i++) {
            if (slots[i].busy || slots[i].abandoned) continue;
            if (start_query(&slots[i], host, server, &stats)) active++;
            host = next_host(&cursor);
        }

        if (active == 0) continue;

        DWORD n = 0;
        for (i = 0; i < MAX_INFLIGHT; i++) {
            if (slots[i].busy) waitlist[n++] = slots[i].event;
        }
        KERNEL32$WaitForMultipleObjects(n, waitlist, FALSE, 100);

        DWORD now = KERNEL32$GetTickCount();
        for (i = 0; i < MAX_INFLIGHT; i++) {
            query_slot *slot = &slots[i];
            if (!slot->busy) continue;

            if (KERNEL32$WaitForSingleObject(slot->event, 0) == WAIT_OBJECT_0) {
                slot->busy = FALSE;
                active--;
                report(slot, &stats);
            } else if (!slot->cancelled && now - slot->started > QUERY_TIMEOUT) {
                DNSAPI$DnsCancelQuery(&slot->cancel);
                slot->cancelled = TRUE;
            } else if (slot->cancelled && now - slot->started > QUERY_TIMEOUT + CANCEL_GRACE) {
                // The callback never came. Keep the slot memory alive and
                // never reuse it, since the DNS client may still write to it.
                slot->busy = FALSE;
                slot->abandoned = TRUE;
                active--;
                abandoned++;
                stats.timedout++;
            }
        }
    }

    printoutput(FALSE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done. %lu resolved, %lu not found, %lu timed out, %lu failed\n",
        stats.resolved, stats.notfound, stats.timedout, stats.failed);

cleanup:
    if (abandoned > 0) {
        // Leak the slots and events on purpose so a late callback does not
        // write to freed memory.
        BeaconPrintf(CALLBACK_ERROR, "[!] %lu DNS queries did not respond to cancel\n", abandoned);
        return abandoned;
    }
    for (i = 0; i < MAX_INFLIGHT; i++) {
        if (slots[i].event != NULL) KERNEL32$CloseHandle(slots[i].event);
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, slots);
    return 0;
}

void go(char *args, int len) {
    datap parser;
    char *fileBytes;
    int fileLen = 0;
    char *dnsServer;
    char *hosts = NULL;
    BOF_DNS_ADDR_ARRAY *server = NULL;

    BeaconDataParse(&parser, args, len);
    fileBytes = BeaconDataExtract(&parser, &fileLen);
    dnsServer = BeaconDataExtract(&parser, NULL);

    if (fileBytes == NULL || fileLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "No hostnames file provided.\n");
        return;
    }

    if (!bofstart()) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        return;
    }

    // Copy so the list is always NUL-terminated
    hosts = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, fileLen + 1);
    if (hosts == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        goto cleanup;
    }
    MSVCRT$memcpy(hosts, fileBytes, fileLen);

    if (dnsServer != NULL && dnsServer[0] != '\0') {
        server = (BOF_DNS_ADDR_ARRAY*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BOF_DNS_ADDR_ARRAY));
        if (server == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
            goto cleanup;
        }
        SOCKADDR_IN *sa = (SOCKADDR_IN*)server->AddrArray[0].MaxSa;
        if (WS2_32$inet_pton(AF_INET, dnsServer, &sa->sin_addr) != 1) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid DNS server address: %s\n", dnsServer);
            goto cleanup;
        }
        sa->sin_family = AF_INET;
        sa->sin_port = WS2_32$htons(53);
        server->MaxCount = 1;
        server->AddrCount = 1;
        server->Family = AF_INET;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded hostname file in memory with a size of %d bytes\n", fileLen);
    if (resolve_all(hosts, server) > 0) {
        server = NULL; // still referenced by abandoned queries, leak it
    }

cleanup:
    if (output != NULL) printoutput(TRUE);
    if (server != NULL) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, server);
    if (hosts != NULL) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, hosts);
}
