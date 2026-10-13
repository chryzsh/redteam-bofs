// Sockets in flight at once. select() is limited to FD_SETSIZE sockets per set.
#define FD_SETSIZE 128
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "beacon.h"

#define MAX_INFLIGHT    FD_SETSIZE
#define DEFAULT_TIMEOUT 1000
#define MAX_PORTS       65535

/* WS2_32 */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int WSAAPI WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int WSAAPI WS2_32$select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
DECLSPEC_IMPORT int WSAAPI WS2_32$setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT INT WSAAPI WS2_32$inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
DECLSPEC_IMPORT INT WSAAPI WS2_32$getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
DECLSPEC_IMPORT VOID WSAAPI WS2_32$freeaddrinfo(PADDRINFOA pAddrInfo);

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);

/* MSVCRT */
DECLSPEC_IMPORT int __cdecl MSVCRT$vsnprintf(char *buffer, size_t count, const char *format, va_list arg);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *str);

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
    char *name;
    ULONG addr;     // IPv4, network byte order
} scan_target;

typedef struct {
    SOCKET s;
    DWORD  target;
    WORD   port;
    DWORD  started;
    BOOL   busy;
} scan_probe;

typedef struct {
    DWORD open;
    DWORD closed;
    DWORD filtered;
    DWORD failed;
} scan_stats;

// FD_ISSET calls __WSAFDIsSet, which a BOF cannot import. Check the set directly.
static BOOL fd_has(fd_set *set, SOCKET s) {
    u_int i;
    for (i = 0; i < set->fd_count; i++) {
        if (set->fd_array[i] == s) return TRUE;
    }
    return FALSE;
}

static BOOL is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

// Parses "445,3389,8000-8100" into ports[]. Returns the count, or 0 on bad input.
static DWORD parse_ports(const char *spec, WORD *ports) {
    const char *p = spec;
    DWORD count = 0;

    while (*p) {
        DWORD lo = 0, hi = 0;
        int digits = 0;

        while (is_space(*p)) p++;
        while (*p >= '0' && *p <= '9') {
            lo = lo * 10 + (*p - '0');
            if (lo > 65535) return 0;
            p++; digits++;
        }
        if (digits == 0) return 0;
        hi = lo;

        if (*p == '-') {
            p++;
            hi = 0; digits = 0;
            while (*p >= '0' && *p <= '9') {
                hi = hi * 10 + (*p - '0');
                if (hi > 65535) return 0;
                p++; digits++;
            }
            if (digits == 0) return 0;
        }
        while (is_space(*p)) p++;
        if (*p == ',') {
            p++;
        } else if (*p != '\0') {
            return 0;
        }

        if (lo == 0 || hi < lo) return 0;
        for (DWORD port = lo; port <= hi; port++) {
            if (count >= MAX_PORTS) return 0;
            ports[count++] = (WORD)port;
        }
    }
    return count;
}

// Reads one target from a line. Accepts "host", "ip", or "host<ws>ip[,ip...]"
// (the nslookup-file output format). When an IP is on the line it is used
// as-is, otherwise the host is resolved here.
static BOOL parse_target(char *line, scan_target *t) {
    char *name = line;
    char *p = line;
    char ip[16];
    int n = 0;
    ADDRINFOA hints;
    PADDRINFOA res = NULL;

    while (*p && !is_space(*p)) p++;
    if (*p) {
        *p++ = '\0';
        while (is_space(*p)) p++;
        while (*p && !is_space(*p) && *p != ',' && n < (int)sizeof(ip) - 1) ip[n++] = *p++;
    }
    ip[n] = '\0';

    t->name = name;
    if (n > 0 && WS2_32$inet_pton(AF_INET, ip, &t->addr) == 1) return TRUE;
    if (WS2_32$inet_pton(AF_INET, name, &t->addr) == 1) return TRUE;

    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (WS2_32$getaddrinfo(name, NULL, &hints, &res) != 0 || res == NULL) return FALSE;
    t->addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    WS2_32$freeaddrinfo(res);
    return TRUE;
}

// Splits the buffer into lines in place and fills targets[]. Returns the count.
static DWORD load_targets(char *buf, scan_target *targets, DWORD max, DWORD *unresolved) {
    char *p = buf;
    DWORD count = 0;

    while (*p && count < max) {
        char *line;
        char *end;

        while (is_space(*p) || *p == '\n') p++;
        if (*p == '\0') break;
        line = p;
        while (*p && *p != '\n') p++;
        end = p;
        if (*p) p++;
        *end = '\0';

        if (parse_target(line, &targets[count])) {
            count++;
        } else {
            (*unresolved)++;
        }
    }
    return count;
}

static void close_probe(scan_probe *probe) {
    // Abortive close: send RST and skip TIME_WAIT
    struct linger lin = { 1, 0 };
    WS2_32$setsockopt(probe->s, SOL_SOCKET, SO_LINGER, (const char*)&lin, sizeof(lin));
    WS2_32$closesocket(probe->s);
    probe->s = INVALID_SOCKET;
    probe->busy = FALSE;
}

static void report_open(scan_target *targets, scan_probe *probe, scan_stats *stats) {
    internal_printf("%s:%u\n", targets[probe->target].name, probe->port);
    stats->open++;
}

// Returns TRUE if the probe is in flight. Otherwise it has already been counted.
static BOOL start_probe(scan_probe *probe, scan_target *targets, DWORD target, WORD port, scan_stats *stats) {
    struct sockaddr_in sa;
    u_long nonblocking = 1;
    int err;

    probe->target = target;
    probe->port = port;
    probe->s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (probe->s == INVALID_SOCKET) {
        stats->failed++;
        return FALSE;
    }
    probe->busy = TRUE;

    if (WS2_32$ioctlsocket(probe->s, FIONBIO, &nonblocking) != 0) {
        stats->failed++;
        close_probe(probe);
        return FALSE;
    }

    MSVCRT$memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = WS2_32$htons(port);
    sa.sin_addr.s_addr = targets[target].addr;

    probe->started = KERNEL32$GetTickCount();
    if (WS2_32$connect(probe->s, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        report_open(targets, probe, stats);
        close_probe(probe);
        return FALSE;
    }

    err = WS2_32$WSAGetLastError();
    if (err == WSAEWOULDBLOCK) return TRUE;

    // Immediate failure, e.g. no route to host
    stats->closed++;
    close_probe(probe);
    return FALSE;
}

static void scan(scan_target *targets, DWORD ntargets, WORD *ports, DWORD nports, DWORD timeout, scan_stats *stats) {
    scan_probe *probes;
    fd_set wset, eset;
    struct timeval tv;
    DWORD active = 0;
    DWORD pi = 0, ti = 0;   // next port index, next target index
    DWORD i;

    // Heap, not stack: the probes plus two fd_sets would pass the 4 KB
    // limit that triggers __chkstk_ms.
    probes = (scan_probe*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(scan_probe) * MAX_INFLIGHT);
    if (probes == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        return;
    }

    for (i = 0; i < MAX_INFLIGHT; i++) {
        probes[i].s = INVALID_SOCKET;
        probes[i].busy = FALSE;
    }

    // Port-major order spreads the load across hosts instead of hitting one
    // host with many ports at once.
    while (pi < nports || active > 0) {
        for (i = 0; i < MAX_INFLIGHT && pi < nports; i++) {
            if (probes[i].busy) continue;
            if (start_probe(&probes[i], targets, ti, ports[pi], stats)) active++;
            if (++ti == ntargets) {
                ti = 0;
                pi++;
            }
        }

        if (active == 0) continue;

        FD_ZERO(&wset);
        FD_ZERO(&eset);
        for (i = 0; i < MAX_INFLIGHT; i++) {
            if (!probes[i].busy) continue;
            FD_SET(probes[i].s, &wset);
            FD_SET(probes[i].s, &eset);
        }

        tv.tv_sec = 0;
        tv.tv_usec = 20000;
        if (WS2_32$select(0, NULL, &wset, &eset, &tv) == SOCKET_ERROR) {
            BeaconPrintf(CALLBACK_ERROR, "select failed: %d\n", WS2_32$WSAGetLastError());
            break;
        }

        DWORD now = KERNEL32$GetTickCount();
        for (i = 0; i < MAX_INFLIGHT; i++) {
            scan_probe *probe = &probes[i];
            if (!probe->busy) continue;

            if (fd_has(&wset, probe->s)) {
                // Writable means the handshake completed
                report_open(targets, probe, stats);
            } else if (fd_has(&eset, probe->s)) {
                // Connect failed, normally an RST from the target
                stats->closed++;
            } else if (now - probe->started >= timeout) {
                stats->filtered++;
            } else {
                continue;
            }
            close_probe(probe);
            active--;
        }
    }

    // Only reached with sockets open if select() failed
    for (i = 0; i < MAX_INFLIGHT; i++) {
        if (probes[i].busy) close_probe(&probes[i]);
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, probes);
}

void go(char *args, int len) {
    datap parser;
    char *inlineHost;
    int hostLen = 0;
    char *fileBytes;
    int fileLen = 0;
    char *portSpec;
    int timeout;
    char *hosts = NULL;
    DWORD hostsLen = 0;
    WORD *ports = NULL;
    DWORD nports = 0;
    scan_target *targets = NULL;
    DWORD maxTargets = 1;
    DWORD ntargets = 0;
    DWORD unresolved = 0;
    scan_stats stats = { 0, 0, 0, 0 };
    WSADATA wsa;
    BOOL wsaStarted = FALSE;
    DWORD i;

    BeaconDataParse(&parser, args, len);
    inlineHost = BeaconDataExtract(&parser, &hostLen);
    fileBytes = BeaconDataExtract(&parser, &fileLen);
    portSpec = BeaconDataExtract(&parser, NULL);
    timeout = BeaconDataInt(&parser);
    if (timeout <= 0) timeout = DEFAULT_TIMEOUT;

    if (!bofstart()) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        return;
    }

    // Copy the target list so it is always NUL-terminated
    if (inlineHost != NULL && hostLen > 1) {
        hostsLen = MSVCRT$strlen(inlineHost);
        hosts = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, hostsLen + 1);
        if (hosts != NULL) MSVCRT$memcpy(hosts, inlineHost, hostsLen);
    } else if (fileBytes != NULL && fileLen > 0) {
        hostsLen = (DWORD)fileLen;
        hosts = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, hostsLen + 1);
        if (hosts != NULL) MSVCRT$memcpy(hosts, fileBytes, hostsLen);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "No host or hostnames file provided.\n");
        goto cleanup;
    }
    if (hosts == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        goto cleanup;
    }

    if (portSpec == NULL || portSpec[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "No ports provided.\n");
        goto cleanup;
    }
    ports = (WORD*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WORD) * MAX_PORTS);
    if (ports == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        goto cleanup;
    }
    nports = parse_ports(portSpec, ports);
    if (nports == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid port list: %s\n", portSpec);
        goto cleanup;
    }

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        goto cleanup;
    }
    wsaStarted = TRUE;

    for (i = 0; i < hostsLen; i++) {
        if (hosts[i] == '\n') maxTargets++;
    }
    targets = (scan_target*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(scan_target) * maxTargets);
    if (targets == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n");
        goto cleanup;
    }
    ntargets = load_targets(hosts, targets, maxTargets, &unresolved);
    if (ntargets == 0) {
        BeaconPrintf(CALLBACK_ERROR, "No targets resolved (%lu could not be resolved).\n", unresolved);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %lu hosts on %lu ports, %d ms timeout\n", ntargets, nports, timeout);
    scan(targets, ntargets, ports, nports, (DWORD)timeout, &stats);
    printoutput(FALSE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done. %lu open, %lu closed, %lu filtered, %lu failed, %lu hosts not resolved\n",
        stats.open, stats.closed, stats.filtered, stats.failed, unresolved);

cleanup:
    if (output != NULL) printoutput(TRUE);
    if (wsaStarted) WS2_32$WSACleanup();
    if (targets != NULL) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, targets);
    if (ports != NULL) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ports);
    if (hosts != NULL) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, hosts);
}
