/*
 * Logon Events BOF
 *
 * Enumerates Windows Security Event Log Event ID 4624 (successful logons).
 * Identifies lateral movement patterns, authentication methods, and logon sources.
 *
 * Features:
 * - Query last N days (configurable, default 7)
 * - Extract: User, LogonType, IpAddress, Auth method
 * - Filter noise: SYSTEM, computer accounts
 * - Cap at max events to prevent beacon blocking
 * - Requires administrator privileges
 *
 * OPSEC: Read-only Security log access, standard Windows API
 */

#include <windows.h>
#include "beacon.h"

// Logon type constants (from Event ID 4624)
#define LOGON_TYPE_INTERACTIVE          2
#define LOGON_TYPE_NETWORK              3
#define LOGON_TYPE_BATCH                4
#define LOGON_TYPE_SERVICE              5
#define LOGON_TYPE_UNLOCK               7
#define LOGON_TYPE_NETWORK_CLEARTEXT    8
#define LOGON_TYPE_NEW_CREDENTIALS      9
#define LOGON_TYPE_REMOTE_INTERACTIVE   10
#define LOGON_TYPE_CACHED_INTERACTIVE   11
#define LOGON_TYPE_CACHED_REMOTE        12
#define LOGON_TYPE_CACHED_UNLOCK        13

// Upper bound on events pulled from the log in one task, so a type filter
// that matches rarely cannot keep the beacon busy indefinitely.
#define MAX_SCANNED_EVENTS 20000

// Statistics structure
typedef struct {
    DWORD totalEvents;
    DWORD networkLogons;
    DWORD interactiveLogons;
    DWORD remoteInteractiveLogons;
    DWORD ntlmv1Count;
    DWORD ntlmv2Count;
    DWORD kerberosCount;
    DWORD filteredEvents;
    DWORD typeFilteredEvents;
} LogonStats;

// Helper: Get logon type string
const char* GetLogonTypeString(const DWORD logonType) {
    switch(logonType) {
        case LOGON_TYPE_INTERACTIVE:
            return "Interactive";
        case LOGON_TYPE_NETWORK:
            return "Network";
        case LOGON_TYPE_BATCH:
            return "Batch";
        case LOGON_TYPE_SERVICE:
            return "Service";
        case LOGON_TYPE_UNLOCK:
            return "Unlock";
        case LOGON_TYPE_NETWORK_CLEARTEXT:
            return "NetworkCleartext";
        case LOGON_TYPE_NEW_CREDENTIALS:
            return "NewCredentials";
        case LOGON_TYPE_REMOTE_INTERACTIVE:
            return "RemoteInteractive";
        case LOGON_TYPE_CACHED_INTERACTIVE:
            return "CachedInteractive";
        case LOGON_TYPE_CACHED_REMOTE:
            return "CachedRemoteInteractive";
        case LOGON_TYPE_CACHED_UNLOCK:
            return "CachedUnlock";
        default:
            return "Unknown";
    }
}

// Helper: Check if username should be filtered out
BOOL ShouldFilterUser(const WCHAR* username, const WCHAR* domain) {
    if (!username || !domain) {
        return TRUE;
    }

    // Filter SYSTEM accounts
    if (lstrcmpW(username, L"SYSTEM") == 0) {
        return TRUE;
    }

    // Filter LOCAL SERVICE
    if (lstrcmpW(username, L"LOCAL SERVICE") == 0) {
        return TRUE;
    }

    // Filter NETWORK SERVICE
    if (lstrcmpW(username, L"NETWORK SERVICE") == 0) {
        return TRUE;
    }

    // Filter ANONYMOUS LOGON
    if (lstrcmpW(username, L"ANONYMOUS LOGON") == 0) {
        return TRUE;
    }

    // Filter computer accounts (ending with $)
    int len = lstrlenW(username);
    if (len > 0 && username[len - 1] == L'$') {
        return TRUE;
    }

    // Filter UMFD-X accounts (User Mode Font Driver)
    if (wcsstr(username, L"UMFD-") == username) {
        return TRUE;
    }

    // Filter DWM-X accounts (Desktop Window Manager)
    if (wcsstr(username, L"DWM-") == username) {
        return TRUE;
    }

    // Filter NT VIRTUAL MACHINE domain
    if (lstrcmpW(domain, L"NT VIRTUAL MACHINE") == 0) {
        return TRUE;
    }

    return FALSE;
}

// Helper: Build XPath query with time filter and optional logon type filter.
// The logon type goes into the XPath so the event log service does the
// filtering instead of the beacon rendering every event and discarding it.
void BuildXPathQuery(const int days, const int logonType, WCHAR* query, const size_t querySize) {
    // Get current time
    SYSTEMTIME st;
    FILETIME ft, ftStart;
    ULARGE_INTEGER uli;

    GetSystemTime(&st);
    if (!SystemTimeToFileTime(&st, &ft)) {
        // Time conversion failed - use default query without time filter
        if (logonType > 0) {
            _snwprintf(query, querySize/sizeof(WCHAR),
                L"*[System/EventID=4624] and *[EventData[Data[@Name='LogonType']='%d']]", logonType);
        } else {
            _snwprintf(query, querySize/sizeof(WCHAR), L"*[System/EventID=4624]");
        }
        query[querySize/sizeof(WCHAR) - 1] = L'\0';
        return;
    }

    // Calculate start time (days ago)
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Subtract days (100-nanosecond intervals)
    ULONGLONG intervals = (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;
    uli.QuadPart -= intervals;

    ftStart.dwLowDateTime = uli.LowPart;
    ftStart.dwHighDateTime = uli.HighPart;

    // Convert back to SYSTEMTIME
    SYSTEMTIME stStart;
    if (!FileTimeToSystemTime(&ftStart, &stStart)) {
        // Time conversion failed - use default query without time filter
        if (logonType > 0) {
            _snwprintf(query, querySize/sizeof(WCHAR),
                L"*[System/EventID=4624] and *[EventData[Data[@Name='LogonType']='%d']]", logonType);
        } else {
            _snwprintf(query, querySize/sizeof(WCHAR), L"*[System/EventID=4624]");
        }
        query[querySize/sizeof(WCHAR) - 1] = L'\0';
        return;
    }

    // Build ISO 8601 timestamp
    WCHAR timestamp[64];
    int written = _snwprintf(timestamp, sizeof(timestamp)/sizeof(WCHAR),
        L"%04d-%02d-%02dT%02d:%02d:%02d.000Z",
        stStart.wYear, stStart.wMonth, stStart.wDay,
        stStart.wHour, stStart.wMinute, stStart.wSecond);

    // Check for truncation/overflow with error logging
    if (written < 0 || written >= sizeof(timestamp)/sizeof(WCHAR)) {
        // Timestamp buffer too small - log error and ensure NULL termination
        BeaconPrintf(CALLBACK_ERROR, "[!] Timestamp formatting failed or truncated (written=%d)\n", written);
        timestamp[sizeof(timestamp)/sizeof(WCHAR) - 1] = L'\0';
    }

    // Build XPath query - both System conditions must be inside a single *[System[...]] selector
    if (logonType > 0) {
        written = _snwprintf(query, querySize/sizeof(WCHAR),
            L"*[System[(EventID=4624) and TimeCreated[@SystemTime >= '%s']]] and *[EventData[Data[@Name='LogonType']='%d']]",
            timestamp, logonType);
    } else {
        written = _snwprintf(query, querySize/sizeof(WCHAR),
            L"*[System[(EventID=4624) and TimeCreated[@SystemTime >= '%s']]]",
            timestamp);
    }

    // Check for truncation/overflow with error logging
    if (written < 0 || written >= querySize/sizeof(WCHAR)) {
        // Query buffer too small - log error and ensure NULL termination
        BeaconPrintf(CALLBACK_ERROR, "[!] XPath query formatting failed or truncated (written=%d)\n", written);
        query[querySize/sizeof(WCHAR) - 1] = L'\0';
    }
}

// Parse and display a single logon event
BOOL ParseLogonEvent(EVT_HANDLE hEvent, LogonStats* stats, const int logonTypeFilter) {
    BOOL result = FALSE;
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;
    LPWSTR xmlText = NULL;

    // Render event as XML (first call to get required buffer size)
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferUsed, &propertyCount)) {
        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            // Real error occurred
            goto cleanup;
        }
        // ERROR_INSUFFICIENT_BUFFER is expected - continue to allocate buffer
    } else {
        // Unexpected success with 0 buffer - should not happen
        goto cleanup;
    }

    // Allocate buffer
    bufferSize = bufferUsed;
    xmlText = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (!xmlText) {
        goto cleanup;
    }

    // Render event as XML
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, xmlText, &bufferUsed, &propertyCount)) {
        goto cleanup;
    }

    // Extract values using simple XML parsing
    WCHAR targetUserName[256] = L"(null)";
    WCHAR targetDomainName[256] = L"(null)";
    WCHAR ipAddress[64] = L"127.0.0.1";
    WCHAR authPackage[64] = L"(null)";
    WCHAR lmPackage[64] = L"-";
    DWORD logonType = 0;
    SYSTEMTIME st = {0};

    // Extract TargetUserName
    LPWSTR p = wcsstr(xmlText, L"<Data Name='TargetUserName'>");
    if (p) {
        p += 28; // Skip opening tag
        LPWSTR end = wcsstr(p, L"</Data>");
        if (end && (end - p) < 255) {
            wcsncpy(targetUserName, p, end - p);
            targetUserName[end - p] = L'\0';
        }
    }

    // Extract TargetDomainName
    p = wcsstr(xmlText, L"<Data Name='TargetDomainName'>");
    if (p) {
        p += 30; // Skip opening tag
        LPWSTR end = wcsstr(p, L"</Data>");
        if (end && (end - p) < 255) {
            wcsncpy(targetDomainName, p, end - p);
            targetDomainName[end - p] = L'\0';
        }
    }

    // Extract LogonType
    p = wcsstr(xmlText, L"<Data Name='LogonType'>");
    if (p) {
        p += 23; // Skip opening tag
        logonType = wcstoul(p, NULL, 10);
    }

    // Extract IpAddress
    p = wcsstr(xmlText, L"<Data Name='IpAddress'>");
    if (p) {
        p += 23; // Skip opening tag
        LPWSTR end = wcsstr(p, L"</Data>");
        if (end && (end - p) < 63) {
            wcsncpy(ipAddress, p, end - p);
            ipAddress[end - p] = L'\0';
        }
    }

    // Extract AuthenticationPackageName
    p = wcsstr(xmlText, L"<Data Name='AuthenticationPackageName'>");
    if (p) {
        p += 39; // Skip opening tag
        LPWSTR end = wcsstr(p, L"</Data>");
        if (end && (end - p) < 63) {
            wcsncpy(authPackage, p, end - p);
            authPackage[end - p] = L'\0';
        }
    }

    // Extract LmPackageName
    p = wcsstr(xmlText, L"<Data Name='LmPackageName'>");
    if (p) {
        p += 27; // Skip opening tag
        LPWSTR end = wcsstr(p, L"</Data>");
        if (end && (end - p) < 63) {
            wcsncpy(lmPackage, p, end - p);
            lmPackage[end - p] = L'\0';
        }
    }

    // Extract TimeCreated
    p = wcsstr(xmlText, L"SystemTime='");
    if (p) {
        p += 12; // Skip to timestamp
        // Parse ISO 8601 timestamp: 2025-11-16T13:08:55.123456Z
        swscanf(p, L"%04hd-%02hd-%02hdT%02hd:%02hd:%02hd",
            &st.wYear, &st.wMonth, &st.wDay,
            &st.wHour, &st.wMinute, &st.wSecond);
    }

    // Belt and braces: the XPath already restricts the type, this catches
    // anything the query let through.
    if (logonTypeFilter > 0 && (int)logonType != logonTypeFilter) {
        stats->typeFilteredEvents++;
        result = TRUE;
        goto cleanup;
    }

    // Filter out noise
    if (ShouldFilterUser(targetUserName, targetDomainName)) {
        stats->filteredEvents++;
        result = TRUE;  // Not an error, just filtered
        goto cleanup;
    }

    // Update statistics
    stats->totalEvents++;

    switch(logonType) {
        case LOGON_TYPE_NETWORK:
            stats->networkLogons++;
            break;
        case LOGON_TYPE_INTERACTIVE:
        case LOGON_TYPE_UNLOCK:
        case LOGON_TYPE_CACHED_INTERACTIVE:
            stats->interactiveLogons++;
            break;
        case LOGON_TYPE_REMOTE_INTERACTIVE:
            stats->remoteInteractiveLogons++;
            break;
    }

    // Track authentication method
    if (logonType == LOGON_TYPE_NETWORK) {
        if (lstrcmpW(authPackage, L"NTLM") == 0) {
            if (lstrcmpW(lmPackage, L"NTLM V1") == 0) {
                stats->ntlmv1Count++;
            } else if (lstrcmpW(lmPackage, L"NTLM V2") == 0) {
                stats->ntlmv2Count++;
            }
        } else if (lstrcmpW(authPackage, L"Kerberos") == 0) {
            stats->kerberosCount++;
        }
    }

    // Display event
    BeaconPrintf(CALLBACK_OUTPUT, "\n[%s] %04d-%02d-%02d %02d:%02d:%02d\n",
        GetLogonTypeString(logonType),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    BeaconPrintf(CALLBACK_OUTPUT, "  User:    %S\\%S\n", targetDomainName, targetUserName);

    // Only show IP for network logons
    if (logonType == LOGON_TYPE_NETWORK || logonType == LOGON_TYPE_REMOTE_INTERACTIVE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  From:    %S\n", ipAddress);
    }

    // Show auth package
    BeaconPrintf(CALLBACK_OUTPUT, "  Auth:    %S", authPackage);
    if (lstrcmpW(lmPackage, L"-") != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, " (%S)", lmPackage);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    result = TRUE;

cleanup:
    if (xmlText) {
        HeapFree(GetProcessHeap(), 0, xmlText);
    }
    return result;
}

void go(char* args, int len) {
    EVT_HANDLE hQuery = NULL;
    EVT_HANDLE hEvent = NULL;
    WCHAR query[512];
    DWORD returned = 0;
    LogonStats stats = {0};

    // Parse arguments
    datap parser;
    BeaconDataParse(&parser, args, len);

    int days = 7;           // Default 7 days
    int maxEvents = 100;    // Default cap at 100 events (reduced to prevent beacon blocking)
    int logonTypeFilter = 0; // 0 = all logon types

    if (len >= 4) {
        days = BeaconDataInt(&parser);
        if (days < 1) days = 1;
        if (days > 30) days = 30;
    }

    if (len >= 8) {
        maxEvents = BeaconDataInt(&parser);
        if (maxEvents < 10) maxEvents = 10;
        if (maxEvents > 5000) maxEvents = 5000;
    }

    if (len >= 12) {
        logonTypeFilter = BeaconDataInt(&parser);
        if (logonTypeFilter < 0 || logonTypeFilter > LOGON_TYPE_CACHED_UNLOCK) logonTypeFilter = 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying Security event log for Event ID 4624...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Time range: Last %d day(s)\n", days);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Max events: %d\n", maxEvents);
    if (logonTypeFilter > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Logon type: %d (%s)\n",
            logonTypeFilter, GetLogonTypeString((DWORD)logonTypeFilter));
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Requires administrator privileges\n\n");

    // Build XPath query
    BuildXPathQuery(days, logonTypeFilter, query, sizeof(query));

    // Open query on Security log
    hQuery = EvtQuery(
        NULL,                           // Local computer
        L"Security",                    // Channel name
        query,                          // XPath query
        EvtQueryChannelPath | EvtQueryReverseDirection
    );

    if (!hQuery) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Access denied. Run as administrator.\n");
        } else if (error == ERROR_EVT_CHANNEL_NOT_FOUND) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Security event log not found.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] EvtQuery failed with error: %d\n", error);
        }
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Query successful, enumerating events...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "================================================================================");

    // Enumerate events. maxEvents caps what is displayed; MAX_SCANNED_EVENTS
    // caps what is pulled from the log so noise-heavy servers cannot stall us.
    int eventCount = 0;
    while (EvtNext(hQuery, 1, &hEvent, 2000, 0, &returned) && returned > 0) {  // Reduced timeout to 2000ms
        if ((int)stats.totalEvents >= maxEvents) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n\n[!] Reached maximum event limit (%d events displayed)\n", maxEvents);
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Use --max-events to increase limit\n");
            break;
        }
        if (eventCount >= MAX_SCANNED_EVENTS) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n\n[!] Scanned %d events, stopping to keep the beacon responsive\n", MAX_SCANNED_EVENTS);
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Narrow the window with --days or add --logon-type\n");
            break;
        }

        // Parse and display event
        ParseLogonEvent(hEvent, &stats, logonTypeFilter);

        eventCount++;

        // Progress indicator
        if (eventCount % 100 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Processed %d events...\n", eventCount);
        }

        // Close this event handle
        if (hEvent) {
            EvtClose(hEvent);
            hEvent = NULL;
        }
    }

    // Display summary
    BeaconPrintf(CALLBACK_OUTPUT, "\n================================================================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Summary:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  Total events displayed:  %d\n", stats.totalEvents);
    BeaconPrintf(CALLBACK_OUTPUT, "  Filtered (noise):        %d\n", stats.filteredEvents);
    if (logonTypeFilter > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  Filtered (logon type):   %d\n", stats.typeFilteredEvents);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  Network logons:          %d\n", stats.networkLogons);
    BeaconPrintf(CALLBACK_OUTPUT, "  Interactive logons:      %d\n", stats.interactiveLogons);
    BeaconPrintf(CALLBACK_OUTPUT, "  RemoteInteractive:       %d\n", stats.remoteInteractiveLogons);

    if (stats.ntlmv1Count > 0 || stats.ntlmv2Count > 0 || stats.kerberosCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Authentication Methods (Network logons only):\n");
        if (stats.ntlmv1Count > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  NTLM v1:  %d (WEAK! Can be cracked!)\n", stats.ntlmv1Count);
        }
        if (stats.ntlmv2Count > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  NTLM v2:  %d\n", stats.ntlmv2Count);
        }
        if (stats.kerberosCount > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Kerberos: %d\n", stats.kerberosCount);
        }
    }

cleanup:
    if (hEvent) {
        EvtClose(hEvent);
    }
    if (hQuery) {
        EvtClose(hQuery);
    }
}
