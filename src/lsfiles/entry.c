#include <windows.h>
#include "beacon.h"

/**
 * Recursive File Lister BOF
 *
 * Recursively enumerates files in a directory with wildcard pattern support.
 * Streams output and provides summary statistics.
 *
 * SAFETY NOTES:
 * - Maximum path length: 512 characters (enforced throughout)
 * - Maximum recursion depth: 100 levels (internal safety limit)
 * - Recommended user maxDepth: 10-20 for typical operations
 * - Deep recursion (>50) may impact performance
 */

// Safety limits
#define MAX_PATH_LENGTH 512
#define MAX_PATTERN_LENGTH 256
#define MAX_RECURSION_DEPTH 100  // Internal safety limit
#define MAX_RESULTS_DEFAULT 1000  // Default maximum results to return

// Statistics structure
typedef struct {
    DWORD fileCount;
    DWORD directoryCount;
    DWORD resultCount;
    ULONGLONG totalSize;
    DWORD errorCount;
    int maxResults;      // Maximum results to return (-1 for unlimited)
    BOOL limitReached;   // TRUE if max results limit was hit
} FileStats;

// Date filter structure for time-based filtering
typedef struct {
    BOOL enabled;       // Whether filtering is enabled
    int year;           // Year (e.g., 2025), -1 if not specified
    int month;          // Month (1-12), -1 if not specified
    int day;            // Day (1-31), -1 if not specified
} DateFilter;

// Size filter structure for file size filtering
typedef struct {
    BOOL enabled;       // Whether filtering is enabled
    LONGLONG minSize;   // Minimum file size in bytes (-1 for no minimum)
    LONGLONG maxSize;   // Maximum file size in bytes (-1 for no maximum)
} SizeFilter;

// Forward declarations
void EnumerateFiles(LPWSTR basePath, LPCWSTR pattern, LPCWSTR excludePatterns, LPCWSTR excludePathPatterns, BOOL suppressErrors,
                    int currentDepth, int maxDepth, FileStats* stats, DateFilter* dateFilter, SizeFilter* sizeFilter,
                    BOOL includeDirs);
void ExpandPathWildcardsAndEnumerate(LPWSTR targetPath, LPCWSTR pattern, LPCWSTR excludePatterns, LPCWSTR excludePathPatterns,
                                      BOOL suppressErrors, int currentDepth,
                                      int maxDepth, FileStats* stats, DateFilter* dateFilter, SizeFilter* sizeFilter,
                                      BOOL includeDirs);

// Case-insensitive single-character comparison for wildcard matching.
BOOL CharsEqualIgnoreCase(WCHAR a, WCHAR b) {
    WCHAR lhs[2] = {a, L'\0'};
    WCHAR rhs[2] = {b, L'\0'};
    return lstrcmpiW(lhs, rhs) == 0;
}

/**
 * Simple wildcard matching function (supports * and ? wildcards)
 *
 * Algorithm: Greedy matching with backtracking
 * - '*' matches zero or more characters
 * - '?' matches exactly one character
 * - All other characters must match exactly
 *
 * Examples:
 *   "*.txt" matches "file.txt", "document.txt", "report.log.txt"
 *   "test?.log" matches "test1.log", "testA.log" but not "test.log"
 *   "*2024*" matches "report_2024_final.pdf", "2024.txt"
 *
 * Implementation uses backtracking when '*' is encountered:
 * 1. Save position after '*' for potential backtrack
 * 2. Try to match remaining pattern with remaining string
 * 3. If mismatch, backtrack to last '*' and try next character
 * 4. Continue until full match or all possibilities exhausted
 *
 * @param pattern  Wildcard pattern string
 * @param string   String to match against pattern
 * @return TRUE if string matches pattern, FALSE otherwise
 */
BOOL SimpleWildcardMatch(LPCWSTR pattern, LPCWSTR string) {
    LPCWSTR p = pattern;
    LPCWSTR s = string;
    LPCWSTR starPos = NULL;   // Position of last '*' in pattern
    LPCWSTR matchPos = NULL;  // Position in string when '*' was found

    // Process string character by character
    while (*s) {
        if (*p == L'*') {
            // Save '*' position for potential backtracking
            starPos = p++;
            matchPos = s;
        } else if (*p == L'?' || CharsEqualIgnoreCase(*p, *s)) {
            // '?' matches any char, or exact character match
            p++;
            s++;
        } else if (starPos) {
            // Mismatch: backtrack to last '*' and try next char
            p = starPos + 1;
            s = ++matchPos;
        } else {
            // Mismatch with no backtrack point
            return FALSE;
        }
    }

    // Consume trailing '*' in pattern
    while (*p == L'*') {
        p++;
    }

    // Match succeeds if we've consumed entire pattern
    return *p == L'\0';
}

/**
 * Check if a string matches any pipe-delimited wildcard pattern.
 * Patterns are pipe-delimited (e.g., "*.tmp|*.log|*.bak")
 * @param value    String to check
 * @param patterns Pipe-delimited wildcard patterns (can be NULL or empty)
 * @return TRUE if value matches any pattern, FALSE otherwise
 */
BOOL MatchesPatternList(LPCWSTR value, LPCWSTR patterns) {
    WCHAR pattern[MAX_PATTERN_LENGTH];
    int patternLen = 0;
    int i;

    // If no patterns, don't exclude anything
    if (!patterns || lstrlenW(patterns) == 0) {
        return FALSE;
    }

    // Parse pipe-delimited patterns
    i = 0;
    while (patterns[i] != L'\0') {
        // Extract one pattern
        patternLen = 0;
        while (patterns[i] != L'\0' && patterns[i] != L'|' && patternLen < MAX_PATTERN_LENGTH - 1) {
            pattern[patternLen++] = patterns[i++];
        }
        pattern[patternLen] = L'\0';

        // Check if pattern was truncated
        if (patternLen >= MAX_PATTERN_LENGTH - 1 &&
            patterns[i] != L'|' && patterns[i] != L'\0') {
            // Pattern exceeded maximum length and was truncated
            BeaconPrintf(CALLBACK_ERROR,
                        "[!] Warning: Pattern truncated (max %d chars). Match may not behave as expected.\n",
                        MAX_PATTERN_LENGTH - 1);
        }

        if (patternLen > 0 && SimpleWildcardMatch(pattern, value)) {
            return TRUE;
        }

        // Skip the pipe delimiter
        if (patterns[i] == L'|') {
            i++;
        }
    }

    return FALSE;
}

// Convert FILETIME to readable format
void FormatFileTime(FILETIME* ft, char* buffer, int bufferSize) {
    SYSTEMTIME stUTC, stLocal;

    if (!FileTimeToSystemTime(ft, &stUTC)) {
        _snprintf(buffer, bufferSize, "Unknown");
        return;
    }

    if (!SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
        // If timezone conversion fails, use UTC
        _snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
                 stUTC.wYear, stUTC.wMonth, stUTC.wDay,
                 stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
    } else {
        _snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
                 stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                 stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    }
}

// Format file size in human-readable format
void FormatFileSize(ULONGLONG size, char* buffer, int bufferSize) {
    if (size >= 1073741824) {  // >= 1 GB
        double sizeGB = (double)size / 1073741824.0;
        _snprintf(buffer, bufferSize, "%.2f GB", sizeGB);
    } else if (size >= 1048576) {  // >= 1 MB
        double sizeMB = (double)size / 1048576.0;
        _snprintf(buffer, bufferSize, "%.2f MB", sizeMB);
    } else if (size >= 1024) {  // >= 1 KB
        double sizeKB = (double)size / 1024.0;
        _snprintf(buffer, bufferSize, "%.2f KB", sizeKB);
    } else {
        _snprintf(buffer, bufferSize, "%llu bytes", size);
    }
}

// Convert wide string to UTF-8 for output
int WideCharToUtf8(LPCWSTR wide, char* buffer, int bufferSize) {
    int i = 0;
    int j = 0;

    while (wide[i] && j < bufferSize - 1) {
        if (wide[i] < 0x80) {
            buffer[j++] = (char)wide[i];
        } else if (wide[i] < 0x800) {
            if (j + 1 >= bufferSize - 1) break;
            buffer[j++] = 0xC0 | (wide[i] >> 6);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        } else {
            if (j + 2 >= bufferSize - 1) break;
            buffer[j++] = 0xE0 | (wide[i] >> 12);
            buffer[j++] = 0x80 | ((wide[i] >> 6) & 0x3F);
            buffer[j++] = 0x80 | (wide[i] & 0x3F);
        }
        i++;
    }
    buffer[j] = '\0';
    return j;
}

// Check if a path contains wildcards
BOOL PathContainsWildcards(LPCWSTR path) {
    while (*path) {
        if (*path == L'*' || *path == L'?') {
            return TRUE;
        }
        path++;
    }
    return FALSE;
}

/**
 * Validate if a date is valid in the calendar
 * Checks for leap years and correct days per month
 * @param year   Year (e.g., 2025)
 * @param month  Month (1-12)
 * @param day    Day (1-31)
 * @return TRUE if date is valid, FALSE otherwise
 */
BOOL IsValidCalendarDate(int year, int month, int day) {
    // Check month range
    if (month < 1 || month > 12) {
        return FALSE;
    }

    // Check day range (basic)
    if (day < 1 || day > 31) {
        return FALSE;
    }

    // Days per month (non-leap year)
    int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    // Check for leap year
    BOOL isLeapYear = FALSE;
    if (year % 4 == 0) {
        if (year % 100 == 0) {
            if (year % 400 == 0) {
                isLeapYear = TRUE;  // Divisible by 400 -> leap year
            }
        } else {
            isLeapYear = TRUE;  // Divisible by 4 but not 100 -> leap year
        }
    }

    // Adjust February for leap years
    if (isLeapYear && month == 2) {
        daysInMonth[1] = 29;
    }

    // Validate day is within valid range for the month
    if (day > daysInMonth[month - 1]) {
        return FALSE;  // Invalid day for this month (e.g., Feb 30, April 31)
    }

    return TRUE;
}

/**
 * Parse date filter string into DateFilter structure
 * Supports formats: "2025", "2025-11", "2025-11-13"
 * @param dateStr  Date string to parse (can be NULL or empty to disable filter)
 * @param filter   Pointer to DateFilter structure to populate
 * @return TRUE if parsing succeeded or filter disabled, FALSE on parse error
 */
BOOL ParseDateFilter(LPCWSTR dateStr, DateFilter* filter) {
    // Initialize filter
    filter->enabled = FALSE;
    filter->year = -1;
    filter->month = -1;
    filter->day = -1;

    // Empty or NULL string means no filtering
    if (!dateStr || lstrlenW(dateStr) == 0) {
        return TRUE;
    }

    // Parse year (required if filter is specified)
    int year = 0, month = 0, day = 0;
    int parsePos = 0;

    // Extract year (4 digits)
    while (parsePos < 4 && dateStr[parsePos] >= L'0' && dateStr[parsePos] <= L'9') {
        year = year * 10 + (dateStr[parsePos] - L'0');
        parsePos++;
    }

    if (parsePos < 4) {
        return FALSE;  // Year must be 4 digits
    }

    filter->year = year;
    filter->enabled = TRUE;

    // Check if month is specified
    if (dateStr[parsePos] == L'-') {
        parsePos++;  // Skip '-'

        // Extract month (1-2 digits)
        int monthDigits = 0;
        while (monthDigits < 2 && dateStr[parsePos] >= L'0' && dateStr[parsePos] <= L'9') {
            month = month * 10 + (dateStr[parsePos] - L'0');
            parsePos++;
            monthDigits++;
        }

        if (monthDigits == 0 || month < 1 || month > 12) {
            return FALSE;  // Invalid month
        }

        filter->month = month;

        // Check if day is specified
        if (dateStr[parsePos] == L'-') {
            parsePos++;  // Skip '-'

            // Extract day (1-2 digits)
            int dayDigits = 0;
            while (dayDigits < 2 && dateStr[parsePos] >= L'0' && dateStr[parsePos] <= L'9') {
                day = day * 10 + (dateStr[parsePos] - L'0');
                parsePos++;
                dayDigits++;
            }

            if (dayDigits == 0 || day < 1 || day > 31) {
                return FALSE;  // Invalid day
            }

            filter->day = day;
        }
    }

    // Ensure we've consumed the entire string
    if (dateStr[parsePos] != L'\0') {
        return FALSE;  // Extra characters after date
    }

    // Validate calendar correctness (reject Feb 30, April 31, Feb 29 in non-leap years, etc.)
    if (filter->enabled && filter->month != -1 && filter->day != -1) {
        if (!IsValidCalendarDate(filter->year, filter->month, filter->day)) {
            return FALSE;  // Invalid calendar date (e.g., Feb 30, April 31)
        }
    }

    return TRUE;
}

/**
 * Check if a file's timestamp matches the date filter
 * @param fileTime  FILETIME from WIN32_FIND_DATA
 * @param filter    DateFilter to check against
 * @return TRUE if file matches filter (or filter disabled), FALSE otherwise
 */
BOOL MatchesDateFilter(FILETIME* fileTime, DateFilter* filter) {
    // If filter is disabled, all files match
    if (!filter || !filter->enabled) {
        return TRUE;
    }

    // Convert FILETIME to SYSTEMTIME
    SYSTEMTIME stUTC, stLocal;
    if (!FileTimeToSystemTime(fileTime, &stUTC)) {
        return FALSE;  // Couldn't convert time, exclude file
    }

    // Convert to local time
    if (!SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
        // If timezone conversion fails, use UTC
        stLocal = stUTC;
    }

    // Check year
    if (filter->year != -1 && stLocal.wYear != filter->year) {
        return FALSE;
    }

    // Check month (if specified)
    if (filter->month != -1 && stLocal.wMonth != filter->month) {
        return FALSE;
    }

    // Check day (if specified)
    if (filter->day != -1 && stLocal.wDay != filter->day) {
        return FALSE;
    }

    return TRUE;
}

/**
 * Check if a file's size matches the size filter
 * @param fileSize  File size in bytes (from WIN32_FIND_DATA)
 * @param filter    SizeFilter to check against
 * @return TRUE if file matches filter (or filter disabled), FALSE otherwise
 */
BOOL MatchesSizeFilter(ULONGLONG fileSize, SizeFilter* filter) {
    // If filter is disabled, all files match
    if (!filter || !filter->enabled) {
        return TRUE;
    }

    // Check minimum size (if specified)
    if (filter->minSize != -1 && (LONGLONG)fileSize < filter->minSize) {
        return FALSE;
    }

    // Check maximum size (if specified)
    if (filter->maxSize != -1 && (LONGLONG)fileSize > filter->maxSize) {
        return FALSE;
    }

    return TRUE;
}

// Validate path for dangerous or invalid characters
BOOL ValidatePathFormat(LPCWSTR path) {
    int len = lstrlenW(path);
    if (len == 0) {
        return FALSE;
    }

    // Check for invalid characters (excluding * and ? which are valid wildcards)
    // Invalid Windows path characters: < > " | and control characters
    for (int i = 0; i < len; i++) {
        WCHAR c = path[i];

        // Check for null bytes (shouldn't happen but be defensive)
        if (c == L'\0' && i < len - 1) {
            return FALSE;
        }

        // Check for dangerous characters
        if (c == L'<' || c == L'>' || c == L'"' || c == L'|') {
            return FALSE;
        }

        // Check for control characters (0x00-0x1F)
        if (c < 0x20) {
            return FALSE;
        }
    }

    // Validate basic path structure
    // Must be either:
    // 1. Drive letter path (C:\, D:\, etc.)
    // 2. UNC path (\\server\share)
    // 3. Relative path (allowed for flexibility)

    if (len >= 2) {
        // Check for drive letter (e.g., C:)
        if ((path[0] >= L'A' && path[0] <= L'Z') ||
            (path[0] >= L'a' && path[0] <= L'z')) {
            if (path[1] == L':') {
                return TRUE;  // Valid drive letter path
            }
        }

        // Check for UNC path (\\server\share)
        if (path[0] == L'\\' && path[1] == L'\\') {
            return TRUE;  // Valid UNC path
        }
    }

    // Check for relative path (doesn't start with \ or drive letter)
    // Allow relative paths starting with a directory name or wildcard
    if ((path[0] >= L'A' && path[0] <= L'Z') ||
        (path[0] >= L'a' && path[0] <= L'z') ||
        (path[0] >= L'0' && path[0] <= L'9') ||
        path[0] == L'*' || path[0] == L'?') {
        return TRUE;
    }

    // If none of the above, reject
    return FALSE;
}

// Expand path wildcards and enumerate files in all matching directories
void ExpandPathWildcardsAndEnumerate(LPWSTR targetPath, LPCWSTR pattern, LPCWSTR excludePatterns, LPCWSTR excludePathPatterns,
                                      BOOL suppressErrors, int currentDepth,
                                      int maxDepth, FileStats* stats, DateFilter* dateFilter, SizeFilter* sizeFilter,
                                      BOOL includeDirs) {
    LPWSTR basePath = NULL;
    LPWSTR wildcardSegment = NULL;
    LPWSTR remainingPath = NULL;
    LPWSTR lastSlash;
    LPWSTR nextSlash;
    int baseLen;
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    LPWSTR searchPath = NULL;
    LPWSTR expandedPath = NULL;

    // Check if max results limit already reached
    if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
        stats->limitReached = TRUE;
        return;
    }

    // Enforce internal recursion depth limit for safety
    if (currentDepth > MAX_RECURSION_DEPTH) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Maximum recursion depth exceeded (%d)\n", MAX_RECURSION_DEPTH);
        }
        return;
    }

    // Check user-specified depth limit
    if (maxDepth >= 0 && currentDepth > maxDepth) {
        return;
    }

    // Allocate buffers on heap to avoid stack overflow in deep recursion
    basePath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));
    wildcardSegment = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATTERN_LENGTH * sizeof(WCHAR));
    remainingPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH_LENGTH * sizeof(WCHAR));

    if (!basePath || !wildcardSegment || !remainingPath) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
        }
        if (basePath) HeapFree(GetProcessHeap(), 0, basePath);
        if (wildcardSegment) HeapFree(GetProcessHeap(), 0, wildcardSegment);
        if (remainingPath) HeapFree(GetProcessHeap(), 0, remainingPath);
        return;
    }

    // Find the first wildcard in the path
    LPWSTR wildcardPos = targetPath;
    while (*wildcardPos && *wildcardPos != L'*' && *wildcardPos != L'?') {
        wildcardPos++;
    }

    if (!*wildcardPos) {
        // No wildcards, just enumerate directly
        EnumerateFiles(targetPath, pattern, excludePatterns, excludePathPatterns, suppressErrors, currentDepth, maxDepth, stats,
                      dateFilter, sizeFilter, includeDirs);
        HeapFree(GetProcessHeap(), 0, basePath);
        HeapFree(GetProcessHeap(), 0, wildcardSegment);
        HeapFree(GetProcessHeap(), 0, remainingPath);
        return;
    }

    // Find the directory separator before the wildcard (if any)
    lastSlash = wildcardPos;
    while (lastSlash > targetPath && *lastSlash != L'\\') {
        lastSlash--;
    }

    // Determine where the wildcard segment actually starts.
    // If no separator exists before the wildcard, the segment starts at targetPath.
    LPWSTR wildcardStart = targetPath;
    if (*lastSlash == L'\\') {
        wildcardStart = lastSlash + 1;
    } else {
        lastSlash = targetPath;
    }

    // Find the end of the wildcard segment (next slash or end)
    nextSlash = wildcardPos;
    while (*nextSlash && *nextSlash != L'\\') {
        nextSlash++;
    }

    // Extract base path (before wildcard segment)
    if (wildcardStart > targetPath && *(wildcardStart - 1) == L'\\') {
        baseLen = (int)(wildcardStart - targetPath - 1);
    } else {
        baseLen = 0;
    }
    if (baseLen > 0) {
        if (baseLen >= MAX_PATH_LENGTH) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Base path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
            }
            HeapFree(GetProcessHeap(), 0, basePath);
            HeapFree(GetProcessHeap(), 0, wildcardSegment);
            HeapFree(GetProcessHeap(), 0, remainingPath);
            return;
        }
        memcpy(basePath, targetPath, baseLen * sizeof(WCHAR));
        basePath[baseLen] = L'\0';
    } else {
        basePath[0] = L'\0';
    }

    // Extract wildcard segment
    int wildcardLen = (int)(nextSlash - wildcardStart);
    if (wildcardLen > 0) {
        if (wildcardLen >= MAX_PATTERN_LENGTH) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Wildcard segment exceeds maximum length (%d characters)\n", MAX_PATTERN_LENGTH);
            }
            HeapFree(GetProcessHeap(), 0, basePath);
            HeapFree(GetProcessHeap(), 0, wildcardSegment);
            HeapFree(GetProcessHeap(), 0, remainingPath);
            return;
        }
        memcpy(wildcardSegment, wildcardStart, wildcardLen * sizeof(WCHAR));
        wildcardSegment[wildcardLen] = L'\0';
    } else {
        lstrcpyW(wildcardSegment, L"*");
    }

    // Extract remaining path (after wildcard segment)
    if (*nextSlash) {
        int remainingLen = lstrlenW(nextSlash + 1);
        if (remainingLen >= MAX_PATH_LENGTH) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Remaining path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
            }
            HeapFree(GetProcessHeap(), 0, basePath);
            HeapFree(GetProcessHeap(), 0, wildcardSegment);
            HeapFree(GetProcessHeap(), 0, remainingPath);
            return;
        }
        lstrcpyW(remainingPath, nextSlash + 1);
    } else {
        remainingPath[0] = L'\0';
    }

    // Build search path
    int searchLen = lstrlenW(basePath) + 4;
    searchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   searchLen * sizeof(WCHAR));
    if (!searchPath) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
        }
        HeapFree(GetProcessHeap(), 0, basePath);
        HeapFree(GetProcessHeap(), 0, wildcardSegment);
        HeapFree(GetProcessHeap(), 0, remainingPath);
        return;
    }

    if (baseLen > 0) {
        lstrcpyW(searchPath, basePath);
        lstrcatW(searchPath, L"\\*");
    } else {
        lstrcpyW(searchPath, L"*");
    }

    // Enumerate directories matching the wildcard
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        if (!suppressErrors) {
            char pathUtf8[1024];
            WideCharToUtf8(basePath, pathUtf8, sizeof(pathUtf8));
            BeaconPrintf(CALLBACK_ERROR, "[!] Cannot access directory: %s (Error: %d)\n",
                        pathUtf8, GetLastError());
            stats->errorCount++;
        }
        HeapFree(GetProcessHeap(), 0, searchPath);
        HeapFree(GetProcessHeap(), 0, basePath);
        HeapFree(GetProcessHeap(), 0, wildcardSegment);
        HeapFree(GetProcessHeap(), 0, remainingPath);
        return;
    }

    do {
        // Skip . and ..
        if (lstrcmpW(findData.cFileName, L".") == 0 ||
            lstrcmpW(findData.cFileName, L"..") == 0) {
            continue;
        }

        // Only process directories
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }

        // Check if directory name matches wildcard pattern
        if (!SimpleWildcardMatch(wildcardSegment, findData.cFileName)) {
            continue;
        }

        // Build expanded path
        int expandedLen = lstrlenW(basePath) + lstrlenW(findData.cFileName) +
                         lstrlenW(remainingPath) + 4;

        // Validate path length (Windows MAX_PATH is 260, but we allow up to MAX_PATH_LENGTH)
        if (expandedLen >= MAX_PATH_LENGTH) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Expanded path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
            }
            continue;
        }

        expandedPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        expandedLen * sizeof(WCHAR));
        if (!expandedPath) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
            }
            continue;
        }

        // Build the complete path with bounds checking
        // Track if path was successfully built
        BOOL pathBuiltSuccessfully = TRUE;
        int currentLen = 0;

        if (baseLen > 0) {
            lstrcpyW(expandedPath, basePath);
            currentLen = baseLen;  // Optimized: track length arithmetically instead of calling lstrlenW
            // Verify space for "\\"
            if (currentLen + 2 <= expandedLen) {
                lstrcatW(expandedPath, L"\\");
                currentLen++;
            } else {
                pathBuiltSuccessfully = FALSE;
            }
        } else {
            expandedPath[0] = L'\0';
        }

        // Verify space for fileName
        if (pathBuiltSuccessfully && currentLen + lstrlenW(findData.cFileName) + 1 <= expandedLen) {
            lstrcatW(expandedPath, findData.cFileName);
            currentLen += lstrlenW(findData.cFileName);  // Optimized: track length arithmetically
        } else {
            pathBuiltSuccessfully = FALSE;
        }

        // Add remaining path if present
        if (pathBuiltSuccessfully && remainingPath[0] != L'\0') {
            // Verify space for "\\" + remainingPath
            if (currentLen + 1 + lstrlenW(remainingPath) + 1 <= expandedLen) {
                lstrcatW(expandedPath, L"\\");
                lstrcatW(expandedPath, remainingPath);
            } else {
                pathBuiltSuccessfully = FALSE;
            }
        }

        // Only enumerate if path was successfully built
        if (pathBuiltSuccessfully) {
            if (MatchesPatternList(expandedPath, excludePathPatterns)) {
                HeapFree(GetProcessHeap(), 0, expandedPath);
                continue;
            }

            if (remainingPath[0] != L'\0' && PathContainsWildcards(remainingPath)) {
                ExpandPathWildcardsAndEnumerate(expandedPath, pattern, excludePatterns, excludePathPatterns,
                                               suppressErrors, currentDepth + 1,
                                               maxDepth, stats, dateFilter, sizeFilter, includeDirs);
            } else if (remainingPath[0] != L'\0') {
                // Literal remainder: resolve to file or directory before enumerating.
                // Treating a file path as a directory used to fail with ERROR_DIRECTORY (267),
                // hiding hits when the wildcard pattern targets a specific file (e.g. ConsoleHost_history.txt).
                WIN32_FILE_ATTRIBUTE_DATA pathInfo;
                if (!GetFileAttributesExW(expandedPath, GetFileExInfoStandard, &pathInfo)) {
                    DWORD err = GetLastError();
                    // Wildcards inherently allow non-matches; suppress the missing-entry noise.
                    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND && !suppressErrors) {
                        char pathUtf8[1024];
                        WideCharToUtf8(expandedPath, pathUtf8, sizeof(pathUtf8));
                        BeaconPrintf(CALLBACK_ERROR, "[!] Cannot access path: %s (Error: %lu)\n",
                                    pathUtf8, err);
                        stats->errorCount++;
                    }
                } else if (pathInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    EnumerateFiles(expandedPath, pattern, excludePatterns, excludePathPatterns, suppressErrors,
                                  currentDepth + 1, maxDepth, stats, dateFilter, sizeFilter, includeDirs);
                } else {
                    LPWSTR fileName = expandedPath;
                    for (LPWSTR scan = expandedPath; *scan; scan++) {
                        if (*scan == L'\\' || *scan == L'/') {
                            fileName = scan + 1;
                        }
                    }

                    ULONGLONG fileSize = ((ULONGLONG)pathInfo.nFileSizeHigh << 32) | pathInfo.nFileSizeLow;

                    if (SimpleWildcardMatch(pattern, fileName) &&
                        MatchesDateFilter(&pathInfo.ftLastWriteTime, dateFilter) &&
                        MatchesSizeFilter(fileSize, sizeFilter) &&
                        !MatchesPatternList(fileName, excludePatterns)) {

                        if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
                            stats->limitReached = TRUE;
                        } else {
                            char timestamp[32];
                            char sizeStr[32];
                            char pathUtf8[2048];
                            FormatFileTime(&pathInfo.ftLastWriteTime, timestamp, sizeof(timestamp));
                            FormatFileSize(fileSize, sizeStr, sizeof(sizeStr));
                            WideCharToUtf8(expandedPath, pathUtf8, sizeof(pathUtf8));
                            BeaconPrintf(CALLBACK_OUTPUT,
                                       "%s (Size: %s, Modified: %s)\n",
                                       pathUtf8, sizeStr, timestamp);
                            stats->fileCount++;
                            stats->resultCount++;
                            stats->totalSize += fileSize;
                        }
                    }
                }
            } else {
                EnumerateFiles(expandedPath, pattern, excludePatterns, excludePathPatterns, suppressErrors,
                              currentDepth + 1, maxDepth, stats, dateFilter, sizeFilter, includeDirs);
            }
        }

        HeapFree(GetProcessHeap(), 0, expandedPath);

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    HeapFree(GetProcessHeap(), 0, searchPath);
    HeapFree(GetProcessHeap(), 0, basePath);
    HeapFree(GetProcessHeap(), 0, wildcardSegment);
    HeapFree(GetProcessHeap(), 0, remainingPath);
}

// Recursive file enumeration function
void EnumerateFiles(LPWSTR basePath, LPCWSTR pattern, LPCWSTR excludePatterns, LPCWSTR excludePathPatterns, BOOL suppressErrors,
                    int currentDepth, int maxDepth, FileStats* stats, DateFilter* dateFilter, SizeFilter* sizeFilter,
                    BOOL includeDirs) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    LPWSTR searchPath;
    LPWSTR fullPath;
    int baseLen;

    // Check if max results limit already reached
    if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
        stats->limitReached = TRUE;
        return;
    }

    // Enforce internal recursion depth limit for safety
    if (currentDepth > MAX_RECURSION_DEPTH) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Maximum recursion depth exceeded (%d)\n", MAX_RECURSION_DEPTH);
        }
        return;
    }

    // Check user-specified depth limit
    if (maxDepth >= 0 && currentDepth > maxDepth) {
        return;
    }

    if (MatchesPatternList(basePath, excludePathPatterns)) {
        return;
    }

    baseLen = lstrlenW(basePath);

    // Validate base path length
    if (baseLen >= MAX_PATH_LENGTH) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Base path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
        }
        return;
    }

    // Allocate buffer for search path (basePath + \* + null)
    searchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   (baseLen + 4) * sizeof(WCHAR));
    if (!searchPath) {
        if (!suppressErrors) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
        }
        return;
    }

    // Build search path: "basePath\*"
    lstrcpyW(searchPath, basePath);
    if (baseLen > 0 && basePath[baseLen - 1] != L'\\') {
        lstrcatW(searchPath, L"\\");
    }
    lstrcatW(searchPath, L"*");

    // Start finding files
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        if (!suppressErrors) {
            char pathUtf8[1024];
            WideCharToUtf8(basePath, pathUtf8, sizeof(pathUtf8));
            BeaconPrintf(CALLBACK_ERROR, "[!] Cannot access directory: %s (Error: %d)\n",
                        pathUtf8, GetLastError());
            stats->errorCount++;
        }
        HeapFree(GetProcessHeap(), 0, searchPath);
        return;
    }

    do {
        if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
            stats->limitReached = TRUE;
            break;
        }

        // Skip . and ..
        if (lstrcmpW(findData.cFileName, L".") == 0 ||
            lstrcmpW(findData.cFileName, L"..") == 0) {
            continue;
        }

        // Build full path
        int fileNameLen = lstrlenW(findData.cFileName);
        int fullPathLen = baseLen + fileNameLen + 2;

        // Validate full path length
        if (fullPathLen >= MAX_PATH_LENGTH) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Full path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
            }
            continue;
        }

        fullPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     fullPathLen * sizeof(WCHAR));
        if (!fullPath) {
            if (!suppressErrors) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed\n");
            }
            continue;
        }

        // Build the complete path with bounds checking
        // Track if path was successfully built
        BOOL pathBuiltSuccessfully = TRUE;
        lstrcpyW(fullPath, basePath);
        int currentLen = baseLen;  // Optimized: track length arithmetically instead of calling lstrlenW

        if (baseLen > 0 && basePath[baseLen - 1] != L'\\') {
            // Verify space for "\\"
            if (currentLen + 2 <= fullPathLen) {
                lstrcatW(fullPath, L"\\");
                currentLen++;
            } else {
                pathBuiltSuccessfully = FALSE;
            }
        }

        // Verify space for fileName
        if (pathBuiltSuccessfully && currentLen + lstrlenW(findData.cFileName) + 1 <= fullPathLen) {
            lstrcatW(fullPath, findData.cFileName);
        } else {
            pathBuiltSuccessfully = FALSE;
        }

        // Only process if path was successfully built
        if (!pathBuiltSuccessfully) {
            HeapFree(GetProcessHeap(), 0, fullPath);
            continue;
        }

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MatchesPatternList(fullPath, excludePathPatterns)) {
                HeapFree(GetProcessHeap(), 0, fullPath);
                continue;
            }

            if (includeDirs &&
                SimpleWildcardMatch(pattern, findData.cFileName) &&
                MatchesDateFilter(&findData.ftLastWriteTime, dateFilter) &&
                !MatchesPatternList(findData.cFileName, excludePatterns)) {
                if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
                    stats->limitReached = TRUE;
                    HeapFree(GetProcessHeap(), 0, fullPath);
                    break;
                }

                char timestamp[32];
                char pathUtf8[2048];
                FormatFileTime(&findData.ftLastWriteTime, timestamp, sizeof(timestamp));
                WideCharToUtf8(fullPath, pathUtf8, sizeof(pathUtf8));

                BeaconPrintf(CALLBACK_OUTPUT,
                           "%s [DIR] (Modified: %s)\n",
                           pathUtf8, timestamp);

                stats->directoryCount++;
                stats->resultCount++;
            }

            // Recurse into subdirectory
            EnumerateFiles(fullPath, pattern, excludePatterns, excludePathPatterns, suppressErrors,
                          currentDepth + 1, maxDepth, stats, dateFilter, sizeFilter, includeDirs);
        } else {
            // Calculate file size first for size filtering
            ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) |
                                findData.nFileSizeLow;

            // Check if file matches pattern, date filter, size filter, and not excluded
            if (SimpleWildcardMatch(pattern, findData.cFileName) &&
                MatchesDateFilter(&findData.ftLastWriteTime, dateFilter) &&
                MatchesSizeFilter(fileSize, sizeFilter) &&
                !MatchesPatternList(findData.cFileName, excludePatterns) &&
                !MatchesPatternList(fullPath, excludePathPatterns)) {

                // Check if we've already reached the limit
                if (stats->maxResults != -1 && stats->resultCount >= (DWORD)stats->maxResults) {
                    stats->limitReached = TRUE;
                    HeapFree(GetProcessHeap(), 0, fullPath);
                    break;  // Stop processing files in this directory
                }

                // Format timestamp
                char timestamp[32];
                FormatFileTime(&findData.ftLastWriteTime, timestamp, sizeof(timestamp));

                // Format file size
                char sizeStr[32];
                FormatFileSize(fileSize, sizeStr, sizeof(sizeStr));

                // Convert path to UTF-8
                char pathUtf8[2048];
                WideCharToUtf8(fullPath, pathUtf8, sizeof(pathUtf8));

                // Output file info
                BeaconPrintf(CALLBACK_OUTPUT,
                           "%s (Size: %s, Modified: %s)\n",
                           pathUtf8, sizeStr, timestamp);

                // Update statistics
                stats->fileCount++;
                stats->resultCount++;
                stats->totalSize += fileSize;
            }
        }

        HeapFree(GetProcessHeap(), 0, fullPath);

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    HeapFree(GetProcessHeap(), 0, searchPath);
}

#ifdef BOF
// BOF entry point
void go(char* args, int len) {
    datap parser;
    LPWSTR targetPath;
    LPWSTR pattern;
    LPWSTR excludePatterns;
    LPWSTR excludePathPatterns;
    LPWSTR dateFilterStr;
    int suppressErrors;
    int maxDepth;
    int maxResults;
    int includeDirs;
    int minSize;
    int maxSize;
    FileStats stats;
    DateFilter dateFilter;
    SizeFilter sizeFilter;

    // Initialize statistics
    memset(&stats, 0, sizeof(FileStats));

    // Parse arguments: targetPath (wstring), pattern (wstring), excludePatterns (wstring), excludePathPatterns (wstring), suppressErrors (int), maxDepth (int), maxResults (int), includeDirs (int), dateFilter (wstring), minSize (int), maxSize (int)
    BeaconDataParse(&parser, args, len);
    targetPath = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (!targetPath) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract target path from arguments\n");
        return;
    }

    pattern = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (!pattern) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract pattern from arguments\n");
        return;
    }

    excludePatterns = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (!excludePatterns) {
        excludePatterns = L"";  // Default to empty (no exclusions)
    }

    excludePathPatterns = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (!excludePathPatterns) {
        excludePathPatterns = L"";
    }

    // Validate exclude patterns total length (defense in depth)
    if (excludePatterns && lstrlenW(excludePatterns) > 4096) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Exclude patterns string too long (max 4096 chars)\n");
        return;
    }

    if (excludePathPatterns && lstrlenW(excludePathPatterns) > 4096) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Exclude path patterns string too long (max 4096 chars)\n");
        return;
    }

    suppressErrors = BeaconDataInt(&parser);
    maxDepth = BeaconDataInt(&parser);
    maxResults = BeaconDataInt(&parser);
    includeDirs = BeaconDataInt(&parser);

    // Validate integer parameters for defense in depth
    if (maxDepth < -1 || maxDepth > 1000) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid maxDepth: %d (must be -1 to 1000)\n", maxDepth);
        return;
    }
    if (maxResults < -1) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid maxResults: %d (must be -1 or positive)\n", maxResults);
        return;
    }
    if (includeDirs != 0 && includeDirs != 1) {
        includeDirs = 0;  // Default to false for safety
    }
    if (suppressErrors != 0 && suppressErrors != 1) {
        suppressErrors = 0;  // Default to false for safety
    }

    dateFilterStr = (LPWSTR)BeaconDataExtract(&parser, NULL);
    if (!dateFilterStr) {
        dateFilterStr = L"";  // Default to empty (no filtering)
    }

    minSize = BeaconDataInt(&parser);
    maxSize = BeaconDataInt(&parser);

    if (minSize < -1) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid minSize: %d (must be -1 or positive)\n", minSize);
        return;
    }
    if (maxSize < -1) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid maxSize: %d (must be -1 or positive)\n", maxSize);
        return;
    }
    if (minSize != -1 && maxSize != -1 && minSize > maxSize) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid size range: minSize (%d) > maxSize (%d)\n",
                     minSize, maxSize);
        return;
    }

    // Set max results in stats structure
    stats.maxResults = maxResults;
    stats.limitReached = FALSE;

    // Initialize size filter
    sizeFilter.enabled = FALSE;
    sizeFilter.minSize = -1;
    sizeFilter.maxSize = -1;

    if (minSize != -1 || maxSize != -1) {
        sizeFilter.enabled = TRUE;
        sizeFilter.minSize = minSize;
        sizeFilter.maxSize = maxSize;
    }

    // Validate inputs
    if (lstrlenW(targetPath) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Empty target path\n");
        return;
    }

    if (lstrlenW(targetPath) >= MAX_PATH_LENGTH) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Target path exceeds maximum length (%d characters)\n", MAX_PATH_LENGTH);
        return;
    }

    // Validate path format and check for dangerous characters
    if (!ValidatePathFormat(targetPath)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid path format or dangerous characters detected\n");
        return;
    }

    if (lstrlenW(pattern) == 0) {
        pattern = L"*";  // Default to all files
    }

    if (lstrlenW(pattern) >= MAX_PATTERN_LENGTH) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Pattern exceeds maximum length (%d characters)\n", MAX_PATTERN_LENGTH);
        return;
    }

    // Parse date filter
    if (!ParseDateFilter(dateFilterStr, &dateFilter)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid date filter format. Use: YYYY, YYYY-MM, or YYYY-MM-DD\n");
        return;
    }

    // Print header
    char pathUtf8[MAX_PATH_LENGTH * 2];  // UTF-8 can be up to 2x size
    char patternUtf8[MAX_PATTERN_LENGTH];
    WideCharToUtf8(targetPath, pathUtf8, sizeof(pathUtf8));
    WideCharToUtf8(pattern, patternUtf8, sizeof(patternUtf8));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Recursive File Listing\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target Path: %s\n", pathUtf8);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Pattern: %s\n", patternUtf8);
    if (maxDepth >= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Max Depth: %d\n", maxDepth);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Max Depth: Unlimited\n");
    }

    // Display max results limit
    if (maxResults >= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Max Results: %d\n", maxResults);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Max Results: Unlimited\n");
    }
    if (includeDirs) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Include Directories: true\n");
    }
    if (lstrlenW(excludePathPatterns) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Exclude Path Filters: configured\n");
    }

    // Display date filter if enabled
    if (dateFilter.enabled) {
        if (dateFilter.day != -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Date Filter: %04d-%02d-%02d\n",
                        dateFilter.year, dateFilter.month, dateFilter.day);
        } else if (dateFilter.month != -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Date Filter: %04d-%02d\n",
                        dateFilter.year, dateFilter.month);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Date Filter: %04d\n", dateFilter.year);
        }
    }

    // Display size filter if enabled
    if (sizeFilter.enabled) {
        if (sizeFilter.minSize != -1 && sizeFilter.maxSize != -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Size Filter: %lld - %lld bytes\n",
                        sizeFilter.minSize, sizeFilter.maxSize);
        } else if (sizeFilter.minSize != -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Min Size: %lld bytes\n", sizeFilter.minSize);
        } else if (sizeFilter.maxSize != -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Max Size: %lld bytes\n", sizeFilter.maxSize);
        }
    }

    // Check if path contains wildcards
    if (PathContainsWildcards(targetPath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Path contains wildcards - expanding...\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    // Enumerate files (with path wildcard expansion if needed)
    if (PathContainsWildcards(targetPath)) {
        ExpandPathWildcardsAndEnumerate(targetPath, pattern, excludePatterns, excludePathPatterns, suppressErrors, 0, maxDepth,
                                        &stats, &dateFilter, &sizeFilter, includeDirs);
    } else {
        EnumerateFiles(targetPath, pattern, excludePatterns, excludePathPatterns, suppressErrors, 0, maxDepth,
                      &stats, &dateFilter, &sizeFilter, includeDirs);
    }

    // Print summary
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Summary:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+]   Files Found: %d\n", stats.fileCount);
    if (includeDirs) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Directories Found: %d\n", stats.directoryCount);
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Results Found: %d\n", stats.resultCount);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+]   Total Size: %llu bytes", stats.totalSize);

    // Format total size in human-readable format
    if (stats.totalSize >= 1073741824) {  // >= 1 GB
        double sizeGB = (double)stats.totalSize / 1073741824.0;
        BeaconPrintf(CALLBACK_OUTPUT, " (%.2f GB)\n", sizeGB);
    } else if (stats.totalSize >= 1048576) {  // >= 1 MB
        double sizeMB = (double)stats.totalSize / 1048576.0;
        BeaconPrintf(CALLBACK_OUTPUT, " (%.2f MB)\n", sizeMB);
    } else if (stats.totalSize >= 1024) {  // >= 1 KB
        double sizeKB = (double)stats.totalSize / 1024.0;
        BeaconPrintf(CALLBACK_OUTPUT, " (%.2f KB)\n", sizeKB);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    if (stats.errorCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+]   Errors: %d\n", stats.errorCount);
    }

    if (stats.limitReached) {
        if (includeDirs) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] WARNING: Maximum results limit reached (%d results). Use --max-results -1 for unlimited.\n", maxResults);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] WARNING: Maximum results limit reached (%d files). Use --max-results -1 for unlimited.\n", maxResults);
        }
    }
}

#else
// Test harness for local execution
#include <stdio.h>

int main(int argc, char** argv) {
    printf("Test mode - compile with -DBOF for BOF mode\n");
    printf("Usage: lsfiles.exe <path> <pattern> <suppress_errors> <max_depth>\n");
    printf("Example: lsfiles.exe C:\\\\Windows *.exe 0 -1\n");
    return 0;
}
#endif
