/*
 * enum-user-right BOF
 *
 * Queries the current LSA policy on the local computer or a remote host for
 * the accounts assigned one user right.  It uses the documented LSA client
 * APIs; a remote query is transported over the target's LSA RPC endpoint.
 *
 * Argument contract (two serialized WSTR values):
 *   1. computer name, empty or "." for local; remote names may use \\host
 *   2. user-right name, e.g. SeMachineAccountPrivilege
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include "beacon.h"

#define MAX_INPUT_CHARS 1024
#define DISPLAY_CHARS   512

/* ntstatus.h is not included by MinGW's ntsecapi.h. */
#define STATUS_SUCCESS_VALUE           ((NTSTATUS)0x00000000L)
#define STATUS_SOME_NOT_MAPPED_VALUE   ((NTSTATUS)0x00000107L)
#define STATUS_NO_MORE_ENTRIES_VALUE   ((NTSTATUS)0x8000001AL)

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenPolicy(
    PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaEnumerateAccountsWithUserRight(
    LSA_HANDLE, PLSA_UNICODE_STRING, PLSA_ENUMERATION_INFORMATION *, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaLookupSids(
    LSA_HANDLE, ULONG, PSID *, PLSA_REFERENCED_DOMAIN_LIST *, PLSA_TRANSLATED_NAME *);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaFreeMemory(PVOID);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaClose(LSA_HANDLE);
DECLSPEC_IMPORT ULONG WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR *);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

static SIZE_T WideLength(const WCHAR *value, SIZE_T maximum) {
    SIZE_T length = 0;
    if (!value) {
        return 0;
    }
    while (length < maximum && value[length] != L'\0') {
        length++;
    }
    return length;
}

static BOOL IsValidPackedWideString(const WCHAR *value, int byteLength) {
    SIZE_T chars;
    if (!value || byteLength < (int)sizeof(WCHAR) || (byteLength % (int)sizeof(WCHAR)) != 0) {
        return FALSE;
    }
    chars = (SIZE_T)byteLength / sizeof(WCHAR);
    return WideLength(value, chars) < chars;
}

static BOOL IsLocalComputer(const WCHAR *computer) {
    return !computer || computer[0] == L'\0' ||
        (computer[0] == L'.' && computer[1] == L'\0');
}

static WCHAR *BuildSystemName(const WCHAR *computer) {
    HANDLE heap;
    SIZE_T computerLength;
    SIZE_T prefixLength;
    SIZE_T i;
    WCHAR *systemName;

    if (IsLocalComputer(computer)) {
        return NULL;
    }

    computerLength = WideLength(computer, MAX_INPUT_CHARS + 1);
    if (computerLength == 0 || computerLength > MAX_INPUT_CHARS) {
        return NULL;
    }

    prefixLength = (computerLength >= 2 && computer[0] == L'\\' && computer[1] == L'\\') ? 0 : 2;
    heap = KERNEL32$GetProcessHeap();
    systemName = (WCHAR *)KERNEL32$HeapAlloc(
        heap, HEAP_ZERO_MEMORY, (computerLength + prefixLength + 1) * sizeof(WCHAR));
    if (!systemName) {
        return NULL;
    }

    if (prefixLength != 0) {
        systemName[0] = L'\\';
        systemName[1] = L'\\';
    }
    for (i = 0; i < computerLength; i++) {
        systemName[prefixLength + i] = computer[i];
    }
    return systemName;
}

static void CopyLsaString(WCHAR *destination, SIZE_T destinationChars, const LSA_UNICODE_STRING *source) {
    SIZE_T sourceChars;
    SIZE_T copyChars;
    SIZE_T i;

    if (!destination || destinationChars == 0) {
        return;
    }
    destination[0] = L'\0';
    if (!source || !source->Buffer) {
        return;
    }
    sourceChars = (SIZE_T)source->Length / sizeof(WCHAR);
    copyChars = sourceChars < destinationChars - 1 ? sourceChars : destinationChars - 1;
    for (i = 0; i < copyChars; i++) {
        destination[i] = source->Buffer[i];
    }
    destination[copyChars] = L'\0';
}

static const char *SidTypeName(SID_NAME_USE use) {
    switch (use) {
        case SidTypeUser: return "User";
        case SidTypeGroup: return "Group";
        case SidTypeDomain: return "Domain";
        case SidTypeAlias: return "Alias";
        case SidTypeWellKnownGroup: return "WellKnownGroup";
        case SidTypeDeletedAccount: return "DeletedAccount";
        case SidTypeInvalid: return "Invalid";
        case SidTypeUnknown: return "Unknown";
        case SidTypeComputer: return "Computer";
        case SidTypeLabel: return "Label";
        default: return "Other";
    }
}

static void PrintSidFallback(PSID sid, ULONG index) {
    LPWSTR sidString = NULL;
    if (ADVAPI32$ConvertSidToStringSidW(sid, &sidString) && sidString) {
        BeaconPrintf(CALLBACK_OUTPUT, "[%lu] %S (unresolved)\n", index, sidString);
        KERNEL32$LocalFree((HLOCAL)sidString);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[%lu] <unresolved SID; ConvertSidToStringSidW failed>\n", index);
    }
}

static void PrintAccount(LSA_HANDLE policy, PSID sid, ULONG index) {
    NTSTATUS status;
    PLSA_REFERENCED_DOMAIN_LIST domains = NULL;
    PLSA_TRANSLATED_NAME names = NULL;
    WCHAR account[DISPLAY_CHARS];
    WCHAR domain[DISPLAY_CHARS];

    status = ADVAPI32$LsaLookupSids(policy, 1, &sid, &domains, &names);
    if ((status == STATUS_SUCCESS_VALUE || status == STATUS_SOME_NOT_MAPPED_VALUE) &&
        names && names[0].Use != SidTypeUnknown && names[0].Name.Buffer && names[0].Name.Length != 0) {
        CopyLsaString(account, DISPLAY_CHARS, &names[0].Name);
        domain[0] = L'\0';
        if (domains && names[0].DomainIndex >= 0 && (ULONG)names[0].DomainIndex < domains->Entries) {
            CopyLsaString(domain, DISPLAY_CHARS, &domains->Domains[names[0].DomainIndex].Name);
        }
        if (domain[0] != L'\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "[%lu] %S\\%S (%s)\n", index, domain, account, SidTypeName(names[0].Use));
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[%lu] %S (%s)\n", index, account, SidTypeName(names[0].Use));
        }
    } else {
        PrintSidFallback(sid, index);
    }

    if (names) {
        ADVAPI32$LsaFreeMemory(names);
    }
    if (domains) {
        ADVAPI32$LsaFreeMemory(domains);
    }
}

void go(char *args, int length) {
    datap parser;
    WCHAR *computer;
    WCHAR *rightName;
    int computerBytes = 0;
    int rightBytes = 0;
    WCHAR *systemName = NULL;
    LSA_UNICODE_STRING systemNameString;
    LSA_UNICODE_STRING rightNameString;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {0};
    LSA_HANDLE policy = NULL;
    PLSA_ENUMERATION_INFORMATION accounts = NULL;
    ULONG accountCount = 0;
    NTSTATUS status;
    ULONG i;

    BeaconDataParse(&parser, args, length);
    computer = (WCHAR *)BeaconDataExtract(&parser, &computerBytes);
    rightName = (WCHAR *)BeaconDataExtract(&parser, &rightBytes);

    if (!IsValidPackedWideString(computer, computerBytes) || !IsValidPackedWideString(rightName, rightBytes)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Expected computer and right-name arguments as null-terminated wide strings.\n");
        return;
    }
    if (WideLength(rightName, MAX_INPUT_CHARS + 1) == 0 || WideLength(rightName, MAX_INPUT_CHARS + 1) > MAX_INPUT_CHARS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] The user-right name must contain 1-%u characters.\n", MAX_INPUT_CHARS);
        return;
    }

    systemName = BuildSystemName(computer);
    if (!IsLocalComputer(computer) && !systemName) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unable to prepare the remote computer name.\n");
        return;
    }

    rightNameString.Buffer = rightName;
    rightNameString.Length = (USHORT)(WideLength(rightName, MAX_INPUT_CHARS) * sizeof(WCHAR));
    rightNameString.MaximumLength = rightNameString.Length;
    objectAttributes.Length = sizeof(objectAttributes);

    if (systemName) {
        systemNameString.Buffer = systemName;
        systemNameString.Length = (USHORT)(WideLength(systemName, MAX_INPUT_CHARS + 2) * sizeof(WCHAR));
        systemNameString.MaximumLength = systemNameString.Length;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying %S for %S\n", systemName, rightName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying local LSA policy for %S\n", rightName);
    }

    status = ADVAPI32$LsaOpenPolicy(
        systemName ? &systemNameString : NULL,
        &objectAttributes,
        POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION,
        &policy);
    if (status != STATUS_SUCCESS_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LsaOpenPolicy failed: NTSTATUS 0x%08lX (Win32 %lu)\n", (ULONG)status, ADVAPI32$LsaNtStatusToWinError(status));
        goto cleanup;
    }

    status = ADVAPI32$LsaEnumerateAccountsWithUserRight(policy, &rightNameString, &accounts, &accountCount);
    if (status == STATUS_NO_MORE_ENTRIES_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] No accounts are assigned %S.\n", rightName);
        goto cleanup;
    }
    if (status != STATUS_SUCCESS_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LsaEnumerateAccountsWithUserRight failed: NTSTATUS 0x%08lX (Win32 %lu)\n", (ULONG)status, ADVAPI32$LsaNtStatusToWinError(status));
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu account(s) assigned %S:\n", accountCount, rightName);
    for (i = 0; i < accountCount; i++) {
        if (accounts[i].Sid) {
            PrintAccount(policy, accounts[i].Sid, i + 1);
        }
    }

cleanup:
    if (accounts) {
        ADVAPI32$LsaFreeMemory(accounts);
    }
    if (policy) {
        ADVAPI32$LsaClose(policy);
    }
    if (systemName) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, systemName);
    }
}
