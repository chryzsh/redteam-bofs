#ifdef _WIN64
// Minimal stub for stack probing if the compiler inserts ___chkstk_ms
__declspec(naked) void ___chkstk_ms(void)
{
    __asm__("ret");
}
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include "beacon.h"

// NetAPI32 function declarations
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGroupDelUser(
    LPCWSTR servername,
    LPCWSTR groupname,
    LPCWSTR username
);

DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupDelMembers(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
);

// Error code constants
#ifndef NERR_Success
#define NERR_Success 0
#endif

#ifndef NERR_GroupNotFound
#define NERR_GroupNotFound 2220L
#endif

#ifndef NERR_UserNotFound
#define NERR_UserNotFound 2221L
#endif

#ifndef NERR_UserNotInGroup
#define NERR_UserNotInGroup 2237L
#endif

#ifndef NERR_SpeGroupOp
#define NERR_SpeGroupOp 2234L
#endif

#ifndef NERR_InvalidComputer
#define NERR_InvalidComputer 2351L
#endif

#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5L
#endif

#ifndef ERROR_NO_SUCH_ALIAS
#define ERROR_NO_SUCH_ALIAS 1376L
#endif

#ifndef ERROR_MEMBER_NOT_IN_ALIAS
#define ERROR_MEMBER_NOT_IN_ALIAS 1377L
#endif

#ifndef ERROR_NO_SUCH_MEMBER
#define ERROR_NO_SUCH_MEMBER 1387L
#endif

#ifndef ERROR_INVALID_MEMBER
#define ERROR_INVALID_MEMBER 1388L
#endif


/**
 * Checks if a wide string is empty or represents "local computer".
 *
 * Treats NULL, empty string, and "." as local computer.
 */
BOOL IsLocalComputer(const wchar_t *str) {
    if (!str || str[0] == L'\0') {
        return TRUE;
    }
    if (str[0] == L'.' && str[1] == L'\0') {
        return TRUE;
    }
    return FALSE;
}


/**
 * Maps NetGroupDelUser error codes to human-readable messages.
 */
const char* GetNetApiErrorMessage(NET_API_STATUS errorCode) {
    switch (errorCode) {
        case NERR_Success:
            return "Success";
        case ERROR_ACCESS_DENIED:
            return "Access denied. Insufficient privileges to remove user from group.";
        case NERR_UserNotInGroup:
            return "The user is not a member of the specified group.";
        case NERR_UserNotFound:
            return "The user account could not be found.";
        case NERR_GroupNotFound:
            return "The specified group is not a global/universal group.";
        case NERR_SpeGroupOp:
            return "Operation not allowed on this special group (e.g., Domain Users).";
        case NERR_InvalidComputer:
            return "The target computer is invalid (must be a domain controller).";
        case ERROR_INVALID_PARAMETER:
            return "Invalid parameter.";
        default:
            return "An unknown error occurred.";
    }
}


/**
 * Maps NetLocalGroupDelMembers error codes to human-readable messages.
 */
const char* GetNetLocalGroupErrorMessage(NET_API_STATUS errorCode) {
    switch (errorCode) {
        case NERR_Success:
            return "Success";
        case ERROR_ACCESS_DENIED:
            return "Access denied. Insufficient privileges to remove user from group.";
        case ERROR_MEMBER_NOT_IN_ALIAS:
            return "The user is not a member of the specified group.";
        case ERROR_NO_SUCH_MEMBER:
        case NERR_UserNotFound:
            return "The user account could not be found.";
        case ERROR_NO_SUCH_ALIAS:
        case NERR_GroupNotFound:
            return "The group does not exist as a global, universal, domain-local, or builtin group.";
        case ERROR_INVALID_MEMBER:
            return "The specified member is invalid for this group.";
        case NERR_InvalidComputer:
            return "The target computer is invalid (must be a domain controller).";
        case ERROR_INVALID_PARAMETER:
            return "Invalid parameter.";
        default:
            return "An unknown error occurred.";
    }
}


/**
 * BOF Entry Point: removeuser-domaingroup
 *
 * Removes a domain user from a domain group. Tries NetGroupDelUser first
 * (global/universal groups). If that returns NERR_GroupNotFound, retries
 * against the same server with NetLocalGroupDelMembers, which covers
 * domain-local and Builtin groups. Must target a domain controller for
 * the user's domain.
 *
 * Expected argument format (all wide strings):
 *   - groupname:    Domain group name (SAM account name, no DOMAIN\ prefix)
 *   - username:     User to remove (SAM account name, no DOMAIN\ prefix)
 *   - computername: DC name/FQDN (empty string only valid when running on the DC)
 */
void go(char *args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);

    wchar_t *groupName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *userName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *computerName = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!groupName || wcslen(groupName) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Group name is required.\n");
        return;
    }

    if (!userName || wcslen(userName) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Username is required.\n");
        return;
    }

    LPCWSTR targetComputer = IsLocalComputer(computerName) ? NULL : computerName;

    if (targetComputer) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Removing user '%ls' from domain group '%ls' on DC '%ls'...\n",
                     userName, groupName, targetComputer);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Removing user '%ls' from domain group '%ls' on local computer (must be a DC)...\n",
                     userName, groupName);
    }

    NET_API_STATUS status = NETAPI32$NetGroupDelUser(
        targetComputer,
        groupName,
        userName
    );

    if (status == NERR_Success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success: User '%ls' removed from group '%ls'.\n",
                     userName, groupName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed via NetGroupDelUser (global/universal group)\n");
        return;
    }

    if (status != NERR_GroupNotFound) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove user from group (NetGroupDelUser).\n");
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: %s (Code: %lu)\n", GetNetApiErrorMessage(status), status);
        return;
    }

    // NERR_GroupNotFound: not a global/universal group. Retry as a
    // domain-local or Builtin group (an alias in SAM terms).
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Not a global/universal group (Code: %lu). Retrying with NetLocalGroupDelMembers...\n",
                 status);

    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = userName;

    NET_API_STATUS localStatus = NETAPI32$NetLocalGroupDelMembers(
        targetComputer,
        groupName,
        3,  // Level 3 - LOCALGROUP_MEMBERS_INFO_3
        (LPBYTE)&memberInfo,
        1
    );

    if (localStatus == NERR_Success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success: User '%ls' removed from group '%ls'.\n",
                     userName, groupName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed via NetLocalGroupDelMembers (domain-local/builtin group)\n");
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove user from group (NetLocalGroupDelMembers).\n");
    BeaconPrintf(CALLBACK_ERROR, "[-] Error: %s (Code: %lu)\n",
                 GetNetLocalGroupErrorMessage(localStatus), localStatus);
    if (localStatus == NERR_GroupNotFound || localStatus == ERROR_NO_SUCH_ALIAS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Group '%ls' was not found as a global, universal, domain-local, or builtin group.\n",
                     groupName);
        BeaconPrintf(CALLBACK_ERROR, "[-] Check the group name. removeuser-localgroup is the manual alternative for local-group targets.\n");
    }
}
