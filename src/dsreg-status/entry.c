#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include "beacon.h"

/*
 * dsreg-status BOF
 *
 * Collects Microsoft Entra / hybrid join state using documented APIs.
 * Phase 1 intentionally avoids undocumented dsreg.dll exports.
 */

#ifndef DSREG_UNKNOWN_JOIN
#define DSREG_UNKNOWN_JOIN 0
#endif

#ifndef DSREG_DEVICE_JOIN
#define DSREG_DEVICE_JOIN 1
#endif

#ifndef DSREG_WORKPLACE_JOIN
#define DSREG_WORKPLACE_JOIN 2
#endif

#define HASH_BUFFER_BYTES 64
#define DATE_BUFFER_CHARS 64
#define COMPUTER_NAME_CHARS 256
#define IE_PROXY_OPTION_COUNT 4
#define NERR_Success 0

typedef DWORD NET_API_STATUS;

typedef enum _NETSETUP_JOIN_STATUS {
    NetSetupUnknownStatus = 0,
    NetSetupUnjoined,
    NetSetupWorkgroupName,
    NetSetupDomainName
} NETSETUP_JOIN_STATUS, *PNETSETUP_JOIN_STATUS;

typedef struct _DSREG_USER_INFO_FALLBACK {
    LPWSTR pszUserEmail;
    LPWSTR pszUserKeyId;
    LPWSTR pszUserKeyName;
} DSREG_USER_INFO_FALLBACK;

typedef struct _DSREG_JOIN_INFO_FALLBACK {
    int joinType;
    PCCERT_CONTEXT pJoinCertificate;
    LPWSTR pszDeviceId;
    LPWSTR pszIdpDomain;
    LPWSTR pszTenantId;
    LPWSTR pszJoinUserEmail;
    LPWSTR pszTenantDisplayName;
    LPWSTR pszMdmEnrollmentUrl;
    LPWSTR pszMdmTermsOfUseUrl;
    LPWSTR pszMdmComplianceUrl;
    LPWSTR pszUserSettingSyncUrl;
    DSREG_USER_INFO_FALLBACK* pUserInfo;
} DSREG_JOIN_INFO_FALLBACK, *PDSREG_JOIN_INFO;

typedef struct _WINHTTP_PROXY_INFO {
    DWORD dwAccessType;
    LPWSTR lpszProxy;
    LPWSTR lpszProxyBypass;
} WINHTTP_PROXY_INFO, *LPWINHTTP_PROXY_INFO;

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGetAadJoinInformation(LPCWSTR, PDSREG_JOIN_INFO*);
DECLSPEC_IMPORT VOID WINAPI NETAPI32$NetFreeAadJoinInformation(PDSREG_JOIN_INFO);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGetJoinInformation(LPCWSTR, LPWSTR*, PNETSETUP_JOIN_STATUS);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT, DWORD, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO*);
DECLSPEC_IMPORT BOOL WINAPI WININET$InternetQueryOptionW(HINTERNET, DWORD, LPVOID, LPDWORD);

typedef struct _DSREG_CONTEXT {
    PDSREG_JOIN_INFO joinInfo;
    DSREG_JOIN_INFO_FALLBACK* joinInfoView;
    LPWSTR domainName;
    NETSETUP_JOIN_STATUS joinStatus;
    WCHAR computerName[COMPUTER_NAME_CHARS];
    DWORD computerNameLen;
    NET_API_STATUS aadStatus;
    NET_API_STATUS domainStatus;
} DSREG_CONTEXT;

void PrintSectionHeader(const char* title) {
    BeaconPrintf(CALLBACK_OUTPUT, "+----------------------------------------------------------------------+\n");
    BeaconPrintf(CALLBACK_OUTPUT, "| %-68s |\n", title);
    BeaconPrintf(CALLBACK_OUTPUT, "+----------------------------------------------------------------------+\n");
}

const char* YesNo(BOOL value) {
    return value ? "YES" : "NO";
}

BOOL HasWideString(LPCWSTR value) {
    return value != NULL && lstrlenW(value) > 0;
}

void PrintWideField(const char* label, LPCWSTR value) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : %S\n", label, HasWideString(value) ? value : L"");
}

void PrintAnsiField(const char* label, const char* value) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : %s\n", label, value ? value : "");
}

void PrintBoolField(const char* label, BOOL value) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : %s\n", label, YesNo(value));
}

void PrintUnavailableField(const char* label) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : UNAVAILABLE (phase 2)\n", label);
}

void PrintErrorField(const char* label, DWORD status) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : ERROR (0x%08X)\n", label, status);
}

void FormatFileTimeUtc(const FILETIME* fileTime, WCHAR* output, DWORD outputChars) {
    SYSTEMTIME systemTime;

    if (!output || outputChars < 2) {
        return;
    }

    output[0] = L'\0';
    if (!fileTime || !KERNEL32$FileTimeToSystemTime(fileTime, &systemTime)) {
        return;
    }

    _snwprintf(
        output,
        outputChars,
        L"%04u-%02u-%02u %02u:%02u:%02u UTC",
        (unsigned int)systemTime.wYear,
        (unsigned int)systemTime.wMonth,
        (unsigned int)systemTime.wDay,
        (unsigned int)systemTime.wHour,
        (unsigned int)systemTime.wMinute,
        (unsigned int)systemTime.wSecond
    );
    output[outputChars - 1] = L'\0';
}

void FormatHex(const BYTE* input, DWORD inputLen, WCHAR* output, DWORD outputChars) {
    DWORD i = 0;
    DWORD offset = 0;

    if (!output || outputChars < 2) {
        return;
    }

    output[0] = L'\0';
    if (!input || inputLen == 0) {
        return;
    }

    for (i = 0; i < inputLen && offset + 3 < outputChars; i++) {
        int written = _snwprintf(output + offset, outputChars - offset, L"%02X", input[i]);
        if (written < 0) {
            break;
        }
        offset += (DWORD)written;
    }

    output[outputChars - 1] = L'\0';
}

void PrintJoinCertificateDetails(DSREG_CONTEXT* ctx) {
    DWORD hashBytes = HASH_BUFFER_BYTES;
    BYTE hashBuffer[HASH_BUFFER_BYTES];
    WCHAR hashHex[(HASH_BUFFER_BYTES * 2) + 1];
    WCHAR notBefore[DATE_BUFFER_CHARS];
    WCHAR notAfter[DATE_BUFFER_CHARS];

    if (!ctx || !ctx->joinInfoView || !ctx->joinInfoView->pJoinCertificate) {
        PrintAnsiField("Thumbprint", "");
        PrintAnsiField("DeviceCertificateValidity", "");
        return;
    }

    memset(hashBuffer, 0, sizeof(hashBuffer));
    memset(hashHex, 0, sizeof(hashHex));
    memset(notBefore, 0, sizeof(notBefore));
    memset(notAfter, 0, sizeof(notAfter));

    if (CRYPT32$CertGetCertificateContextProperty(
            ctx->joinInfoView->pJoinCertificate,
            CERT_HASH_PROP_ID,
            hashBuffer,
            &hashBytes)) {
        FormatHex(hashBuffer, hashBytes, hashHex, sizeof(hashHex) / sizeof(WCHAR));
        PrintWideField("Thumbprint", hashHex);
    } else {
        PrintErrorField("Thumbprint", GetLastError());
    }

    FormatFileTimeUtc(
        &ctx->joinInfoView->pJoinCertificate->pCertInfo->NotBefore,
        notBefore,
        sizeof(notBefore) / sizeof(WCHAR)
    );
    FormatFileTimeUtc(
        &ctx->joinInfoView->pJoinCertificate->pCertInfo->NotAfter,
        notAfter,
        sizeof(notAfter) / sizeof(WCHAR)
    );
    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : %S -> %S\n", "DeviceCertificateValidity", notBefore, notAfter);
}

BOOL CollectContext(DSREG_CONTEXT* ctx) {
    DWORD nameChars = COMPUTER_NAME_CHARS;

    if (!ctx) {
        return FALSE;
    }

    memset(ctx, 0, sizeof(DSREG_CONTEXT));
    ctx->joinStatus = NetSetupUnknownStatus;
    ctx->computerName[0] = L'\0';

    if (KERNEL32$GetComputerNameExW(ComputerNameDnsHostname, ctx->computerName, &nameChars) ||
        KERNEL32$GetComputerNameExW(ComputerNameNetBIOS, ctx->computerName, &nameChars)) {
        ctx->computerNameLen = nameChars;
    }

    ctx->aadStatus = NETAPI32$NetGetAadJoinInformation(NULL, &ctx->joinInfo);
    if (ctx->aadStatus == NERR_Success && ctx->joinInfo) {
        ctx->joinInfoView = (DSREG_JOIN_INFO_FALLBACK*)ctx->joinInfo;
    }

    ctx->domainStatus = NETAPI32$NetGetJoinInformation(NULL, &ctx->domainName, &ctx->joinStatus);

    return TRUE;
}

void FreeContext(DSREG_CONTEXT* ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->domainName) {
        NETAPI32$NetApiBufferFree(ctx->domainName);
        ctx->domainName = NULL;
    }

    if (ctx->joinInfo) {
        NETAPI32$NetFreeAadJoinInformation(ctx->joinInfo);
        ctx->joinInfo = NULL;
        ctx->joinInfoView = NULL;
    }
}

void PrintDeviceState(DSREG_CONTEXT* ctx) {
    BOOL azureAdJoined = FALSE;
    BOOL workplaceJoined = FALSE;
    BOOL domainJoined = FALSE;

    PrintSectionHeader("Device State");

    if (ctx->aadStatus == NERR_Success && ctx->joinInfoView) {
        azureAdJoined = ctx->joinInfoView->joinType == DSREG_DEVICE_JOIN;
        workplaceJoined = ctx->joinInfoView->joinType == DSREG_WORKPLACE_JOIN;
    }

    if (ctx->domainStatus == NERR_Success) {
        domainJoined = ctx->joinStatus == NetSetupDomainName;
    }

    PrintBoolField("AzureAdJoined", azureAdJoined);
    PrintBoolField("EnterpriseJoined", FALSE);
    PrintBoolField("DomainJoined", domainJoined);
    PrintBoolField("WorkplaceJoined", workplaceJoined);
    PrintWideField("DomainName", domainJoined ? ctx->domainName : L"");
    PrintWideField("DeviceName", HasWideString(ctx->computerName) ? ctx->computerName : L"");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintDeviceDetails(DSREG_CONTEXT* ctx) {
    PrintSectionHeader("Device Details");

    if (ctx->aadStatus != NERR_Success || !ctx->joinInfoView) {
        PrintErrorField("JoinInformation", ctx->aadStatus);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        return;
    }

    PrintWideField("DeviceId", ctx->joinInfoView->pszDeviceId);
    PrintJoinCertificateDetails(ctx);
    PrintUnavailableField("KeyContainerId");
    PrintUnavailableField("KeyProvider");
    PrintUnavailableField("TpmProtected");
    PrintUnavailableField("DeviceAuthStatus");
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintTenantDetails(DSREG_CONTEXT* ctx) {
    PrintSectionHeader("Tenant Details");

    if (ctx->aadStatus != NERR_Success || !ctx->joinInfoView) {
        PrintErrorField("JoinInformation", ctx->aadStatus);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        return;
    }

    PrintWideField("TenantName", ctx->joinInfoView->pszTenantDisplayName);
    PrintWideField("TenantId", ctx->joinInfoView->pszTenantId);
    PrintWideField("IdpDomain", ctx->joinInfoView->pszIdpDomain);
    PrintWideField("JoinUserEmail", ctx->joinInfoView->pszJoinUserEmail);
    PrintWideField("MdmEnrollmentUrl", ctx->joinInfoView->pszMdmEnrollmentUrl);
    PrintWideField("MdmTermsOfUseUrl", ctx->joinInfoView->pszMdmTermsOfUseUrl);
    PrintWideField("MdmComplianceUrl", ctx->joinInfoView->pszMdmComplianceUrl);
    PrintWideField("UserSettingSyncUrl", ctx->joinInfoView->pszUserSettingSyncUrl);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintUserState(DSREG_CONTEXT* ctx) {
    DSREG_USER_INFO_FALLBACK* userInfo = NULL;

    PrintSectionHeader("User State");

    if (ctx->aadStatus == NERR_Success && ctx->joinInfoView) {
        userInfo = ctx->joinInfoView->pUserInfo;
    }

    PrintBoolField("NgcSet", userInfo && HasWideString(userInfo->pszUserKeyId));
    PrintBoolField("WorkplaceJoined", ctx->joinInfoView && ctx->joinInfoView->joinType == DSREG_WORKPLACE_JOIN);
    PrintUnavailableField("WamDefaultSet");
    if (userInfo) {
        PrintWideField("UserEmail", userInfo->pszUserEmail);
        PrintWideField("UserKeyId", userInfo->pszUserKeyId);
        PrintWideField("UserKeyName", userInfo->pszUserKeyName);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintUnsupportedSection(const char* sectionName, const char* fieldName) {
    PrintSectionHeader(sectionName);
    PrintUnavailableField(fieldName);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintWorkAccount(DSREG_CONTEXT* ctx) {
    DSREG_USER_INFO_FALLBACK* userInfo = NULL;

    PrintSectionHeader("Work Account 1");

    if (ctx->aadStatus != NERR_Success || !ctx->joinInfoView) {
        PrintErrorField("JoinInformation", ctx->aadStatus);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        return;
    }

    userInfo = ctx->joinInfoView->pUserInfo;
    PrintWideField("TenantId", ctx->joinInfoView->pszTenantId);
    PrintWideField("TenantName", ctx->joinInfoView->pszTenantDisplayName);
    PrintWideField("UserEmail", userInfo ? userInfo->pszUserEmail : NULL);
    PrintWideField("JoinUserEmail", ctx->joinInfoView->pszJoinUserEmail);
    PrintWideField("MdmEnrollmentUrl", ctx->joinInfoView->pszMdmEnrollmentUrl);
    PrintWideField("MdmTermsOfUseUrl", ctx->joinInfoView->pszMdmTermsOfUseUrl);
    PrintWideField("MdmComplianceUrl", ctx->joinInfoView->pszMdmComplianceUrl);
    PrintWideField("UserSettingSyncUrl", ctx->joinInfoView->pszUserSettingSyncUrl);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintIEProxyConfig(void) {
    INTERNET_PER_CONN_OPTION_LISTW* optionList = NULL;
    INTERNET_PER_CONN_OPTIONW* options = NULL;
    DWORD optionListSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    DWORD i = 0;

    PrintSectionHeader("IE Proxy Config for Current User");

    optionList = (INTERNET_PER_CONN_OPTION_LISTW*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(INTERNET_PER_CONN_OPTION_LISTW)
    );
    options = (INTERNET_PER_CONN_OPTIONW*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(INTERNET_PER_CONN_OPTIONW) * IE_PROXY_OPTION_COUNT
    );

    if (!optionList || !options) {
        BeaconPrintf(CALLBACK_OUTPUT, "Collection                    : ERROR (allocation failed)\n\n");
        goto cleanup;
    }

    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;

    optionList->dwSize = sizeof(INTERNET_PER_CONN_OPTION_LISTW);
    optionList->pszConnection = NULL;
    optionList->dwOptionCount = IE_PROXY_OPTION_COUNT;
    optionList->dwOptionError = 0;
    optionList->pOptions = options;

    if (!WININET$InternetQueryOptionW(
            NULL,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            optionList,
            &optionListSize)) {
        PrintErrorField("Collection", GetLastError());
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        goto cleanup;
    }

    PrintWideField("ProxyServer", options[1].Value.pszValue);
    PrintWideField("ProxyBypass", options[2].Value.pszValue);
    PrintWideField("AutoConfigUrl", options[3].Value.pszValue);

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "%-28s : 0x%08X\n",
        "Flags",
        options[0].Value.dwValue
    );

cleanup:
    if (options) {
        for (i = 0; i < IE_PROXY_OPTION_COUNT; i++) {
            if (options[i].dwOption == INTERNET_PER_CONN_PROXY_SERVER ||
                options[i].dwOption == INTERNET_PER_CONN_PROXY_BYPASS ||
                options[i].dwOption == INTERNET_PER_CONN_AUTOCONFIG_URL) {
                if (options[i].Value.pszValue) {
                    GlobalFree(options[i].Value.pszValue);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, options);
    }

    if (optionList) {
        HeapFree(GetProcessHeap(), 0, optionList);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}

void PrintWinHttpProxyConfig(void) {
    WINHTTP_PROXY_INFO proxyInfo;

    PrintSectionHeader("WinHttp Default Proxy Config");
    memset(&proxyInfo, 0, sizeof(proxyInfo));

    if (!WINHTTP$WinHttpGetDefaultProxyConfiguration(&proxyInfo)) {
        PrintErrorField("Collection", GetLastError());
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%-28s : 0x%08X\n", "AccessType", proxyInfo.dwAccessType);
    PrintWideField("Proxy", proxyInfo.lpszProxy);
    PrintWideField("ProxyBypass", proxyInfo.lpszProxyBypass);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    if (proxyInfo.lpszProxy) {
        GlobalFree(proxyInfo.lpszProxy);
    }
    if (proxyInfo.lpszProxyBypass) {
        GlobalFree(proxyInfo.lpszProxyBypass);
    }
}

void go(char* args, int len) {
    DSREG_CONTEXT ctx;
    datap parser;

    BeaconDataParse(&parser, args, len);
    memset(&ctx, 0, sizeof(ctx));

    if (!CollectContext(&ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to collect dsreg state\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "## Dsregcmd /status\n\n");
    PrintDeviceState(&ctx);
    PrintDeviceDetails(&ctx);
    PrintTenantDetails(&ctx);
    PrintUserState(&ctx);
    PrintUnsupportedSection("SSO State", "AzureAdPrt");
    PrintWorkAccount(&ctx);
    PrintUnsupportedSection("Diagnostic Data", "Status");
    PrintIEProxyConfig();
    PrintWinHttpProxyConfig();
    PrintUnsupportedSection("Ngc Prerequisite Check", "Status");

    FreeContext(&ctx);
}
