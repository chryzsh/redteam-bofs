#include <windows.h>
#ifndef BOF
#include <stdio.h>  // Only for test harness
#endif
#include "beacon.h"

/**
 * Credential Guard and Security Features Checker BOF
 *
 * Checks the status of:
 * - Credential Guard
 * - HVCI (Hypervisor-protected Code Integrity)
 * - LSA Protection (RunAsPPL)
 * - VBS (Virtualization-Based Security)
 */

#define MAX_VALUE_SIZE 256

// Define output macro for both BOF and test modes
#ifdef BOF
    #define OUTPUT(type, ...) BeaconPrintf(type, __VA_ARGS__)
    #define _RegOpenKeyExA RegOpenKeyExA
    #define _RegQueryValueExA RegQueryValueExA
    #define _RegCloseKey RegCloseKey
#else
    #define OUTPUT(type, ...) printf(__VA_ARGS__)
    // In test mode, use standard Windows APIs
    #define _RegOpenKeyExA RegOpenKeyExA
    #define _RegQueryValueExA RegQueryValueExA
    #define _RegCloseKey RegCloseKey
#endif

// Helper function to check if a registry key exists
BOOL CheckKeyExists(HKEY hKeyRoot, const char* subKey) {
    HKEY hKey;
    LONG result = _RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        _RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

// Helper function to read a DWORD registry value
BOOL ReadRegistryDWORD(HKEY hKeyRoot, const char* subKey, const char* valueName, DWORD* value) {
    HKEY hKey;
    LONG result;
    DWORD dataSize = sizeof(DWORD);
    DWORD type;

    result = _RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    result = _RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)value, &dataSize);
    _RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_DWORD) {
        return TRUE;
    }
    return FALSE;
}

// Check Credential Guard status
void CheckCredentialGuard() {
    const char* lsaKey = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    const char* lsaCfgValue = "LsaCfgFlags";
    DWORD lsaCfgFlags = 0;

    OUTPUT(CALLBACK_OUTPUT, "[*] Credential Guard Status:\n");

    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, lsaKey, lsaCfgValue, &lsaCfgFlags)) {
        if (lsaCfgFlags == 1) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED with UEFI lock (Value: 1)\n");
        } else if (lsaCfgFlags == 2) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED without UEFI lock (Value: 2)\n");
        } else {
            OUTPUT(CALLBACK_OUTPUT, "    [-] DISABLED (Value: %d)\n", lsaCfgFlags);
        }
    } else {
        OUTPUT(CALLBACK_OUTPUT, "    [-] NOT CONFIGURED - LsaCfgFlags value not found\n");
    }
}

// Check HVCI (Hypervisor-protected Code Integrity) status
void CheckHVCI() {
    const char* hvciKey = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
    const char* hvciValue = "Enabled";
    DWORD enabled = 0;

    OUTPUT(CALLBACK_OUTPUT, "\n[*] HVCI (Hypervisor-protected Code Integrity) Status:\n");

    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, hvciKey, hvciValue, &enabled)) {
        if (enabled == 1) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED (Value: %d)\n", enabled);
        } else {
            OUTPUT(CALLBACK_OUTPUT, "    [-] DISABLED (Value: %d)\n", enabled);
        }
    } else {
        OUTPUT(CALLBACK_OUTPUT, "    [-] NOT CONFIGURED - Registry key/value not found\n");
    }
}

// Check LSA Protection (RunAsPPL) status
void CheckLSAProtection() {
    const char* lsaKey = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    const char* lsaValue = "RunAsPPL";
    DWORD runAsPPL = 0;

    OUTPUT(CALLBACK_OUTPUT, "\n[*] LSA Protection (RunAsPPL) Status:\n");

    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, lsaKey, lsaValue, &runAsPPL)) {
        if (runAsPPL == 1) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED with UEFI variable (Value: 1)\n");
        } else if (runAsPPL == 2) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED without UEFI variable (Value: 2)\n");
        } else {
            OUTPUT(CALLBACK_OUTPUT, "    [-] DISABLED (Value: %d)\n", runAsPPL);
        }
    } else {
        OUTPUT(CALLBACK_OUTPUT, "    [-] DISABLED - RunAsPPL value not found\n");
    }
}

// Check VBS (Virtualization-Based Security) status
void CheckVBS() {
    const char* vbsKey = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
    const char* vbsValue = "EnableVirtualizationBasedSecurity";
    DWORD vbsEnabled = 0;

    OUTPUT(CALLBACK_OUTPUT, "\n[*] VBS (Virtualization-Based Security) Status:\n");

    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, vbsKey, vbsValue, &vbsEnabled)) {
        if (vbsEnabled == 1) {
            OUTPUT(CALLBACK_OUTPUT, "    [+] ENABLED (Value: %d)\n", vbsEnabled);
        } else {
            OUTPUT(CALLBACK_OUTPUT, "    [-] DISABLED (Value: %d)\n", vbsEnabled);
        }
    } else {
        OUTPUT(CALLBACK_OUTPUT, "    [-] NOT CONFIGURED - Registry key/value not found\n");
    }

    // Also check for RequirePlatformSecurityFeatures
    const char* platformSecValue = "RequirePlatformSecurityFeatures";
    DWORD platformSec = 0;

    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, vbsKey, platformSecValue, &platformSec)) {
        OUTPUT(CALLBACK_OUTPUT, "    [*] Platform Security Features: ");
        if (platformSec == 1) {
            OUTPUT(CALLBACK_OUTPUT, "Secure Boot only\n");
        } else if (platformSec == 3) {
            OUTPUT(CALLBACK_OUTPUT, "Secure Boot + DMA Protection\n");
        } else {
            OUTPUT(CALLBACK_OUTPUT, "Value %d\n", platformSec);
        }
    }
}

#ifdef BOF
// BOF entry point
void go(char* args, int len) {
    // This BOF takes no arguments - performs static enumeration only
    (void)args;
    (void)len;

    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  Windows Security Features Check\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n\n");

    // Check all security features
    CheckCredentialGuard();
    CheckHVCI();
    CheckLSAProtection();
    CheckVBS();

    BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  Scan Complete\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
}

#else
// Test harness for local execution
int main(int argc, char** argv) {
    printf("\n========================================\n");
    printf("  Windows Security Features Check\n");
    printf("========================================\n\n");

    DWORD value;

    // Direct function calls for testing
    printf("[*] Credential Guard Status:\n");
    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "LsaCfgFlags", &value)) {
        if (value == 1) {
            printf("    [+] ENABLED with UEFI lock (Value: 1)\n");
        } else if (value == 2) {
            printf("    [+] ENABLED without UEFI lock (Value: 2)\n");
        } else {
            printf("    [-] DISABLED (Value: %d)\n", value);
        }
    } else {
        printf("    [-] NOT CONFIGURED - LsaCfgFlags value not found\n");
    }
    printf("\n[*] HVCI Status:\n");
    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE,
                          "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                          "Enabled", &value)) {
        printf("    [%c] %s (Value: %d)\n", value == 1 ? '+' : '-', value == 1 ? "ENABLED" : "DISABLED", value);
    } else {
        printf("    [-] NOT CONFIGURED\n");
    }

    printf("\n[*] LSA Protection Status:\n");
    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", &value)) {
        if (value == 1) {
            printf("    [+] ENABLED with UEFI variable (Value: 1)\n");
        } else if (value == 2) {
            printf("    [+] ENABLED without UEFI variable (Value: 2)\n");
        } else {
            printf("    [-] DISABLED (Value: %d)\n", value);
        }
    } else {
        printf("    [-] DISABLED\n");
    }

    printf("\n[*] VBS Status:\n");
    if (ReadRegistryDWORD(HKEY_LOCAL_MACHINE,
                          "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                          "EnableVirtualizationBasedSecurity", &value)) {
        printf("    [%c] %s (Value: %d)\n", value == 1 ? '+' : '-', value == 1 ? "ENABLED" : "DISABLED", value);
    } else {
        printf("    [-] NOT CONFIGURED\n");
    }

    printf("\n========================================\n");
    printf("  Scan Complete\n");
    printf("========================================\n");

    return 0;
}
#endif
