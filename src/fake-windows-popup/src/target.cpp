#include "target.h"

#include <dsgetdc.h>
#include <lm.h>

#include "policy.h"

namespace {

bool copy_wide(const wchar_t* source, wchar_t* destination, std::size_t count) {
    if (source == nullptr || destination == nullptr || count == 0) {
        return false;
    }
    std::size_t index = 0;
    while (source[index] != L'\0') {
        if (index + 1 >= count) {
            destination[0] = L'\0';
            return false;
        }
        destination[index] = source[index];
        ++index;
    }
    destination[index] = L'\0';
    return true;
}
bool resolve_computer_name(TargetInfo* target, DWORD* error_code) {
    DWORD length = static_cast<DWORD>(kTargetNameChars);
    if (!GetComputerNameW(target->prompt_target, &length)) {
        if (error_code != nullptr) {
            *error_code = GetLastError();
        }
        return false;
    }
    return true;
}

}  // namespace

bool resolve_target(TargetInfo* target, DWORD* error_code) {
    if (target == nullptr) {
        if (error_code != nullptr) {
            *error_code = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    *target = {};
    if (error_code != nullptr) {
        *error_code = ERROR_SUCCESS;
    }

    LPWSTR join_name = nullptr;
    NETSETUP_JOIN_STATUS join_status = NetSetupUnknownStatus;
    const NET_API_STATUS join_result =
        NetGetJoinInformation(nullptr, &join_name, &join_status);
    if (join_result != NERR_Success) {
        return resolve_computer_name(target, error_code);
    }

    target->domain_joined = join_status == NetSetupDomainName;
    if (target->domain_joined && join_name != nullptr) {
        if (!copy_wide(join_name, target->joined_domain, kTargetNameChars)) {
            NetApiBufferFree(join_name);
            if (error_code != nullptr) {
                *error_code = ERROR_INSUFFICIENT_BUFFER;
            }
            return false;
        }
    }
    if (join_name != nullptr) {
        NetApiBufferFree(join_name);
    }

    if (!target->domain_joined || target->joined_domain[0] == L'\0') {
        target->domain_joined = false;
        return resolve_computer_name(target, error_code);
    }

    PDOMAIN_CONTROLLER_INFOW dc_info = nullptr;
    const DWORD dc_result = DsGetDcNameW(
        nullptr,
        target->joined_domain,
        nullptr,
        nullptr,
        DS_RETURN_DNS_NAME,
        &dc_info);
    if (dc_result == ERROR_SUCCESS && dc_info != nullptr) {
        const bool copied = copy_without_leading_backslashes(
            dc_info->DomainControllerName,
            target->prompt_target,
            kTargetNameChars);
        NetApiBufferFree(dc_info);
        if (!copied && error_code != nullptr) {
            *error_code = ERROR_INSUFFICIENT_BUFFER;
        }
        return copied;
    }

    if (dc_info != nullptr) {
        NetApiBufferFree(dc_info);
    }
    return copy_wide(target->joined_domain, target->prompt_target, kTargetNameChars);
}
