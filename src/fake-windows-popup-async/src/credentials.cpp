#include "credentials.h"

#include "policy.h"

Credentials::Credentials() : username{}, domain{}, password{} {}

Credentials::~Credentials() {
    clear();
}

void Credentials::clear() {
    secure_zero(username, sizeof(username));
    secure_zero(domain, sizeof(domain));
    secure_zero(password, sizeof(password));
}

bool unpack_credentials(
    void* packed,
    DWORD packed_size,
    Credentials* credentials,
    DWORD* error_code) {
    if (packed == nullptr || packed_size == 0 || credentials == nullptr) {
        if (error_code != nullptr) {
            *error_code = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    credentials->clear();

    DWORD username_chars = CREDUI_MAX_USERNAME_LENGTH + 1;
    DWORD domain_chars = CREDUI_MAX_USERNAME_LENGTH + 1;
    DWORD password_chars = CREDUI_MAX_PASSWORD_LENGTH + 1;
    if (!CredUnPackAuthenticationBufferW(
            0,
            packed,
            packed_size,
            credentials->username,
            &username_chars,
            credentials->domain,
            &domain_chars,
            credentials->password,
            &password_chars)) {
        if (error_code != nullptr) {
            *error_code = GetLastError();
        }
        credentials->clear();
        return false;
    }

    if (error_code != nullptr) {
        *error_code = ERROR_SUCCESS;
    }
    return true;
}

bool validate_credentials(
    const Credentials& credentials,
    const TargetInfo& target,
    DWORD* error_code) {
    if (credentials.username[0] == L'\0' ||
        !has_nonempty_password(credentials.password)) {
        if (error_code != nullptr) {
            *error_code = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    wchar_t parsed_username[CREDUI_MAX_USERNAME_LENGTH + 1]{};
    wchar_t parsed_domain[CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1]{};
    const wchar_t* auth_username = credentials.username;
    const wchar_t* auth_domain = nullptr;
    if (is_local_account_shorthand(credentials.username)) {
        auth_username = credentials.username + 2;
        auth_domain = L".";
    } else if (is_downlevel_username(credentials.username)) {
        const DWORD parse_result = CredUIParseUserNameW(
            credentials.username,
            parsed_username,
            CREDUI_MAX_USERNAME_LENGTH + 1,
            parsed_domain,
            CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1);
        if (parse_result != NO_ERROR) {
            secure_zero(parsed_username, sizeof(parsed_username));
            secure_zero(parsed_domain, sizeof(parsed_domain));
            if (error_code != nullptr) {
                *error_code = parse_result;
            }
            return false;
        }
        auth_username = parsed_username;
        auth_domain = parsed_domain;
    } else {
        auth_domain = select_auth_domain(
            credentials.username,
            credentials.domain,
            target.domain_joined,
            target.joined_domain);
    }

    HANDLE token = nullptr;
    const bool validated = LogonUserW(
            auth_username,
            auth_domain,
            credentials.password,
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &token) != FALSE;
    const DWORD validation_error = validated ? ERROR_SUCCESS : GetLastError();
    secure_zero(parsed_username, sizeof(parsed_username));
    secure_zero(parsed_domain, sizeof(parsed_domain));
    if (!validated) {
        if (error_code != nullptr) {
            *error_code = validation_error;
        }
        return false;
    }

    if (token != nullptr) {
        CloseHandle(token);
    }
    if (error_code != nullptr) {
        *error_code = ERROR_SUCCESS;
    }
    return true;
}
