#include "policy.h"

#include "app.h"

namespace {

bool is_empty(const wchar_t* value) {
    return value == nullptr || value[0] == L'\0';
}
}  // namespace

bool is_upn(const wchar_t* username) {
    if (username == nullptr) {
        return false;
    }
    for (const wchar_t* current = username; *current != L'\0'; ++current) {
        if (*current == L'@') {
            return true;
        }
    }
    return false;
}

bool is_downlevel_username(const wchar_t* username) {
    if (username == nullptr) {
        return false;
    }
    for (const wchar_t* current = username; *current != L'\0'; ++current) {
        if (*current == L'\\') {
            return true;
        }
    }
    return false;
}

bool is_local_account_shorthand(const wchar_t* username) {
    return username != nullptr &&
        username[0] == L'.' &&
        username[1] == L'\\' &&
        username[2] != L'\0';
}

const wchar_t* select_auth_domain(
    const wchar_t* username,
    const wchar_t* typed_domain,
    bool domain_joined,
    const wchar_t* joined_domain) {
    if (is_upn(username)) {
        return nullptr;
    }
    if (!is_empty(typed_domain)) {
        return typed_domain;
    }
    if (domain_joined && !is_empty(joined_domain)) {
        return joined_domain;
    }
    return L".";
}

bool copy_without_leading_backslashes(
    const wchar_t* source,
    wchar_t* destination,
    std::size_t destination_chars) {
    if (source == nullptr || destination == nullptr || destination_chars == 0) {
        return false;
    }
    while (*source == L'\\') {
        ++source;
    }
    std::size_t index = 0;
    while (source[index] != L'\0') {
        if (index + 1 >= destination_chars) {
            destination[0] = L'\0';
            return false;
        }
        destination[index] = source[index];
        ++index;
    }
    destination[index] = L'\0';
    return true;
}

unsigned int clamp_timeout_seconds(int value) {
    if (value == 0) {
        return kNoTimeout;
    }
    if (value < 0 || static_cast<unsigned int>(value) < kMinimumTimeoutSeconds) {
        return kMinimumTimeoutSeconds;
    }
    return static_cast<unsigned int>(value);
}

unsigned int clamp_max_attempts(int value) {
    if (value == 0) {
        return kDefaultMaxAttempts;
    }
    if (value < 0 || static_cast<unsigned int>(value) < kMinimumMaxAttempts) {
        return kMinimumMaxAttempts;
    }
    if (static_cast<unsigned int>(value) > kMaximumMaxAttempts) {
        return kMaximumMaxAttempts;
    }
    return static_cast<unsigned int>(value);
}

bool normalize_bool(int value) {
    return value != 0;
}

bool has_nonempty_password(const wchar_t* password) {
    return password != nullptr && password[0] != L'\0';
}

void secure_zero(void* buffer, std::size_t bytes) {
    auto* current = static_cast<volatile unsigned char*>(buffer);
    while (current != nullptr && bytes > 0) {
        *current++ = 0;
        --bytes;
    }
}
