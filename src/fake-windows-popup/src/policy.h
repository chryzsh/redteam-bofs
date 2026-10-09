#pragma once

#include <cstddef>

bool is_upn(const wchar_t* username);
bool is_downlevel_username(const wchar_t* username);
bool is_local_account_shorthand(const wchar_t* username);
const wchar_t* select_auth_domain(
    const wchar_t* username,
    const wchar_t* typed_domain,
    bool domain_joined,
    const wchar_t* joined_domain);
bool copy_without_leading_backslashes(
    const wchar_t* source,
    wchar_t* destination,
    std::size_t destination_chars);
unsigned int clamp_timeout_seconds(int value);
unsigned int clamp_max_attempts(int value);
bool normalize_bool(int value);
bool has_nonempty_password(const wchar_t* password);
void secure_zero(void* buffer, std::size_t bytes);
