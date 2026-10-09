#pragma once

#include <windows.h>
#include <wincred.h>

#include "target.h"

struct Credentials {
    wchar_t username[CREDUI_MAX_USERNAME_LENGTH + 1];
    wchar_t domain[CREDUI_MAX_USERNAME_LENGTH + 1];
    wchar_t password[CREDUI_MAX_PASSWORD_LENGTH + 1];

    Credentials();
    ~Credentials();
    void clear();
    Credentials(const Credentials&) = delete;
    Credentials& operator=(const Credentials&) = delete;
};

bool unpack_credentials(
    void* packed,
    DWORD packed_size,
    Credentials* credentials,
    DWORD* error_code);
bool validate_credentials(
    const Credentials& credentials,
    const TargetInfo& target,
    DWORD* error_code);
