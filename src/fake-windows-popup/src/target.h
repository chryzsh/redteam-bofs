#pragma once

#include <cstddef>
#include <windows.h>

constexpr std::size_t kTargetNameChars = 256;

struct TargetInfo {
    bool domain_joined;
    wchar_t joined_domain[kTargetNameChars];
    wchar_t prompt_target[kTargetNameChars];
};

bool resolve_target(TargetInfo* target, DWORD* error_code);
