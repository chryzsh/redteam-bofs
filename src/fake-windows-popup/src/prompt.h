#pragma once

#include <windows.h>

#include "app.h"
#include "credentials.h"
#include "target.h"

enum class PromptResult {
    captured,
    validated,
    cancelled,
    timed_out,
    attempts_exhausted,
    error,
};

PromptResult run_prompt(
    HWND parent,
    HANDLE cancel_event,
    const wchar_t* caption,
    const wchar_t* message,
    const AppSettings& settings,
    const TargetInfo& target,
    Credentials* credentials,
    DWORD* error_code);
