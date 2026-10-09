#define SECURITY_WIN32

#include "prompt.h"

#include <security.h>
#include <wincred.h>

#include "policy.h"

namespace {

struct PromptMonitor {
    HANDLE completed_event;
    HANDLE cancel_event;
    HWND parent;
    DWORD prompt_thread_id;
    DWORD timeout_ms;
    volatile LONG timed_out;
    volatile LONG cancelled;
};

BOOL CALLBACK close_owned_window(HWND window, LPARAM parameter) {
    auto* monitor = reinterpret_cast<PromptMonitor*>(parameter);
    const HWND owner = GetWindow(window, GW_OWNER);
    const HWND root_owner = GetAncestor(window, GA_ROOTOWNER);
    if (owner == monitor->parent || root_owner == monitor->parent) {
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

DWORD WINAPI monitor_prompt(void* parameter) {
    auto* monitor = static_cast<PromptMonitor*>(parameter);
    HANDLE events[] = {monitor->completed_event, monitor->cancel_event};
    const DWORD result = WaitForMultipleObjects(2, events, FALSE, monitor->timeout_ms);
    if (result == WAIT_OBJECT_0) {
        return 0;
    }
    if (result == WAIT_OBJECT_0 + 1) {
        InterlockedExchange(&monitor->cancelled, 1);
    } else if (result == WAIT_TIMEOUT) {
        InterlockedExchange(&monitor->timed_out, 1);
    } else {
        return 0;
    }
    EnumThreadWindows(
        monitor->prompt_thread_id,
        close_owned_window,
        reinterpret_cast<LPARAM>(monitor));
    return 0;
}

void release_prompt_buffer(void* buffer, DWORD size) {
    if (buffer != nullptr) {
        secure_zero(buffer, size);
        CoTaskMemFree(buffer);
    }
}

void release_prefill_buffer(void* buffer, DWORD size) {
    if (buffer != nullptr) {
        secure_zero(buffer, size);
        HeapFree(GetProcessHeap(), 0, buffer);
    }
}

bool create_prefill(void** buffer, DWORD* size) {
    *buffer = nullptr;
    *size = 0;
    wchar_t identity[512]{};
    ULONG identity_chars = static_cast<ULONG>(sizeof(identity) / sizeof(identity[0]));
    if (!GetUserNameExW(NameSamCompatible, identity, &identity_chars)) {
        return false;
    }

    CredPackAuthenticationBufferW(0, identity, const_cast<wchar_t*>(L""), nullptr, size);
    if (*size == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        secure_zero(identity, sizeof(identity));
        return false;
    }
    const DWORD allocated_size = *size;
    *buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocated_size);
    if (*buffer == nullptr) {
        secure_zero(identity, sizeof(identity));
        *size = 0;
        return false;
    }
    const bool packed = CredPackAuthenticationBufferW(
        0,
        identity,
        const_cast<wchar_t*>(L""),
        static_cast<unsigned char*>(*buffer),
        size) != FALSE;
    secure_zero(identity, sizeof(identity));
    if (!packed) {
        release_prefill_buffer(*buffer, allocated_size);
        *buffer = nullptr;
        *size = 0;
    }
    return packed;
}

}  // namespace

PromptResult run_prompt(
    HWND parent,
    HANDLE cancel_event,
    const wchar_t* caption,
    const wchar_t* message,
    const AppSettings& settings,
    const TargetInfo& target,
    Credentials* credentials,
    DWORD* error_code) {
    if (parent == nullptr || cancel_event == nullptr || caption == nullptr ||
        message == nullptr || credentials == nullptr) {
        if (error_code != nullptr) {
            *error_code = ERROR_INVALID_PARAMETER;
        }
        return PromptResult::error;
    }

    void* prefill = nullptr;
    DWORD prefill_size = 0;
    create_prefill(&prefill, &prefill_size);

    const ULONGLONG deadline = GetTickCount64() +
        static_cast<ULONGLONG>(settings.timeout_seconds) * 1000ULL;
    DWORD last_auth_error = ERROR_SUCCESS;
    PromptResult final_result = PromptResult::error;

    unsigned int submitted_attempts = 0;
    while (submitted_attempts < settings.max_attempts) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            final_result = PromptResult::timed_out;
            break;
        }

        HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (completed == nullptr) {
            if (error_code != nullptr) {
                *error_code = GetLastError();
            }
            break;
        }

        PromptMonitor monitor{
            completed,
            cancel_event,
            parent,
            GetCurrentThreadId(),
            static_cast<DWORD>(deadline - now),
            0,
            0,
        };
        HANDLE monitor_thread = CreateThread(nullptr, 0, monitor_prompt, &monitor, 0, nullptr);
        if (monitor_thread == nullptr) {
            if (error_code != nullptr) {
                *error_code = GetLastError();
            }
            CloseHandle(completed);
            break;
        }

        CREDUI_INFOW info{};
        info.cbSize = sizeof(info);
        info.hwndParent = parent;
        info.pszCaptionText = caption;
        info.pszMessageText = message;
        ULONG auth_package = 0;
        BOOL save = FALSE;
        void* packed = nullptr;
        ULONG packed_size = 0;
        const DWORD prompt_result = CredUIPromptForWindowsCredentialsW(
            &info,
            last_auth_error,
            &auth_package,
            prefill,
            prefill_size,
            &packed,
            &packed_size,
            &save,
            CREDUIWIN_GENERIC);

        SetEvent(completed);
        WaitForSingleObject(monitor_thread, INFINITE);
        CloseHandle(monitor_thread);
        CloseHandle(completed);

        if (monitor.timed_out != 0) {
            release_prompt_buffer(packed, packed_size);
            final_result = PromptResult::timed_out;
            break;
        }
        if (monitor.cancelled != 0) {
            release_prompt_buffer(packed, packed_size);
            final_result = PromptResult::cancelled;
            break;
        }
        if (prompt_result != ERROR_SUCCESS) {
            release_prompt_buffer(packed, packed_size);
            if (prompt_result == ERROR_CANCELLED && settings.persistent) {
                last_auth_error = ERROR_SUCCESS;
                continue;
            }
            final_result = prompt_result == ERROR_CANCELLED
                ? PromptResult::cancelled
                : PromptResult::error;
            if (error_code != nullptr) {
                *error_code = prompt_result;
            }
            break;
        }

        DWORD unpack_error = ERROR_SUCCESS;
        const bool unpacked = unpack_credentials(
            packed,
            packed_size,
            credentials,
            &unpack_error);
        release_prompt_buffer(packed, packed_size);
        if (!unpacked) {
            if (error_code != nullptr) {
                *error_code = unpack_error;
            }
            final_result = PromptResult::error;
            break;
        }
        if (credentials->username[0] == L'\0' ||
            !has_nonempty_password(credentials->password)) {
            last_auth_error = ERROR_LOGON_FAILURE;
            credentials->clear();
            if (settings.persistent) {
                continue;
            }
            ++submitted_attempts;
            final_result = PromptResult::attempts_exhausted;
            continue;
        }
        ++submitted_attempts;
        if (!settings.validate) {
            final_result = PromptResult::captured;
            break;
        }

        if (validate_credentials(*credentials, target, &last_auth_error)) {
            final_result = PromptResult::validated;
            break;
        }
        if (error_code != nullptr) {
            *error_code = last_auth_error;
        }
        final_result = PromptResult::attempts_exhausted;
        if (submitted_attempts < settings.max_attempts) {
            credentials->clear();
        }
    }

    release_prefill_buffer(prefill, prefill_size);
    return final_result;
}
