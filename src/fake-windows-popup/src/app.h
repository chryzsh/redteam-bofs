#pragma once

struct AppSettings {
    const wchar_t* caption;
    const wchar_t* message;
    unsigned int timeout_seconds;
    unsigned int max_attempts;
    bool validate;
    bool include_password;
    bool persistent;
};

constexpr unsigned int kDefaultTimeoutSeconds = 60;
constexpr unsigned int kMinimumTimeoutSeconds = 10;
constexpr unsigned int kMaximumTimeoutSeconds = 300;
constexpr unsigned int kDefaultMaxAttempts = 1;
constexpr unsigned int kMinimumMaxAttempts = 1;
constexpr unsigned int kMaximumMaxAttempts = 3;
