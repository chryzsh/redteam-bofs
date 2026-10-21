#pragma once

struct AppSettings {
    const wchar_t* caption;
    const wchar_t* message;
    unsigned int timeout_seconds;
    unsigned int max_attempts;
    bool validate;
    bool persistent;
    bool force;
};

// As an async job the prompt no longer blocks the beacon, so there is no
// upper cap and 0 means wait until capture, cancel, or the C2 stops the job
constexpr unsigned int kNoTimeout = 0;
// Used only when no timeout argument is passed at all
constexpr unsigned int kDefaultTimeoutSeconds = 60;
constexpr unsigned int kMinimumTimeoutSeconds = 10;
constexpr unsigned int kDefaultMaxAttempts = 1;
constexpr unsigned int kMinimumMaxAttempts = 1;
constexpr unsigned int kMaximumMaxAttempts = 3;
