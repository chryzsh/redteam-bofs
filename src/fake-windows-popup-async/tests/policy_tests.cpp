#include <cassert>
#include <cwchar>
#include <iterator>

#include "policy.h"

int main() {
    assert(is_upn(L"user@example.test"));
    assert(!is_upn(L"DOMAIN\\user"));
    assert(!is_upn(nullptr));
    assert(is_downlevel_username(L"DOMAIN\\user"));
    assert(is_downlevel_username(L".\\user"));
    assert(!is_downlevel_username(L"user@example.test"));
    assert(!is_downlevel_username(L"user"));
    assert(!is_downlevel_username(nullptr));
    assert(is_local_account_shorthand(L".\\user"));
    assert(!is_local_account_shorthand(L".\\"));
    assert(!is_local_account_shorthand(L"MACHINE\\user"));
    assert(!is_local_account_shorthand(nullptr));

    assert(select_auth_domain(L"user@example.test", L"X", true, L"JOINED") == nullptr);
    const wchar_t typed[] = L"TYPED";
    assert(select_auth_domain(L"user", typed, true, L"JOINED") == typed);
    const wchar_t joined[] = L"JOINED";
    assert(select_auth_domain(L"user", L"", true, joined) == joined);
    assert(std::wcscmp(select_auth_domain(L"user", nullptr, false, nullptr), L".") == 0);

    wchar_t target[64]{};
    assert(copy_without_leading_backslashes(
        L"\\\\dc01.example.test", target, std::size(target)));
    assert(std::wcscmp(target, L"dc01.example.test") == 0);
    wchar_t too_small[4]{L'x', L'x', L'x', L'\0'};
    assert(!copy_without_leading_backslashes(
        L"host", too_small, std::size(too_small)));
    assert(too_small[0] == L'\0');

    assert(clamp_timeout_seconds(0) == 0);
    assert(clamp_timeout_seconds(-1) == 10);
    assert(clamp_timeout_seconds(5) == 10);
    assert(clamp_timeout_seconds(301) == 301);
    assert(clamp_timeout_seconds(3600) == 3600);
    assert(clamp_timeout_seconds(45) == 45);
    assert(clamp_max_attempts(0) == 1);
    assert(clamp_max_attempts(9) == 3);
    assert(clamp_max_attempts(2) == 2);
    assert(!normalize_bool(0));
    assert(normalize_bool(1));
    assert(normalize_bool(-1));

    assert(has_nonempty_password(L"password"));
    assert(has_nonempty_password(L" "));
    assert(!has_nonempty_password(L""));
    assert(!has_nonempty_password(nullptr));

    unsigned char secret[] = {1, 2, 3, 4};
    secure_zero(secret, sizeof(secret));
    for (const unsigned char value : secret) {
        assert(value == 0);
    }
    return 0;
}
