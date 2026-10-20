#include "dimmer.h"

namespace {

constexpr UINT kShutdownMessage = WM_APP + 41;
constexpr int kEmergencyHotkey = 1;
constexpr UINT kEmergencyVirtualKey = 0x30;  // Main keyboard-row 0 key.

bool activate_for_prompt(HWND window) {
    const DWORD current_thread = GetCurrentThreadId();
    const HWND foreground_window = GetForegroundWindow();
    const DWORD foreground_thread = foreground_window == nullptr
        ? 0
        : GetWindowThreadProcessId(foreground_window, nullptr);
    bool attached = false;
    if (foreground_thread != 0 && foreground_thread != current_thread) {
        attached = AttachThreadInput(current_thread, foreground_thread, TRUE) != FALSE;
    }

    SetForegroundWindow(window);
    BringWindowToTop(window);
    SetActiveWindow(window);
    SetFocus(window);
    const bool activated = GetForegroundWindow() == window;

    const bool detached = !attached ||
        AttachThreadInput(current_thread, foreground_thread, FALSE) != FALSE;
    return activated && detached;
}

void append_decimal(DWORD value, wchar_t* destination, unsigned int* offset, unsigned int capacity) {
    wchar_t reversed[16]{};
    unsigned int count = 0;
    do {
        reversed[count++] = static_cast<wchar_t>(L'0' + (value % 10));
        value /= 10;
    } while (value != 0 && count < 16);
    while (count > 0 && *offset + 1 < capacity) {
        destination[(*offset)++] = reversed[--count];
    }
    destination[*offset] = L'\0';
}

}  // namespace

DimmerWindow::DimmerWindow()
    : thread_(nullptr),
      ready_event_(nullptr),
      cancel_event_(nullptr),
      hwnd_(nullptr),
      startup_error_(ERROR_SUCCESS),
      foreground_activated_(false),
      class_name_{} {}

DimmerWindow::~DimmerWindow() {
    stop();
}

bool DimmerWindow::start(DWORD* error_code) {
    foreground_activated_ = false;
    ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    cancel_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ready_event_ == nullptr || cancel_event_ == nullptr) {
        if (error_code != nullptr) {
            *error_code = GetLastError();
        }
        stop();
        return false;
    }

    thread_ = CreateThread(nullptr, 0, thread_main, this, 0, nullptr);
    if (thread_ == nullptr) {
        if (error_code != nullptr) {
            *error_code = GetLastError();
        }
        stop();
        return false;
    }

    const DWORD wait_result = WaitForSingleObject(ready_event_, 5000);
    if (wait_result != WAIT_OBJECT_0 || hwnd_ == nullptr) {
        if (error_code != nullptr) {
            *error_code = wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : startup_error_;
        }
        stop();
        return false;
    }

    if (error_code != nullptr) {
        *error_code = ERROR_SUCCESS;
    }
    return true;
}

void DimmerWindow::stop() {
    if (thread_ != nullptr) {
        if (hwnd_ != nullptr) {
            PostMessageW(hwnd_, kShutdownMessage, 0, 0);
        }
        WaitForSingleObject(thread_, INFINITE);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    hwnd_ = nullptr;
    if (ready_event_ != nullptr) {
        CloseHandle(ready_event_);
        ready_event_ = nullptr;
    }
    if (cancel_event_ != nullptr) {
        CloseHandle(cancel_event_);
        cancel_event_ = nullptr;
    }
}

HWND DimmerWindow::hwnd() const {
    return hwnd_;
}

HANDLE DimmerWindow::cancel_event() const {
    return cancel_event_;
}

bool DimmerWindow::foreground_activated() const {
    return foreground_activated_;
}

DWORD WINAPI DimmerWindow::thread_main(void* parameter) {
    auto* self = static_cast<DimmerWindow*>(parameter);
    self->run_message_loop();
    return 0;
}

void DimmerWindow::run_message_loop() {
    constexpr wchar_t prefix[] = L"FakeWindowsPopupDimmer-";
    unsigned int offset = 0;
    while (prefix[offset] != L'\0' && offset + 1 < 64) {
        class_name_[offset] = prefix[offset];
        ++offset;
    }
    append_decimal(GetCurrentThreadId(), class_name_, &offset, 64);

    const HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    window_class.lpszClassName = class_name_;
    if (RegisterClassExW(&window_class) == 0) {
        startup_error_ = GetLastError();
        SetEvent(ready_event_);
        return;
    }

    const int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    hwnd_ = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOOLWINDOW,
        class_name_,
        L"",
        WS_POPUP,
        x,
        y,
        width,
        height,
        nullptr,
        nullptr,
        instance,
        this);
    if (hwnd_ == nullptr) {
        startup_error_ = GetLastError();
        UnregisterClassW(class_name_, instance);
        SetEvent(ready_event_);
        return;
    }

    if (!SetLayeredWindowAttributes(hwnd_, 0, 140, LWA_ALPHA)) {
        startup_error_ = GetLastError();
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        UnregisterClassW(class_name_, instance);
        SetEvent(ready_event_);
        return;
    }

    if (!RegisterHotKey(
            hwnd_,
            kEmergencyHotkey,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
            kEmergencyVirtualKey)) {
        startup_error_ = GetLastError();
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        UnregisterClassW(class_name_, instance);
        SetEvent(ready_event_);
        return;
    }
    if (!SetWindowPos(
            hwnd_,
            HWND_TOPMOST,
            x,
            y,
            width,
            height,
            SWP_SHOWWINDOW)) {
        startup_error_ = GetLastError();
        UnregisterHotKey(hwnd_, kEmergencyHotkey);
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        UnregisterClassW(class_name_, instance);
        SetEvent(ready_event_);
        return;
    }
    UpdateWindow(hwnd_);
    foreground_activated_ = activate_for_prompt(hwnd_);
    if (foreground_activated_) {
        SetActiveWindow(hwnd_);
        SetFocus(hwnd_);
    } else if (!SetWindowPos(
                   // A background Beacon may be denied foreground rights. Do
                   // not leave its full-screen dimmer above brokered CredUI.
                   hwnd_,
                   HWND_NOTOPMOST,
                   0,
                   0,
                   0,
                   0,
                   SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
        startup_error_ = GetLastError();
        UnregisterHotKey(hwnd_, kEmergencyHotkey);
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
        UnregisterClassW(class_name_, instance);
        SetEvent(ready_event_);
        return;
    }
    SetEvent(ready_event_);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    UnregisterHotKey(hwnd_, kEmergencyHotkey);
    hwnd_ = nullptr;
    UnregisterClassW(class_name_, instance);
}

LRESULT CALLBACK DimmerWindow::window_proc(
    HWND window,
    UINT message,
    WPARAM wparam,
    LPARAM lparam) {
    DimmerWindow* self = reinterpret_cast<DimmerWindow*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        self = static_cast<DimmerWindow*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }

    if (message == WM_HOTKEY && wparam == kEmergencyHotkey && self != nullptr) {
        SetEvent(self->cancel_event_);
        DestroyWindow(window);
        return 0;
    }
    if (message == kShutdownMessage) {
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
