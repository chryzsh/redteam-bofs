#pragma once

#include <windows.h>

class DimmerWindow {
public:
    DimmerWindow();
    ~DimmerWindow();

    DimmerWindow(const DimmerWindow&) = delete;
    DimmerWindow& operator=(const DimmerWindow&) = delete;

    bool start(DWORD* error_code);
    void stop();
    HWND hwnd() const;
    HANDLE cancel_event() const;
    bool foreground_activated() const;

private:
    static DWORD WINAPI thread_main(void* parameter);
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    void run_message_loop();

    HANDLE thread_;
    HANDLE ready_event_;
    HANDLE cancel_event_;
    HWND hwnd_;
    DWORD startup_error_;
    bool foreground_activated_;
    wchar_t class_name_[64];
};
