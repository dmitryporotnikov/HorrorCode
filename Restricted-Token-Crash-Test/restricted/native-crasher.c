#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// No CRT startup, exception handlers, crash reporter, user32, or gdi32.
void WINAPI crash_entry(void) {
    Sleep(5000);
    RaiseException(0xC0000005u, EXCEPTION_NONCONTINUABLE, 0, NULL);
    ExitProcess(99); // Unreachable unless exception handling was intercepted.
}
