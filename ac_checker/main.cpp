#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <thread>

#include <util/hooklib.hpp>
#include <util/memory.hpp>

define_hook(log_token, int, __fastcall, uintptr_t, uintptr_t, char *, size_t);

template <typename T>
constexpr auto x86_abs_addr(T source, ptrdiff_t disp, size_t length) {
    return (uintptr_t) (source + disp + length);
}

static int __fastcall log_token_hook(uintptr_t ecx, uintptr_t edx, char *text, size_t size) {
    if (size == 4 /*A trash value representing a flag has been pushed; do not print it.*/) {
        fprintf(stdout, "[!] flag detected!\n");
    } else {
        fprintf(stdout, "[~] %s\n", text);
    }

    return log_token.invoke<decltype(&log_token_hook)>(ecx, edx, text, size);
}

bool __stdcall DllMain(uintptr_t instance, uint32_t reason, uintptr_t reserved) {
    if (reason == 1) {
        std::thread([]() {
            AllocConsole();
            SetConsoleTitleA("1337 h4x0r ac checker");
            freopen_s((FILE **) stdout, "CONOUT$", "w", stdout);

            fprintf(stdout, "iroha // pushfq\n");

            if (auto addr = util::scan_module("osu!auth.dll", signatures::s_token_log_ref, 0x1A)) {
                log_token.enable(x86_abs_addr(addr, *(ptrdiff_t *) (addr + 0x1), 0x5), log_token_hook);
            }
            // The user is likely using a targeted build. (TODO: perhaps add support for this where possible?)
            else {
                MessageBoxA(nullptr, "Unsupported target.", "osu!", MB_OK | MB_TOPMOST);
                exit(0);
            }

            fprintf(stdout, "initialized.\n");
        }).detach();
    }

    return true;
}