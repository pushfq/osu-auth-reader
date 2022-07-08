#pragma once
#include <cstdint>
#include <type_traits>

namespace util {

    struct Hook {
        uintptr_t _bytes = 0;
        uintptr_t _target = 0;
        uintptr_t _detour = 0;
        uintptr_t _tramp = 0;

        bool enable(uintptr_t target, uintptr_t detour);
        void disable();

        template <typename Target, typename Detour>
        inline bool enable(Target target, Detour detour) {
            return enable((uintptr_t) target, (uintptr_t) detour);
        }

        template <typename Func, typename... Args>
        inline auto invoke(Args &&...args) const {
            return ((Func) _tramp)(std::forward<Args>(args)...);
        }
    };

} // namespace util

#define define_hook(name, ret, call_conv, ...) \
    inline util::Hook name;                    \
    ret call_conv name##_hook(__VA_ARGS__);