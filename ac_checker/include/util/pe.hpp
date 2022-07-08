#pragma once
#include <cstdint>
#include <string_view>

// <3 mr polish man

namespace util {

    struct ModuleInfo {
        uintptr_t base;
        size_t size;
    };

    ModuleInfo get_module(std::string_view module_name);
    uintptr_t get_export(std::string_view module_name, std::string_view export_name);

} // namespace util