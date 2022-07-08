#pragma once
#include <cstdint>
#include <string>

namespace signatures {

    constexpr static auto s_token_log_ref = "558BEC83EC08C645FC01C745";

}

namespace util {

    uint8_t *find_pattern(std::string_view pattern, uint8_t *begin, size_t size, ptrdiff_t offset = 0x0);
    uint8_t *scan_module(std::string_view module_name, std::string_view pattern, ptrdiff_t offset = 0x0);
    
} // namespace util