#include <util/memory.hpp>
#include <util/pe.hpp>
#include <vendor/small_vector.hpp>

namespace util {

    constexpr uint8_t hex_to_byte(char ch) {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }

        // >.<
        std::unreachable();
    }

    constexpr uint8_t stich_byte(char x, char y) {
        return hex_to_byte(x) << 4 | hex_to_byte(y);
    }

    uint8_t *find_pattern(std::string_view pattern, uint8_t *begin, size_t size, ptrdiff_t offset) {
        vendor::small_vector<uint8_t, 0x20> vec;

        for (auto i = 0u; i < pattern.size(); i++) {
            auto &ch = pattern[i];

            if (ch == '?') {
                vec.push_back(0xCC);
            } else if (std::isxdigit(ch)) {
                vec.push_back(stich_byte(ch, pattern[++i]));
            }
        }

        for (auto mem = begin; mem < begin + size; mem++) {
            bool is_found = true;

            for (auto i = 0u; i < vec.size(); i++) {
                if (vec[i] != 0xCC && vec[i] != mem[i]) {
                    is_found = false;
                    break;
                }
            }

            if (is_found) {
                return mem + offset;
            }
        }

        return nullptr;
    }

    uint8_t *scan_module(std::string_view module_name, std::string_view pattern, ptrdiff_t offset) {
        auto module_info = util::get_module(module_name);

        if (!module_info.base)
            return nullptr;

        return util::find_pattern(pattern, (uint8_t *) module_info.base, module_info.size, offset);
    }

} // namespace util