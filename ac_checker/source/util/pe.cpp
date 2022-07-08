#include <Windows.h>
#include <Winternl.h>
#include <cstdint>
#include <cstdlib>

#include <util/pe.hpp>

struct LdrEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    uintptr_t DllBase;
    uintptr_t EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

namespace util {

    ModuleInfo get_module(std::string_view module_name) {
        auto peb = ((_TEB *) __readfsdword(0x18))->ProcessEnvironmentBlock;
        auto list = &peb->Ldr->InMemoryOrderModuleList;

        size_t wide_name_length = 0;
        wchar_t wide_name[256] = {0};

        mbstowcs_s(&wide_name_length, wide_name, 256, module_name.data(), module_name.size());

        for (auto iter = list->Flink; iter != list; iter = iter->Flink) {
            auto entry = CONTAINING_RECORD(iter, LdrEntry, InMemoryOrderLinks);

            if (entry->BaseDllName.Buffer && _wcsnicmp(entry->BaseDllName.Buffer, wide_name, wide_name_length) == 0) {
                return {
                    .base = entry->DllBase,
                    .size = entry->SizeOfImage,
                };
            }
        }

        return {};
    }

    uintptr_t get_export(std::string_view module_name, std::string_view export_name) {
        auto module_info = get_module(module_name);
        auto module_base = module_info.base;

        if (!module_base)
            return 0u;

        auto dos_hdr = (IMAGE_DOS_HEADER *) module_base;
        auto nt_hdrs = (IMAGE_NT_HEADERS *) (module_base + dos_hdr->e_lfanew);

        auto exports_va = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto exports_size = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        auto exports = (IMAGE_EXPORT_DIRECTORY *) (module_base + exports_va);

        auto names = (uintptr_t *) (module_base + exports->AddressOfNames);
        auto functions = (uintptr_t *) (module_base + exports->AddressOfFunctions);
        auto name_ordinals = (uint16_t *) (module_base + exports->AddressOfNameOrdinals);

        for (auto i = 0u; i < exports->NumberOfNames; i++) {
            if (export_name.compare((const char *) (module_base + names[i])) == 0)
                return module_base + functions[name_ordinals[i]];
        }

        return 0u;
    }

} // namespace util