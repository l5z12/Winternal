#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

struct ModuleInfo {
    uintptr_t baseAddress = 0;
    uint32_t size = 0;
    std::wstring name;
    std::wstring path;
    bool fileMissing = false;     // image not present on disk at recorded path
};

// Enumerate all loaded modules in a given process. Walks PEB Ldr list when
// possible (more authoritative); falls back to EnumProcessModulesEx on
// access-restricted targets.
std::vector<ModuleInfo> EnumProcessModules(uint32_t pid);

} // namespace winternal
