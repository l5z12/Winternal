#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

struct KernelModuleInfo {
    uintptr_t imageBase = 0;
    uint32_t imageSize = 0;
    uint32_t flags = 0;
    uint16_t loadOrder = 0;
    std::wstring name;
    std::wstring path;
    bool fileMissing = false;
};

// Lists all currently loaded kernel modules (drivers + ntoskrnl + hal + etc.)
// via NtQuerySystemInformation(SystemModuleInformation).
std::vector<KernelModuleInfo> EnumKernelModules();

} // namespace winternal
