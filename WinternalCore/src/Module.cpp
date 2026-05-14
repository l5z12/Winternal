#include "Module.h"
#include "Util.h"
// Pin to PSAPI v1 so psapi.h does not macro-rename EnumProcessModulesEx and
// friends to their K32-prefixed kernel32 forwarders. We call psapi.dll exports.
#define PSAPI_VERSION 1
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace winternal {

std::vector<ModuleInfo> EnumProcessModules(uint32_t pid) {
    std::vector<ModuleInfo> out;
    HandleGuard p(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!p.valid()) {
        p.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!p.valid()) return out;
    }

    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(p.get(), mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        return out;
    }
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;

    for (DWORD i = 0; i < count; ++i) {
        ModuleInfo m{};
        m.baseAddress = reinterpret_cast<uintptr_t>(mods[i]);
        MODULEINFO mi{};
        if (::GetModuleInformation(p.get(), mods[i], &mi, sizeof(mi))) {
            m.size = (uint32_t)mi.SizeOfImage;
        }
        wchar_t buf[1024];
        if (::GetModuleFileNameExW(p.get(), mods[i], buf, 1024)) {
            m.path = buf;
            auto pos = m.path.find_last_of(L'\\');
            m.name = (pos == std::wstring::npos) ? m.path : m.path.substr(pos + 1);
            m.fileMissing = (::GetFileAttributesW(m.path.c_str()) == INVALID_FILE_ATTRIBUTES);
        } else {
            wchar_t bn[256];
            if (::GetModuleBaseNameW(p.get(), mods[i], bn, 256)) m.name = bn;
        }
        out.push_back(std::move(m));
    }
    return out;
}

} // namespace winternal
