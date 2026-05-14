#include "KernelModule.h"
#include "NtApi.h"
#include "Util.h"
#include <vector>

#pragma comment(lib, "ntdll.lib")

using namespace winternal::nt;

namespace winternal {

std::vector<KernelModuleInfo> EnumKernelModules() {
    std::vector<KernelModuleInfo> out;
    std::vector<BYTE> buf(64 * 1024);
    ULONG needed = 0;
    NTSTATUS s;
    while (true) {
        s = NtQuerySystemInformation(SystemModuleInformationClass, buf.data(), (ULONG)buf.size(), &needed);
        if (s == 0) break;
        if ((ULONG)buf.size() < needed) {
            buf.resize(needed * 2);
            continue;
        }
        return out;
    }

    auto* p = reinterpret_cast<RTL_PROCESS_MODULES_X*>(buf.data());
    for (ULONG i = 0; i < p->NumberOfModules; ++i) {
        const auto& m = p->Modules[i];
        KernelModuleInfo k{};
        k.imageBase = reinterpret_cast<uintptr_t>(m.ImageBase);
        k.imageSize = m.ImageSize;
        k.flags = m.Flags;
        k.loadOrder = m.LoadOrderIndex;
        // FullPathName is ASCII OEM, with the basename starting at OffsetToFileName.
        const char* full = reinterpret_cast<const char*>(m.FullPathName);
        std::string s8(full);
        // Map "\SystemRoot\..." to a Windows path.
        if (s8.starts_with("\\SystemRoot\\") || s8.starts_with("\\??\\") || s8.starts_with("\\")) {
            // Common prefixes for the kernel module path.
            if (s8.starts_with("\\SystemRoot\\")) {
                wchar_t sysroot[MAX_PATH];
                UINT n = ::GetWindowsDirectoryW(sysroot, MAX_PATH);
                if (n > 0 && n < MAX_PATH) {
                    std::wstring w(sysroot, n);
                    w += L"\\";
                    w += ToUtf16(std::string_view(s8).substr(12));
                    k.path = std::move(w);
                } else {
                    k.path = ToUtf16(s8);
                }
            } else {
                k.path = ToUtf16(s8);
            }
        } else {
            k.path = ToUtf16(s8);
        }
        size_t pos = k.path.find_last_of(L'\\');
        k.name = (pos == std::wstring::npos) ? k.path : k.path.substr(pos + 1);
        k.fileMissing = (::GetFileAttributesW(k.path.c_str()) == INVALID_FILE_ATTRIBUTES);
        out.push_back(std::move(k));
    }
    return out;
}

} // namespace winternal
