#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

enum class HookKind { Iat, Eat, Inline };

struct HookInfo {
    HookKind kind = HookKind::Iat;
    uint32_t pid = 0;
    std::wstring victimModule;     // module where the hook was placed
    std::wstring victimFunction;   // function name
    std::wstring resolvedModule;   // where the hook ended up pointing
    uintptr_t expectedAddress = 0;
    uintptr_t actualAddress = 0;
};

// Scan IAT entries for hooks. For each loaded module in the target process,
// walk imports and verify each resolved address belongs to the import-source
// module (modulo forwarding). A hook is reported when the resolved address
// belongs to a different module than expected.
std::vector<HookInfo> ScanIatHooks(uint32_t pid);

// Scan inline patches: for each loaded module's .text exports, read the first
// few bytes and compare with the on-disk image. Differences flag a hook.
// (Best-effort, slow; intended for targeted scans, not whole-system sweeps.)
std::vector<HookInfo> ScanInlineHooks(uint32_t pid, size_t maxFunctionsPerModule = 64);

} // namespace winternal
