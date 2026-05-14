#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

struct HandleInfo {
    uint32_t pid = 0;
    uint32_t handleValue = 0;
    uint32_t typeIndex = 0;
    std::wstring typeName;
    std::wstring name;
    uint32_t grantedAccess = 0;
    uint64_t object = 0;
};

// Enumerate all open handles in the system. Resolution of name is best-effort
// and skipped on handle types prone to deadlock during NtQueryObject (Files /
// pipes are queried from a worker thread with a timeout).
std::vector<HandleInfo> EnumHandles(bool resolveNames = true);

bool CloseHandleInProcess(uint32_t pid, uint32_t handleValue);

} // namespace winternal
