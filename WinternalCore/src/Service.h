#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

enum class SvcType : uint32_t {
    Other = 0,
    KernelDriver = 1,
    FileSystemDriver = 2,
    Win32OwnProcess = 16,
    Win32SharedProcess = 32,
    UserOwnProcess = 64,
    UserSharedProcess = 96,
    InteractiveProcess = 256
};

enum class SvcStartType : uint32_t {
    Boot = 0, System = 1, Auto = 2, Manual = 3, Disabled = 4
};

enum class SvcState : uint32_t {
    Stopped = 1, StartPending = 2, StopPending = 3, Running = 4,
    ContinuePending = 5, PausePending = 6, Paused = 7
};

struct ServiceInfo {
    std::wstring name;
    std::wstring displayName;
    std::wstring binPath;
    std::wstring description;
    std::wstring account;
    SvcType type = SvcType::Other;
    SvcStartType startType = SvcStartType::Manual;
    SvcState state = SvcState::Stopped;
    uint32_t pid = 0;     // for running services
    bool autostart = false;
    bool kernel = false;
};

std::vector<ServiceInfo> EnumServices();
bool StartServiceByName(const std::wstring& name);
bool StopServiceByName(const std::wstring& name);

} // namespace winternal
