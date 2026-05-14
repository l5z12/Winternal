#include "Service.h"
#include "Util.h"
#include <Windows.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace winternal {

class ScmHandle {
public:
    explicit ScmHandle(SC_HANDLE h) : h_(h) {}
    ScmHandle(const ScmHandle&) = delete;
    ScmHandle& operator=(const ScmHandle&) = delete;
    ~ScmHandle() { if (h_) ::CloseServiceHandle(h_); }
    SC_HANDLE get() const { return h_; }
    bool valid() const { return h_ != nullptr; }
private:
    SC_HANDLE h_ = nullptr;
};

static std::wstring QueryDescription(SC_HANDLE svc) {
    DWORD cb = 0;
    ::QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cb);
    if (cb == 0) return L"";
    std::vector<BYTE> buf(cb);
    if (!::QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, buf.data(), cb, &cb)) return L"";
    auto* d = reinterpret_cast<SERVICE_DESCRIPTIONW*>(buf.data());
    return d->lpDescription ? std::wstring(d->lpDescription) : L"";
}

std::vector<ServiceInfo> EnumServices() {
    std::vector<ServiceInfo> out;
    ScmHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT));
    if (!scm.valid()) return out;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    DWORD types = SERVICE_WIN32 | SERVICE_DRIVER;
    DWORD bufSize = 256 * 1024;
    std::vector<BYTE> buf(bufSize);

    while (true) {
        BOOL ok = ::EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO, types, SERVICE_STATE_ALL,
                                          buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr);
        if (!ok && ::GetLastError() == ERROR_MORE_DATA) {
            buf.resize(buf.size() + bytesNeeded + 4096);
            continue;
        }
        if (!ok) break;

        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            ServiceInfo s{};
            s.name = arr[i].lpServiceName ? arr[i].lpServiceName : L"";
            s.displayName = arr[i].lpDisplayName ? arr[i].lpDisplayName : L"";
            s.state = static_cast<SvcState>(arr[i].ServiceStatusProcess.dwCurrentState);
            s.pid = arr[i].ServiceStatusProcess.dwProcessId;
            s.type = static_cast<SvcType>(arr[i].ServiceStatusProcess.dwServiceType & 0xFF);
            s.kernel = (arr[i].ServiceStatusProcess.dwServiceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;

            ScmHandle svc(::OpenServiceW(scm.get(), s.name.c_str(), SERVICE_QUERY_CONFIG));
            if (svc.valid()) {
                DWORD cb = 0;
                ::QueryServiceConfigW(svc.get(), nullptr, 0, &cb);
                if (cb > 0) {
                    std::vector<BYTE> cbuf(cb);
                    if (::QueryServiceConfigW(svc.get(), reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cbuf.data()), cb, &cb)) {
                        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cbuf.data());
                        if (cfg->lpBinaryPathName) s.binPath = cfg->lpBinaryPathName;
                        if (cfg->lpServiceStartName) s.account = cfg->lpServiceStartName;
                        s.startType = static_cast<SvcStartType>(cfg->dwStartType);
                        s.autostart = (cfg->dwStartType == SERVICE_AUTO_START);
                    }
                }
                s.description = QueryDescription(svc.get());
            }

            out.push_back(std::move(s));
        }

        if (resume == 0) break;
    }
    return out;
}

bool StartServiceByName(const std::wstring& name) {
    ScmHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) return false;
    ScmHandle svc(::OpenServiceW(scm.get(), name.c_str(), SERVICE_START));
    if (!svc.valid()) return false;
    if (::StartServiceW(svc.get(), 0, nullptr)) return true;
    return ::GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopServiceByName(const std::wstring& name) {
    ScmHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) return false;
    ScmHandle svc(::OpenServiceW(scm.get(), name.c_str(), SERVICE_STOP));
    if (!svc.valid()) return false;
    SERVICE_STATUS st{};
    return ::ControlService(svc.get(), SERVICE_CONTROL_STOP, &st) != 0;
}

} // namespace winternal
