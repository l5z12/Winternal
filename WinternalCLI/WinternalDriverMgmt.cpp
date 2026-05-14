// `winternal drv ...` — kernel-driver management.
//
//   drv list                      enumerate kernel-mode services
//   drv stop    <name>            ControlService(SERVICE_CONTROL_STOP)
//   drv start   <name>            StartService
//   drv enable  <name>            StartType = SERVICE_DEMAND_START
//   drv disable <name>            StartType = SERVICE_DISABLED
//   drv delete  <name>            DeleteService (best effort: tries stop first)
//   drv unload  <name>            kernel-side ObReferenceObjectByName +
//                                 direct DriverUnload, via Winternal.sys.
//                                 Use when SCM stop fails (error 1052).
//
// `stop` returns the SCM error verbatim; if it's 1052 (the driver doesn't
// accept SERVICE_ACCEPT_STOP), the message points at `drv unload`.

#include "WinternalCore.h"
#include "../Winternal/Public.h"
#include <Windows.h>
#include <winsvc.h>
#include <cstdio>
#include <string>
#include <vector>

using namespace winternal;

namespace {

bool IsAdmin() {
    BOOL elev = FALSE; HANDLE tok = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te{}; DWORD sz = sizeof(te);
        ::GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz);
        elev = te.TokenIsElevated;
        ::CloseHandle(tok);
    }
    return elev != FALSE;
}

const wchar_t* StateName(DWORD s) {
    switch (s) {
    case SERVICE_STOPPED:        return L"stopped";
    case SERVICE_START_PENDING:  return L"start_pending";
    case SERVICE_STOP_PENDING:   return L"stop_pending";
    case SERVICE_RUNNING:        return L"RUNNING";
    case SERVICE_PAUSE_PENDING:  return L"pause_pending";
    case SERVICE_PAUSED:         return L"paused";
    }
    return L"?";
}

const wchar_t* StartTypeName(DWORD t) {
    switch (t) {
    case SERVICE_BOOT_START:    return L"boot";
    case SERVICE_SYSTEM_START:  return L"system";
    case SERVICE_AUTO_START:    return L"auto";
    case SERVICE_DEMAND_START:  return L"demand";
    case SERVICE_DISABLED:      return L"DISABLED";
    }
    return L"?";
}

int CmdList() {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { fwprintf(stderr, L"OpenSCManager failed (%lu)\n", ::GetLastError()); return 1; }

    DWORD needed = 0, count = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL,
                            nullptr, 0, &needed, &count, &resume, nullptr);
    if (::GetLastError() != ERROR_MORE_DATA) {
        fwprintf(stderr, L"EnumServicesStatusEx probe failed (%lu)\n", ::GetLastError());
        ::CloseServiceHandle(scm); return 1;
    }
    std::vector<BYTE> buf(needed);
    if (!::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL,
                                 buf.data(), needed, &needed, &count, &resume, nullptr)) {
        fwprintf(stderr, L"EnumServicesStatusEx failed (%lu)\n", ::GetLastError());
        ::CloseServiceHandle(scm); return 1;
    }
    auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    wprintf(L"%-36s %-13s %-9s %s\n", L"NAME", L"STATE", L"START", L"DISPLAY");
    for (DWORD i = 0; i < count; ++i) {
        // Pull start type via QueryServiceConfig — slower per-service but
        // we want it in the output. Skip if open fails.
        SC_HANDLE h = ::OpenServiceW(scm, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        DWORD startType = 0;
        if (h) {
            DWORD bytesNeeded = 0;
            ::QueryServiceConfigW(h, nullptr, 0, &bytesNeeded);
            std::vector<BYTE> cfgBuf(bytesNeeded);
            QUERY_SERVICE_CONFIGW* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
            if (::QueryServiceConfigW(h, cfg, bytesNeeded, &bytesNeeded)) {
                startType = cfg->dwStartType;
            }
            ::CloseServiceHandle(h);
        }
        wprintf(L"%-36s %-13s %-9s %s\n",
                svcs[i].lpServiceName,
                StateName(svcs[i].ServiceStatusProcess.dwCurrentState),
                StartTypeName(startType),
                svcs[i].lpDisplayName);
    }
    ::CloseServiceHandle(scm);
    return 0;
}

// Open a service handle with the access mask the caller needs. Returns
// {scm, svc} or {nullptr, nullptr} on failure (with a printed message).
struct ScmHandles { SC_HANDLE scm = nullptr; SC_HANDLE svc = nullptr; };
ScmHandles OpenSvc(const wchar_t* name, DWORD access) {
    ScmHandles h{};
    h.scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!h.scm) { fwprintf(stderr, L"OpenSCManager failed (%lu)\n", ::GetLastError()); return h; }
    h.svc = ::OpenServiceW(h.scm, name, access);
    if (!h.svc) {
        DWORD e = ::GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) fwprintf(stderr, L"No such service: %s\n", name);
        else                                    fwprintf(stderr, L"OpenService %s failed (%lu)\n", name, e);
        ::CloseServiceHandle(h.scm); h.scm = nullptr;
    }
    return h;
}

int CmdStop(const wchar_t* name) {
    if (!IsAdmin()) { fwprintf(stderr, L"drv stop: requires admin\n"); return 1; }
    auto h = OpenSvc(name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!h.svc) return 1;
    SERVICE_STATUS st{};
    if (!::ControlService(h.svc, SERVICE_CONTROL_STOP, &st)) {
        DWORD e = ::GetLastError();
        ::CloseServiceHandle(h.svc); ::CloseServiceHandle(h.scm);
        if (e == ERROR_INVALID_SERVICE_CONTROL || e == 1052) {
            fwprintf(stderr,
                L"drv stop %s: SCM error %lu (service does not accept STOP).\n"
                L"Try `winternal drv unload %s` for a kernel-side force-unload.\n",
                name, e, name);
        } else {
            fwprintf(stderr, L"drv stop %s: error %lu\n", name, e);
        }
        return 1;
    }
    wprintf(L"%s: stop requested\n", name);
    ::CloseServiceHandle(h.svc); ::CloseServiceHandle(h.scm);
    return 0;
}

int CmdStart(const wchar_t* name) {
    if (!IsAdmin()) { fwprintf(stderr, L"drv start: requires admin\n"); return 1; }
    auto h = OpenSvc(name, SERVICE_START);
    if (!h.svc) return 1;
    BOOL ok = ::StartServiceW(h.svc, 0, nullptr);
    DWORD e = ::GetLastError();
    ::CloseServiceHandle(h.svc); ::CloseServiceHandle(h.scm);
    if (!ok && e != ERROR_SERVICE_ALREADY_RUNNING) {
        fwprintf(stderr, L"drv start %s: error %lu\n", name, e);
        return 1;
    }
    wprintf(L"%s: %s\n", name, (e == ERROR_SERVICE_ALREADY_RUNNING) ? L"already running" : L"started");
    return 0;
}

int CmdSetStartType(const wchar_t* name, DWORD startType) {
    if (!IsAdmin()) { fwprintf(stderr, L"requires admin\n"); return 1; }
    auto h = OpenSvc(name, SERVICE_CHANGE_CONFIG);
    if (!h.svc) return 1;
    BOOL ok = ::ChangeServiceConfigW(h.svc, SERVICE_NO_CHANGE, startType, SERVICE_NO_CHANGE,
                                     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    DWORD e = ::GetLastError();
    ::CloseServiceHandle(h.svc); ::CloseServiceHandle(h.scm);
    if (!ok) { fwprintf(stderr, L"ChangeServiceConfig %s: error %lu\n", name, e); return 1; }
    wprintf(L"%s: StartType = %s\n", name, StartTypeName(startType));
    return 0;
}

int CmdDelete(const wchar_t* name) {
    if (!IsAdmin()) { fwprintf(stderr, L"drv delete: requires admin\n"); return 1; }
    auto h = OpenSvc(name, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!h.svc) return 1;
    SERVICE_STATUS st{};
    ::ControlService(h.svc, SERVICE_CONTROL_STOP, &st);   // best effort
    BOOL ok = ::DeleteService(h.svc);
    DWORD e = ::GetLastError();
    ::CloseServiceHandle(h.svc); ::CloseServiceHandle(h.scm);
    if (!ok && e != ERROR_SERVICE_MARKED_FOR_DELETE) {
        fwprintf(stderr, L"drv delete %s: error %lu\n", name, e);
        return 1;
    }
    wprintf(L"%s: deleted (image stays in memory until reboot if it was loaded)\n", name);
    return 0;
}

// Convert a DOS path ("C:\foo\bar.sys") to an NT-style path ("\??\C:\foo\bar.sys")
// for use by ZwLoadDriver. Returns true on success.
bool DosToNtPath(const wchar_t* dos, wchar_t* out, size_t outChars) {
    wchar_t full[MAX_PATH];
    if (!::GetFullPathNameW(dos, MAX_PATH, full, nullptr)) return false;
    int n = _snwprintf_s(out, outChars, _TRUNCATE, L"\\??\\%ls", full);
    return n > 0;
}

int CmdLoad(const wchar_t* name, const wchar_t* sysPath) {
    if (!IsAdmin()) { fwprintf(stderr, L"drv load: requires admin\n"); return 1; }

    wchar_t full[MAX_PATH], ntPath[MAX_PATH + 8];
    if (!::GetFullPathNameW(sysPath, MAX_PATH, full, nullptr)) {
        fwprintf(stderr, L"drv load: cannot resolve path %s (%lu)\n", sysPath, ::GetLastError());
        return 1;
    }
    if (::GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"drv load: no such file %s\n", full);
        return 1;
    }
    if (!DosToNtPath(sysPath, ntPath, MAX_PATH + 8)) {
        fwprintf(stderr, L"drv load: NT-path conversion failed\n");
        return 1;
    }

    // Prefer the kernel path when Winternal.sys is loaded — fewer round-trips
    // through SCM, single privileged dispatch in audit log.
    DriverSession ds;
    if (ds.open()) {
        if (!ds.kdrvRegister(name, ntPath)) {
            fwprintf(stderr, L"drv load: KDRV_REGISTER failed (%lu) — falling back to SCM\n", ::GetLastError());
        } else if (!ds.kdrvLoad(name)) {
            DWORD e = ::GetLastError();
            if (e == 577) {
                fwprintf(stderr, L"drv load %s: KDRV_LOAD got 577 — image not accepted.\n"
                                 L"  bcdedit /set testsigning on  (then reboot)\n", name);
            } else {
                fwprintf(stderr, L"drv load %s: KDRV_LOAD failed (%lu)\n", name, e);
            }
            return 1;
        } else {
            wprintf(L"%s: registered + loaded via Winternal.sys (NT path %s)\n", name, ntPath);
            return 0;
        }
    }

    // Fallback: SCM path when Winternal.sys isn't available.
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) { fwprintf(stderr, L"OpenSCManager failed (%lu)\n", ::GetLastError()); return 1; }

    SC_HANDLE svc = ::OpenServiceW(scm, name, SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = ::CreateServiceW(scm, name, name,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            full, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            fwprintf(stderr, L"drv load: CreateService failed (%lu)\n", e);
            return 1;
        }
        wprintf(L"%s: service created at %s\n", name, full);
    } else {
        ::ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                               full, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        wprintf(L"%s: service exists, binary path -> %s\n", name, full);
    }

    BOOL ok = ::StartServiceW(svc, 0, nullptr);
    DWORD e = ::GetLastError();
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);

    if (ok)                                       { wprintf(L"%s: started (SCM)\n", name); return 0; }
    if (e == ERROR_SERVICE_ALREADY_RUNNING)       { wprintf(L"%s: already running\n", name); return 0; }
    if (e == 577) {
        fwprintf(stderr, L"drv load %s: 577 — bcdedit /set testsigning on (then reboot)\n", name);
    } else {
        fwprintf(stderr, L"drv load %s: StartService failed (%lu)\n", name, e);
    }
    return 1;
}

int CmdForceUnload(const wchar_t* name) {
    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"drv unload: Winternal.sys is not loaded (open failed: %lu)\n", ::GetLastError());
        return 1;
    }
    if (!ds.forceUnloadDriver(name)) {
        fwprintf(stderr, L"drv unload %s: error %lu\n", name, ::GetLastError());
        return 1;
    }
    wprintf(L"%s: DriverUnload invoked. The image stays mapped until reboot; "
           L"`drv delete` to remove the service entry.\n", name);
    return 0;
}

int Usage() {
    fwprintf(stderr,
        L"usage: winternal drv <subcommand> [args]\n"
        L"  list                          enumerate kernel-mode services\n"
        L"  load    <name> <sys-path>    create service + start it\n"
        L"  start   <name>                SCM start an existing service\n"
        L"  stop    <name>                SCM stop\n"
        L"  enable  <name>                StartType = demand\n"
        L"  disable <name>                StartType = disabled\n"
        L"  delete  <name>                DeleteService (after best-effort stop)\n"
        L"  unload  <name>                force kernel unload (uses Winternal.sys)\n");
    return 1;
}

} // namespace

namespace winternal {
int RunDriverMgmt(int argc, wchar_t** argv) {
    if (argc < 1) return Usage();
    std::wstring_view sub = argv[0];
    if (sub == L"list") return CmdList();
    if (argc < 2) { fwprintf(stderr, L"drv %s: missing service name\n", argv[0]); return 1; }
    if (sub == L"load") {
        if (argc < 3) { fwprintf(stderr, L"drv load: usage: drv load <name> <sys-path>\n"); return 1; }
        return CmdLoad(argv[1], argv[2]);
    }
    if (sub == L"stop")    return CmdStop(argv[1]);
    if (sub == L"start")   return CmdStart(argv[1]);
    if (sub == L"enable")  return CmdSetStartType(argv[1], SERVICE_DEMAND_START);
    if (sub == L"disable") return CmdSetStartType(argv[1], SERVICE_DISABLED);
    if (sub == L"delete")  return CmdDelete(argv[1]);
    if (sub == L"unload")  return CmdForceUnload(argv[1]);
    return Usage();
}
}
