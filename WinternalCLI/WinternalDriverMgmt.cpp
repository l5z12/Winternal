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
#include "WClap.h"
#include "Symbols/SymbolResolver.h"
#include <Windows.h>
#include <winsvc.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

using namespace winternal;

namespace {

// Case-insensitive shell-style wildcard match. Mirrors the kernel-side
// WinternalMatchWildcard exactly so the CLI pre-check predicts what the
// driver would do. `*` matches any run of chars (including none), `?` one.
bool MatchPatternIcase(std::wstring_view pat, std::wstring_view str) {
    size_t pi = 0, si = 0;
    size_t starPi = (size_t)-1, starSi = 0;
    auto lower = [](wchar_t c) -> wchar_t {
        return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
    };
    while (si < str.size()) {
        if (pi < pat.size() && pat[pi] == L'*') {
            starPi = pi++;
            starSi = si;
            continue;
        }
        if (pi < pat.size()) {
            wchar_t p = lower(pat[pi]);
            wchar_t s = lower(str[si]);
            if (p == L'?' || p == s) { ++pi; ++si; continue; }
        }
        if (starPi != (size_t)-1) {
            pi = starPi + 1;
            si = ++starSi;
            continue;
        }
        return false;
    }
    while (pi < pat.size() && pat[pi] == L'*') ++pi;
    return pi == pat.size();
}

const wchar_t* DrvActionName(uint32_t a) {
    switch (a) {
    case WINTERNAL_DRV_ACT_ALLOW: return L"ALLOW";
    case WINTERNAL_DRV_ACT_DENY:  return L"DENY";
    case WINTERNAL_DRV_ACT_LOG:   return L"LOG";
    default:                       return L"?";
    }
}

int ParseDrvAction(std::wstring_view s) {
    auto eq = [&](const wchar_t* lit) {
        if (wcslen(lit) != s.size()) return false;
        for (size_t i = 0; i < s.size(); ++i) {
            wchar_t a = s[i]; if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
            if (a != lit[i]) return false;
        }
        return true;
    };
    if (eq(L"allow")) return WINTERNAL_DRV_ACT_ALLOW;
    if (eq(L"deny"))  return WINTERNAL_DRV_ACT_DENY;
    if (eq(L"log"))   return WINTERNAL_DRV_ACT_LOG;
    return -1;
}

// Accepts 0x... NT hex or small decimal Win32 codes (5 = ACCESS_DENIED,
// 2 = NAME_NOT_FOUND, etc.). Subset of ResolveStatusInput in
// WinternalCLI.cpp -- duplicated here so this TU doesn't depend on that
// one's symbol table.
uint32_t ParseStatusArg(const std::wstring& s) {
    if (s.empty()) return 0xC0000022u;
    if (s.size() >= 2 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) {
        return (uint32_t)wcstoul(s.c_str(), nullptr, 16);
    }
    bool hasHex = false, allHex = !s.empty();
    for (wchar_t c : s) {
        if ((c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')) hasHex = true;
        else if (!(c >= L'0' && c <= L'9')) { allHex = false; break; }
    }
    if (allHex && (hasHex || s.size() == 8)) return (uint32_t)wcstoul(s.c_str(), nullptr, 16);
    uint32_t v = (uint32_t)wcstoul(s.c_str(), nullptr, 10);
    switch (v) {
    case 0:   return 0x00000000u;
    case 1:   return 0xC0000034u;   // NAME_NOT_FOUND
    case 2:   return 0xC0000034u;
    case 3:   return 0xC000003Au;   // PATH_NOT_FOUND
    case 5:   return 0xC0000022u;   // ACCESS_DENIED
    case 87:  return 0xC000000Du;   // INVALID_PARAMETER
    default:  return v;
    }
}

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

int CmdList(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv list");
    app.about(L"Enumerate kernel-mode service entries from the SCM database. "
              L"Shows current state (running/stopped) and configured start "
              L"type (boot/system/auto/demand/disabled).");
    app.parse(argc, argv);

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

int CmdStop(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv stop");
    app.about(L"Send SERVICE_CONTROL_STOP to a kernel service via SCM. If the "
              L"service doesn't accept stop (error 1052), use `drv unload` for "
              L"a kernel-side force-unload via Winternal.sys.")
       .arg(wclap::Arg(L"name").positional().required().help(L"Service name"));
    auto m = app.parse(argc, argv);
    const wchar_t* name = m.value(L"name")->c_str();

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

int CmdStart(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv start");
    app.about(L"StartService on an existing kernel-service entry. Routes "
              L"through SCM, which ultimately calls NtLoadDriver -- so `drv "
              L"rule deny` patterns apply here too.")
       .arg(wclap::Arg(L"name").positional().required().help(L"Service name"));
    auto m = app.parse(argc, argv);
    const wchar_t* name = m.value(L"name")->c_str();

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

// Shared implementation for enable/disable. startType is fixed by the
// caller; `verb` is just for nicer error/help text.
int CmdSetStartType_Impl(int argc, wchar_t** argv, const wchar_t* verb, DWORD startType) {
    std::wstring progName = std::wstring(L"winternal drv ") + verb;
    wclap::App app(progName.c_str());
    if (startType == SERVICE_DEMAND_START) {
        app.about(L"Set the service StartType to SERVICE_DEMAND_START (3) -- "
                  L"the service can be brought up on demand via `sc start` / "
                  L"`drv start`, but doesn't auto-load at boot.");
    } else {
        app.about(L"Set the service StartType to SERVICE_DISABLED (4) -- SCM "
                  L"refuses to start the service until it's re-enabled. "
                  L"Already-running services keep running until stopped.");
    }
    app.arg(wclap::Arg(L"name").positional().required().help(L"Service name"));
    auto m = app.parse(argc, argv);
    const wchar_t* name = m.value(L"name")->c_str();

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

int CmdEnable(int argc, wchar_t** argv)  { return CmdSetStartType_Impl(argc, argv, L"enable",  SERVICE_DEMAND_START); }
int CmdDisable(int argc, wchar_t** argv) { return CmdSetStartType_Impl(argc, argv, L"disable", SERVICE_DISABLED); }

int CmdDelete(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv delete");
    app.about(L"DeleteService on the named entry. Tries SERVICE_CONTROL_STOP "
              L"first as a best-effort. The driver image stays mapped until "
              L"reboot if it was actually loaded; this only removes the SCM "
              L"registration.")
       .arg(wclap::Arg(L"name").positional().required().help(L"Service name"));
    auto m = app.parse(argc, argv);
    const wchar_t* name = m.value(L"name")->c_str();

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

// CLI-side pre-check: walk the kernel rule list and, if a DENY rule
// matches the service name, refuse the load with a friendlier error
// than the kernel's STATUS_ACCESS_DENIED. The kernel hook is still the
// load-bearing enforcement; this just gives users a nice "rule N
// matched" message before we issue the IOCTL. Returns true if the load
// should proceed.
bool DrvRulePrecheck(const wchar_t* name) {
    DriverSession ds;
    if (!ds.open()) return true;       // driver not loaded -> no rules to honor
    bool hookLive = false, cmLive = false;
    auto rules = ds.drvRuleList(&hookLive, &cmLive);
    if (rules.empty()) return true;
    for (auto& r : rules) {
        if (r.action != WINTERNAL_DRV_ACT_DENY) continue;
        if (!MatchPatternIcase(r.pattern, name)) continue;
        uint32_t st = r.status ? r.status : 0xC0000022u;
        const wchar_t* warn =
            (!hookLive && !cmLive) ? L" [NEITHER layer live -- rule listed but not enforced kernel-side]"
                                   : L"";
        fwprintf(stderr,
            L"drv load %ls: blocked by rule %u (pattern '%ls' -> DENY, status 0x%08X)%ls\n",
            name, r.ruleId, r.pattern.c_str(), st, warn);
        return false;
    }
    return true;
}

int CmdLoad(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv load");
    app.about(L"Register a kernel service for the given .sys file and start "
              L"it. Prefers the Winternal.sys kernel path (single privileged "
              L"dispatch in the audit log) and falls back to SCM "
              L"CreateService+StartService when the driver isn't loaded.\n"
              L"\n"
              L"Honors `drv rule deny` patterns -- pre-check happens client-\n"
              L"side BEFORE the IOCTL so the user gets a friendly error, and\n"
              L"the kernel NtLoadDriver hook is the load-bearing enforcer.")
       .arg(wclap::Arg(L"name").positional().required()
                .help(L"Service name (registry key under \\Services\\<name>)"))
       .arg(wclap::Arg(L"sys-path").positional().required()
                .help(L"Path to the .sys file (relative or absolute)"));
    auto m = app.parse(argc, argv);
    const wchar_t* name    = m.value(L"name")->c_str();
    const wchar_t* sysPath = m.value(L"sys-path")->c_str();

    if (!IsAdmin()) { fwprintf(stderr, L"drv load: requires admin\n"); return 1; }
    if (!DrvRulePrecheck(name)) return 1;

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

int CmdForceUnload(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv unload");
    app.about(L"Kernel-side force-unload via Winternal.sys: resolves the "
              L"driver object by name and calls its DriverUnload routine "
              L"directly, bypassing SCM. Use when SCM stop fails (error "
              L"1052). The image stays mapped until reboot; pair with "
              L"`drv delete` to remove the SCM entry.")
       .arg(wclap::Arg(L"name").positional().required()
                .help(L"Driver object name (no \\Driver\\ prefix)"));
    auto m = app.parse(argc, argv);
    const wchar_t* name = m.value(L"name")->c_str();

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

int CmdRuleAdd(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv rule add");
    app.about(L"Install a driver-load block rule. Patterns are case-insensitive "
              L"shell wildcards matched against the service-name leaf of the "
              L"registry path NtLoadDriver receives -- e.g. `Foo` for "
              L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Foo. "
              L"Catches SCM-driven loads (services.exe) AND direct ZwLoadDriver "
              L"callers (including our own `drv load`).\n"
              L"\n"
              L"--status overrides the NTSTATUS the loader sees on DENY. "
              L"Default 5 (STATUS_ACCESS_DENIED). Decimal Win32 codes or 0x... "
              L"NT hex accepted. Status is ignored for allow/log.\n"
              L"\n"
              L"WARNING: a pattern like `*` blocks ALL further driver loads. "
              L"Boot-time services already running aren't affected, but anything "
              L"new -- including filter drivers SCM tries to bring up on demand -- "
              L"will fail. Test on a VM.")
       .arg(wclap::Arg(L"pattern").positional().required()
                .help(L"Wildcard pattern against the service name"))
       .arg(wclap::Arg(L"action").positional().required()
                .help(L"allow | deny | log"))
       .arg(wclap::Arg(L"status").long_name(L"status").takes_value()
                .default_value(L"5")
                .help(L"NTSTATUS for DENY (decimal Win32 or 0x... NT hex). Default 5."));
    auto m = app.parse(argc, argv);
    std::wstring pattern = *m.value(L"pattern");
    int act = ParseDrvAction(*m.value(L"action"));
    if (act < 0) {
        fwprintf(stderr, L"drv rule add: bad action '%ls' (use allow|deny|log)\n",
                 m.value(L"action")->c_str());
        return 1;
    }
    uint32_t status = ParseStatusArg(*m.value(L"status"));

    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"drv rule add: Winternal.sys is not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    auto id = ds.drvRuleAdd(pattern, (DriverSession::DrvRuleAction)act, status);
    if (!id) {
        DWORD e = ::GetLastError();
        fwprintf(stderr, L"drv rule add: failed (%lu)\n", e);
        if (e == ERROR_NOT_READY) {
            // Neither the inline hook NOR the Cm callback registered. The
            // inline hook can fail under HVCI / WDAC; the Cm callback fails
            // for things like altitude collision or driver not yet fully
            // initialized. Both failing simultaneously is rare and usually
            // means the driver was loaded into a really hostile environment.
            fwprintf(stderr,
                L"  hint: no enforcement layer is live. Both the NtLoadDriver\n"
                L"  inline hook AND the Cm-callback fallback failed to register.\n"
                L"  Check kernel debug output for the specific status codes.\n");
        }
        return 1;
    }
    wprintf(L"added drv rule %u: %ls -> %ls (status 0x%08X)\n",
            *id, pattern.c_str(), DrvActionName((uint32_t)act), status);
    return 0;
}

int CmdRuleList(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv rule list");
    app.about(L"List installed driver-load rules and whether the NtLoadDriver "
              L"hook is actually live (HVCI can reject the install).");
    app.parse(argc, argv);

    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"drv rule list: Winternal.sys is not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    bool hookLive = false, cmLive = false;
    auto rules = ds.drvRuleList(&hookLive, &cmLive);
    if (hookLive && cmLive) {
        wprintf(L"enforcement: NtLoadDriver inline hook + Cm-callback (defense in depth)\n");
    } else if (hookLive) {
        wprintf(L"enforcement: NtLoadDriver inline hook (precise, blocks only loads)\n");
    } else if (cmLive) {
        wprintf(L"enforcement: Cm-callback on \\Services\\<denied> (also blocks `sc query`, `reg query`)\n");
    } else {
        wprintf(L"enforcement: INACTIVE (rules listed but not enforced)\n");
    }
    if (rules.empty()) { wprintf(L"(no rules)\n"); return 0; }
    wprintf(L"%-6ls  %-6ls  %-12ls  %-7ls  %ls\n",
            L"ID", L"ACTION", L"STATUS", L"HITS", L"PATTERN");
    for (auto& r : rules) {
        wprintf(L"%-6u  %-6ls  0x%08X    %-7u  %ls\n",
                r.ruleId, DrvActionName(r.action),
                r.status, r.matchCount, r.pattern.c_str());
    }
    return 0;
}

int CmdRuleRemove(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv rule remove");
    app.about(L"Remove a drv rule by ID (see `drv rule list`).")
       .arg(wclap::Arg(L"id").positional().required().help(L"Rule ID (decimal)"));
    auto m = app.parse(argc, argv);
    uint32_t id = (uint32_t)*m.value_u64(L"id");

    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"drv rule remove: Winternal.sys is not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    if (!ds.drvRuleRemove(id)) {
        fwprintf(stderr, L"drv rule remove %u: failed (%lu)\n", id, ::GetLastError());
        return 1;
    }
    wprintf(L"rule %u removed\n", id);
    return 0;
}

int CmdRuleClear(int argc, wchar_t** argv) {
    wclap::App app(L"winternal drv rule clear");
    app.about(L"Remove every driver-load rule.");
    app.parse(argc, argv);

    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"drv rule clear: Winternal.sys is not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    if (!ds.drvRuleClear()) {
        fwprintf(stderr, L"drv rule clear: failed (%lu)\n", ::GetLastError());
        return 1;
    }
    wprintf(L"all drv rules cleared\n");
    return 0;
}

int CmdRule(int argc, wchar_t** argv) {
    if (argc < 1) {
        wclap::App app(L"winternal drv rule");
        app.about(L"Prohibit kernel-driver loads by pattern. Symmetric to "
                  L"`proc rule` but enforced inside the NtLoadDriver prologue "
                  L"hook -- catches every load path (SCM, direct ZwLoadDriver, "
                  L"our own `drv load`).")
           .subcommand(wclap::App(L"add").about(L"Install a rule"))
           .subcommand(wclap::App(L"list").about(L"Show installed rules + hook state"))
           .subcommand(wclap::App(L"remove").about(L"Remove a rule by ID"))
           .subcommand(wclap::App(L"clear").about(L"Remove all rules"));
        app.print_help(stderr);
        return 1;
    }
    std::wstring_view sub = argv[0];
    int sa = argc - 1;
    wchar_t** av = argv + 1;
    if (sub == L"add")    return CmdRuleAdd(sa, av);
    if (sub == L"list")   return CmdRuleList(sa, av);
    if (sub == L"remove") return CmdRuleRemove(sa, av);
    if (sub == L"clear")  return CmdRuleClear(sa, av);
    fwprintf(stderr, L"drv rule: unknown action '%ls'\n", argv[0]);
    return 1;
}

int PrintTopHelp() {
    wclap::App app(L"winternal drv");
    app.about(L"Kernel-driver management: list / load / start / stop / "
              L"enable / disable / delete / unload kernel-mode services, "
              L"and `rule` to prohibit driver loads by name pattern.")
       .subcommand(wclap::App(L"list").about(L"Enumerate kernel-mode service entries"))
       .subcommand(wclap::App(L"load").about(L"Register + start a kernel service"))
       .subcommand(wclap::App(L"start").about(L"SCM start an existing service"))
       .subcommand(wclap::App(L"stop").about(L"SCM stop"))
       .subcommand(wclap::App(L"enable").about(L"StartType = demand"))
       .subcommand(wclap::App(L"disable").about(L"StartType = disabled"))
       .subcommand(wclap::App(L"delete").about(L"DeleteService (best-effort stop first)"))
       .subcommand(wclap::App(L"unload").about(L"Force kernel unload via Winternal.sys"))
       .subcommand(wclap::App(L"rule").about(L"Prohibit kernel-driver loads by name pattern"));
    app.print_help(stderr);
    return 1;
}

} // namespace

namespace winternal {
int RunDriverMgmt(int argc, wchar_t** argv) {
    if (argc < 1) return PrintTopHelp();
    std::wstring_view sub = argv[0];
    int sa = argc - 1;
    wchar_t** av = argv + 1;
    if (sub == L"list")    return CmdList(sa, av);
    if (sub == L"load")    return CmdLoad(sa, av);
    if (sub == L"start")   return CmdStart(sa, av);
    if (sub == L"stop")    return CmdStop(sa, av);
    if (sub == L"enable")  return CmdEnable(sa, av);
    if (sub == L"disable") return CmdDisable(sa, av);
    if (sub == L"delete")  return CmdDelete(sa, av);
    if (sub == L"unload")  return CmdForceUnload(sa, av);
    if (sub == L"rule")    return CmdRule(sa, av);
    if (sub == L"--help" || sub == L"-h" || sub == L"help") { (void)PrintTopHelp(); return 0; }
    fwprintf(stderr, L"drv: unknown subcommand '%ls'\n", argv[0]);
    return PrintTopHelp();
}
}
