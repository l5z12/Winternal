// `winternal install` / `uninstall` / `status` subcommands.
//
// All service operations go through the Windows SCM API rather than shelling
// to sc.exe — direct error reporting, no quoting hazards, and works without
// PATH lookups. The .sys is copied to %SystemRoot%\System32\drivers\ to
// match what every other Windows kernel driver does.
//
// All three commands require Administrator. The CLI returns 1 + a clear
// hint when run unelevated rather than failing midway through.

#include "WinternalCore.h"
#include "../Winternal/Public.h"
#include <Windows.h>
#include <winsvc.h>
#include <shlwapi.h>
#include <cstdio>
#include <filesystem>
#include <string>

using namespace winternal;

namespace {

constexpr const wchar_t* kServiceName = L"Winternal";
constexpr const wchar_t* kDisplayName = L"Winternal ARK research driver";
constexpr const wchar_t* kInstalledSysName = L"Winternal.sys";

bool IsAdmin() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD len = sizeof(te);
        if (::GetTokenInformation(token, TokenElevation, &te, sizeof(te), &len)) {
            elevated = te.TokenIsElevated;
        }
        ::CloseHandle(token);
    }
    return elevated != FALSE;
}

// Resolve the .sys to install. Order of preference:
//   1. user-supplied path
//   2. <exe-dir>\Winternal.sys                (single-folder deploy)
//   3. <exe-dir>\..\..\Winternal\x64\Release\Winternal\Winternal.sys (dev build)
std::wstring ResolveSourceSys(const wchar_t* override_) {
    if (override_ && *override_) return override_;

    wchar_t exe[MAX_PATH];
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(exe).parent_path();

    std::filesystem::path candidates[] = {
        exeDir / L"Winternal.sys",
        exeDir / L".." / L".." / L"Winternal" / L"x64" / L"Release" / L"Winternal" / L"Winternal.sys",
    };
    for (auto& c : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(c, ec)) return c.wstring();
    }
    return {};
}

std::wstring InstalledSysPath() {
    wchar_t winDir[MAX_PATH];
    ::GetSystemDirectoryW(winDir, MAX_PATH);  // -> C:\Windows\System32
    return std::wstring(winDir) + L"\\drivers\\" + kInstalledSysName;
}

// Returns 1 if testsigning is on, 0 if off, -1 if we couldn't tell.
//
// The authoritative source is NtQuerySystemInformation with class
// SystemCodeIntegrityInformation (103). The CodeIntegrityOptions field
// has CODEINTEGRITY_OPTION_TESTSIGN (0x02) set when /testsigning is on.
// The older registry path HKLM\System\...\CI\TestSigningStatus doesn't
// exist on modern builds — using NtQSI gives a consistent answer across
// Win10 21H2 through Win11 24H2.
int CheckTestSigning() {
    typedef struct _SCII { ULONG Length; ULONG CodeIntegrityOptions; } SCII;
    constexpr ULONG kSystemCodeIntegrityInformation = 103;
    constexpr ULONG kOptionTestSign = 0x02;

    typedef LONG (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return -1;
    auto NtQSI = (NtQSI_t)::GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    SCII ci{};
    ci.Length = sizeof(ci);
    LONG s = NtQSI(kSystemCodeIntegrityInformation, &ci, sizeof(ci), nullptr);
    if (s < 0) return -1;
    return (ci.CodeIntegrityOptions & kOptionTestSign) ? 1 : 0;
}

int CmdInstall(int argc, wchar_t** argv) {
    if (!IsAdmin()) {
        fwprintf(stderr, L"install: requires an elevated prompt (right-click -> Run as administrator).\n");
        return 1;
    }
    const wchar_t* srcOverride = nullptr;
    bool autoStart = true;   // default: start the service after install
    for (int i = 0; i < argc; ++i) {
        if (wcscmp(argv[i], L"--path") == 0 && i + 1 < argc) srcOverride = argv[++i];
        else if (wcscmp(argv[i], L"--start") == 0)    autoStart = true;   // legacy no-op
        else if (wcscmp(argv[i], L"--no-start") == 0) autoStart = false;
    }

    std::wstring src = ResolveSourceSys(srcOverride);
    if (src.empty()) {
        fwprintf(stderr, L"install: cannot find Winternal.sys (pass --path <full-path>).\n");
        return 1;
    }
    std::wstring dst = InstalledSysPath();
    wprintf(L"Copy: %s\n   -> %s\n", src.c_str(), dst.c_str());
    if (!::CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
        fwprintf(stderr, L"install: copy failed (%lu).\n", ::GetLastError());
        return 1;
    }

    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) { fwprintf(stderr, L"install: OpenSCManager failed (%lu).\n", ::GetLastError()); return 1; }

    // If the service already exists, reuse it — make this idempotent.
    SC_HANDLE svc = ::OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = ::CreateServiceW(
            scm, kServiceName, kDisplayName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            dst.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            DWORD e = ::GetLastError();
            ::CloseServiceHandle(scm);
            fwprintf(stderr, L"install: CreateService failed (%lu).\n", e);
            return 1;
        }
        wprintf(L"Created service '%s'.\n", kServiceName);
    } else {
        // Update existing service binary path in case --path moved.
        if (!::ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                    dst.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            fwprintf(stderr, L"install: ChangeServiceConfig failed (%lu) — proceeding anyway.\n", ::GetLastError());
        }
        wprintf(L"Service '%s' already present — reused.\n", kServiceName);
    }

    if (autoStart) {
        if (::StartServiceW(svc, 0, nullptr)) {
            wprintf(L"Service started.\n");
        } else {
            DWORD e = ::GetLastError();
            if (e == ERROR_SERVICE_ALREADY_RUNNING) {
                wprintf(L"Service already running.\n");
            } else if (e == 577 /* ERROR_INVALID_IMAGE_HASH */) {
                fwprintf(stderr, L"install: start failed (577) — signing not accepted.\n"
                                 L"  Enable test signing and reboot:\n"
                                 L"    bcdedit /set testsigning on\n");
            } else {
                fwprintf(stderr, L"install: StartService failed (%lu).\n", e);
            }
        }
    }

    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);

    int testSigning = CheckTestSigning();
    if (testSigning != 1) {
        wprintf(L"\nNote: test signing appears OFF. To load test-signed drivers, run from an\n"
               L"elevated prompt and reboot:\n  bcdedit /set testsigning on\n");
    }

    wprintf(L"\nNext: 'winternal status' to verify, 'winternal kver' to round-trip an IOCTL.\n");
    return 0;
}

int CmdUninstall() {
    if (!IsAdmin()) {
        fwprintf(stderr, L"uninstall: requires an elevated prompt.\n");
        return 1;
    }
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { fwprintf(stderr, L"uninstall: OpenSCManager failed (%lu).\n", ::GetLastError()); return 1; }

    SC_HANDLE svc = ::OpenServiceW(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS st{};
        ::ControlService(svc, SERVICE_CONTROL_STOP, &st);   // best-effort stop
        if (!::DeleteService(svc)) {
            DWORD e = ::GetLastError();
            if (e != ERROR_SERVICE_MARKED_FOR_DELETE) {
                fwprintf(stderr, L"uninstall: DeleteService failed (%lu).\n", e);
            }
        }
        ::CloseServiceHandle(svc);
        wprintf(L"Service '%s' deleted.\n", kServiceName);
    } else if (::GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        fwprintf(stderr, L"uninstall: OpenService failed (%lu).\n", ::GetLastError());
    }
    ::CloseServiceHandle(scm);

    std::wstring sys = InstalledSysPath();
    if (::DeleteFileW(sys.c_str())) {
        wprintf(L"Removed %s\n", sys.c_str());
    } else if (::GetLastError() != ERROR_FILE_NOT_FOUND) {
        fwprintf(stderr, L"uninstall: DeleteFile %s failed (%lu) — may need a reboot to release the lock.\n",
                 sys.c_str(), ::GetLastError());
    }
    return 0;
}

// End-to-end self-test. Each step writes a one-line PASS/FAIL with timing
// and bails on the first failure. Designed to be the second thing you run
// after `winternal install`.
int CmdSelftest() {
    // Print the Win32 GetLastError alongside the human cause — without it,
    // failures look like a mystery (e.g. "could not read kernel prologue").
    auto fail = [](const wchar_t* step, const char* why) {
        DWORD e = ::GetLastError();
        wprintf(L"[FAIL] %s -- %S  (GetLastError=%lu / 0x%08lx)\n", step, why, e, e);
        return 1;
    };

    DriverSession ds;
    wprintf(L"selftest: \\\\.\\Winternal\n");
    if (!ds.open()) {
        return fail(L"open driver",
                    "Winternal.sys is not loaded. Run `winternal install` first.");
    }
    wprintf(L"  [ok ] CreateFile succeeded\n");

    auto v = ds.getVersion();
    if (!v) return fail(L"GET_VERSION IOCTL", "DeviceIoControl returned FALSE");
    wprintf(L"  [ok ] driver version %u.%u\n", v->major, v->minor);

    auto pids = ds.enumPids();
    if (pids.empty()) return fail(L"ENUM_PIDS", "no PIDs returned");
    wprintf(L"  [ok ] ENUM_PIDS returned %zu processes\n", pids.size());

    auto sym = ds.ksym(L"PsLookupProcessByProcessId");
    if (!sym) return fail(L"KSYM", "PsLookupProcessByProcessId not resolved");
    wprintf(L"  [ok ] ksym('PsLookupProcessByProcessId') = 0x%llx\n", (unsigned long long)*sym);

    auto bytes = ds.kread(*sym, 16);
    if (!bytes) return fail(L"KMEM_READ", "DeviceIoControl returned FALSE");
    wprintf(L"  [ok ] kread(16) returned %zu bytes  first8 =", bytes->size());
    for (size_t i = 0; i < bytes->size() && i < 8; ++i) wprintf(L" %02x", (*bytes)[i]);
    wprintf(L"\n");

    auto lua = ds.luaExec("print(string.format('kernel-lua live, %d PIDs', #wnk.pids()))");
    if (!lua) return fail(L"LUA_EXEC IOCTL", "kernel-Lua call failed");
    if (lua->luaStatus != 0) return fail(L"LUA_EXEC kernel error",
                                          lua->output.empty() ? "(empty)" : lua->output.c_str());
    wprintf(L"  [ok ] kernel-Lua: %S", lua->output.c_str());
    if (lua->output.empty() || lua->output.back() != '\n') wprintf(L"\n");

    auto status = ds.lockdownStatus();
    if (!status) return fail(L"LOCKDOWN_STATUS", "IOCTL failed");
    wprintf(L"  [ok ] lockdown: %s\n", status->engaged ? L"ENGAGED" : L"open");

    auto audit = ds.auditTail(8);
    wprintf(L"  [ok ] audit_tail returned %zu rows\n", audit.size());

    // ---- NTFS surface ----
    // Pick the system volume (where Windows lives) so we have something
    // reliable on every Windows install. Resolve drive -> NT device name
    // and round-trip every NTFS IOCTL through DriverSession.
    wchar_t winDir[MAX_PATH] = {};
    ::GetWindowsDirectoryW(winDir, _countof(winDir));
    std::wstring drive(winDir, 2);                      // "C:"
    wchar_t devBuf[MAX_PATH] = {};
    DWORD devN = ::QueryDosDeviceW(drive.c_str(), devBuf, _countof(devBuf));
    if (!devN) {
        wprintf(L"  [warn] QueryDosDevice(%ls) failed (%lu) — skipping NTFS round-trip\n",
                drive.c_str(), ::GetLastError());
    } else {
        std::wstring dev = devBuf;
        wprintf(L"  ntfs:  %ls -> %ls\n", drive.c_str(), dev.c_str());

        auto vd = ds.ntfsVolData(dev);
        if (!vd)                       return fail(L"NTFS_VOL_DATA",  "FSCTL passthrough failed");
        if (vd->bytesPerSector == 0)   return fail(L"NTFS_VOL_DATA",  "bytesPerSector=0");
        wprintf(L"  [ok ] NTFS_VOL_DATA   sector=%u cluster=%u mftLcn=0x%llx mftSize=%llu\n",
                vd->bytesPerSector, vd->bytesPerCluster,
                (unsigned long long)vd->mftStartLcn,
                (unsigned long long)vd->mftValidDataLength);

        auto uj = ds.ntfsUsnQuery(dev);
        if (!uj)                       return fail(L"NTFS_USN_QUERY", "no active journal");
        if (uj->journalId == 0)        return fail(L"NTFS_USN_QUERY", "journalId=0");
        wprintf(L"  [ok ] NTFS_USN_QUERY  id=%llu first=%lld next=%lld\n",
                (unsigned long long)uj->journalId, uj->firstUsn, uj->nextUsn);

        auto usn = ds.ntfsUsnRead(dev, uj->journalId, uj->firstUsn, 0xFFFFFFFF, false);
        if (!usn)                      return fail(L"NTFS_USN_READ",  "read returned nullopt");
        if (usn->size() < 8)           return fail(L"NTFS_USN_READ",  "short response (<8 bytes)");
        wprintf(L"  [ok ] NTFS_USN_READ   %zu bytes (next-USN cursor + records)\n", usn->size());

        auto mft = ds.ntfsMftEnum(dev, 0);
        if (!mft)                      return fail(L"NTFS_MFT_ENUM",  "FSCTL passthrough failed");
        if (mft->size() < 16)          return fail(L"NTFS_MFT_ENUM",  "short response");
        wprintf(L"  [ok ] NTFS_MFT_ENUM   %zu bytes from first batch\n", mft->size());

        // FILE_STREAM_INFORMATION on Windows itself — guaranteed to exist.
        std::wstring ntPath = L"\\??\\";
        ntPath += winDir;
        auto streams = ds.ntfsStreams(ntPath);
        if (!streams)                  return fail(L"NTFS_STREAMS",   "FileStreamInformation returned nullopt");
        wprintf(L"  [ok ] NTFS_STREAMS    %zu bytes for %ls\n", streams->size(), ntPath.c_str());

        // Raw read of the volume boot sector. NTFS BPB has "NTFS    " at
        // offset 3; if we don't see it, the raw-read path is broken.
        auto boot = ds.ntfsRawRead(dev, 0, 512);
        if (!boot)                     return fail(L"NTFS_RAW_READ",  "ZwReadFile returned nullopt");
        if (boot->size() < 512)        return fail(L"NTFS_RAW_READ",  "short read (<512 bytes)");
        const char* oem = reinterpret_cast<const char*>(boot->data() + 3);
        if (std::strncmp(oem, "NTFS", 4) != 0)
                                       return fail(L"NTFS_RAW_READ",  "boot-sector OEM-id != 'NTFS'");
        wprintf(L"  [ok ] NTFS_RAW_READ   512 bytes @ 0; OEM-id='NTFS'\n");

        // wnk.* binding round-trip — confirm the Lua surface mirrors the
        // C++ DriverSession surface (catches registry-table typos).
        std::string script =
            "local q = wnk.ntfs_usn_query([[" + std::string(dev.begin(), dev.end()) + "]])\n"
            "print('lua sees journalId='..tostring(q.journalId))\n";
        // ^ the dev path contains only ASCII; widechar->narrow trivially.
        auto lua2 = ds.luaExec(script);
        if (!lua2 || lua2->luaStatus != 0)
            return fail(L"wnk.ntfs_usn_query", "kernel-Lua binding round-trip failed");
        wprintf(L"  [ok ] wnk.ntfs_usn_query (lua binding)\n");
    }

    wprintf(L"\nselftest: all checks passed.\n");
    return 0;
}

int CmdStatus() {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { fwprintf(stderr, L"status: OpenSCManager failed (%lu).\n", ::GetLastError()); return 1; }
    SC_HANDLE svc = ::OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);

    if (!svc) {
        wprintf(L"Service:    NOT INSTALLED\n");
    } else {
        SERVICE_STATUS_PROCESS st{};
        DWORD got = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st, sizeof(st), &got)) {
            const wchar_t* state = L"unknown";
            switch (st.dwCurrentState) {
            case SERVICE_STOPPED:         state = L"stopped"; break;
            case SERVICE_START_PENDING:   state = L"start_pending"; break;
            case SERVICE_RUNNING:         state = L"RUNNING"; break;
            case SERVICE_STOP_PENDING:    state = L"stop_pending"; break;
            }
            wprintf(L"Service:    %s\n", state);
        }
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);

    int ts = CheckTestSigning();
    wprintf(L"TestSigning: %s\n",
            ts == 1 ? L"on" : ts == 0 ? L"off" : L"unknown");

    DriverSession ds;
    if (ds.open()) {
        if (auto v = ds.getVersion()) {
            wprintf(L"Driver:     online, version %u.%u\n", v->major, v->minor);
        } else {
            wprintf(L"Driver:     open ok, GET_VERSION failed (%lu)\n", ::GetLastError());
        }
    } else {
        wprintf(L"Driver:     not reachable via \\\\.\\Winternal (%lu)\n", ::GetLastError());
    }
    return 0;
}

} // namespace

namespace winternal {
int RunInstall(int argc, wchar_t** argv)   { return CmdInstall(argc, argv); }
int RunUninstall()                          { return CmdUninstall(); }
int RunStatus()                             { return CmdStatus(); }
int RunSelftest()                           { return CmdSelftest(); }
}
