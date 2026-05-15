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
#include <sddl.h>
#include <aclapi.h>
#include <cstdio>
#include <filesystem>
#include <string>

#pragma comment(lib, "advapi32.lib")

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

// Forward decl — used by install/uninstall to recover from a selfprotect-
// leftover DACL. Implementation lives near the selfprotect helpers below.
static bool RecoverServiceRegistry();

// Minifilter registry setup. FltRegisterFilter requires:
//   Services\Winternal\Instances                  (key)
//     DefaultInstance = "WinternalDefault"        (REG_SZ)
//   Services\Winternal\Instances\WinternalDefault (subkey)
//     Altitude = "385720.1932"                    (REG_SZ — free range)
//     Flags    = 0                                (REG_DWORD)
//   Services\Winternal\DependOnService = "FltMgr" (REG_MULTI_SZ; ensures
//                                                  fltmgr loads first)
// Without these the driver registers fine as a kernel service but
// FltRegisterFilter returns 0xC03A0014 (STATUS_FLT_NOT_INITIALIZED).
static bool SetupMinifilterRegistry() {
    HKEY hSvc = nullptr;
    LONG rc = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Winternal",
        0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &hSvc);
    if (rc != ERROR_SUCCESS) return false;

    static const wchar_t kDeps[]     = L"FltMgr\0";          // double-NUL terminated
    static const wchar_t kDefaultI[] = L"WinternalDefault";
    // Activity Monitor group (320000-329999) is far less crowded than the
    // Anti-Virus range. Defender et al. live around 328010-329980; we pick
    // 320200 which is unassigned in the public Microsoft altitude list.
    static const wchar_t kAltitude[] = L"320200";
    DWORD flags = 0;

    ::RegSetValueExW(hSvc, L"DependOnService", 0, REG_MULTI_SZ,
                     (const BYTE*)kDeps, sizeof(kDeps));

    HKEY hInstances = nullptr;
    rc = ::RegCreateKeyExW(hSvc, L"Instances", 0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_SET_VALUE | KEY_CREATE_SUB_KEY, nullptr, &hInstances, nullptr);
    if (rc != ERROR_SUCCESS) { ::RegCloseKey(hSvc); return false; }
    ::RegSetValueExW(hInstances, L"DefaultInstance", 0, REG_SZ,
                     (const BYTE*)kDefaultI, sizeof(kDefaultI));

    HKEY hDef = nullptr;
    rc = ::RegCreateKeyExW(hInstances, kDefaultI, 0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_SET_VALUE, nullptr, &hDef, nullptr);
    if (rc == ERROR_SUCCESS) {
        ::RegSetValueExW(hDef, L"Altitude", 0, REG_SZ,
                         (const BYTE*)kAltitude, sizeof(kAltitude));
        ::RegSetValueExW(hDef, L"Flags", 0, REG_DWORD,
                         (const BYTE*)&flags, sizeof(flags));
        ::RegCloseKey(hDef);
    }
    ::RegCloseKey(hInstances);
    ::RegCloseKey(hSvc);
    return true;
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
    DWORD openErr = svc ? 0 : ::GetLastError();
    if (!svc && openErr == ERROR_ACCESS_DENIED) {
        // Leftover from selfprotect — service exists but DACL is locked.
        // Restore a permissive DACL via direct registry write, then retry.
        wprintf(L"install: existing service has restrictive DACL (selfprotect leftover) — restoring via registry...\n");
        if (RecoverServiceRegistry()) {
            svc = ::OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
            if (svc) {
                wprintf(L"install: registry recovery succeeded; reusing service.\n");
            } else {
                fwprintf(stderr,
                    L"install: SCM still rejects (%lu). Reboot to let SCM reload the DACL, "
                    L"then re-run `winternal install`.\n", ::GetLastError());
                ::CloseServiceHandle(scm);
                return 1;
            }
        }
    }
    if (!svc) {
        // SERVICE_FILE_SYSTEM_DRIVER (Type=2) is the canonical type for
        // minifilter drivers — FltMgr is happier with this even though
        // Type=1 also works on modern Windows as long as the Instances
        // registry is populated.
        svc = ::CreateServiceW(
            scm, kServiceName, kDisplayName,
            SERVICE_ALL_ACCESS,
            SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            dst.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            DWORD e = ::GetLastError();
            if (e == ERROR_SERVICE_EXISTS) {
                // Service is in SCM but OpenService said ACCESS_DENIED *and*
                // the registry recovery above didn't help — SCM has the old
                // DACL cached in memory and won't refresh until reboot.
                fwprintf(stderr,
                    L"install: service exists in SCM but is unreachable (DACL-locked).\n"
                    L"  This is a selfprotect leftover. SCM caches DACLs in memory,\n"
                    L"  so a reboot is required. After reboot:\n"
                    L"    winternal install\n");
            } else {
                fwprintf(stderr, L"install: CreateService failed (%lu).\n", e);
            }
            ::CloseServiceHandle(scm);
            return 1;
        }
        wprintf(L"Created service '%s'.\n", kServiceName);
    } else {
        // Update existing service binary path in case --path moved.
        // Upgrade existing service to SERVICE_FILE_SYSTEM_DRIVER if it
        // was created earlier as Type=1. Required for the minifilter to
        // attach reliably under modern FltMgr.
        if (!::ChangeServiceConfigW(svc, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                    dst.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            fwprintf(stderr, L"install: ChangeServiceConfig failed (%lu) — proceeding anyway.\n", ::GetLastError());
        }
        wprintf(L"Service '%s' already present — reused.\n", kServiceName);
    }

    // Minifilter registry plumbing — required for FltRegisterFilter to
    // succeed when `ntfs filter add` engages the filter. Idempotent;
    // safe to re-run.
    if (!SetupMinifilterRegistry()) {
        fwprintf(stderr, L"install: minifilter registry setup failed (%lu) — "
                         L"`ntfs filter` may return STATUS_FLT_NOT_INITIALIZED.\n",
                 ::GetLastError());
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
    if (!svc && ::GetLastError() == ERROR_ACCESS_DENIED) {
        // Same selfprotect-leftover recovery as install: restore permissive
        // DACL via registry, then re-open.
        wprintf(L"uninstall: service DACL is locked (selfprotect leftover) — restoring via registry...\n");
        if (RecoverServiceRegistry())
            svc = ::OpenServiceW(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (!svc) {
            fwprintf(stderr,
                L"uninstall: SCM still rejects (%lu) — DACL is cached in memory.\n"
                L"  Reboot, then re-run `winternal uninstall`.\n", ::GetLastError());
        }
    }
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
    } else if (::GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST &&
               ::GetLastError() != ERROR_ACCESS_DENIED) {
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

        // ---- NTFS filter end-to-end test ----
        // Create a temp file, install a DENY rule for its full NT path,
        // assert CreateFile fails with ACCESS_DENIED, remove the rule,
        // assert CreateFile succeeds, and clean up. Exercises the live
        // NtCreateFile hook all the way through the path-match logic.
        {
            wchar_t tmpDir[MAX_PATH];
            ::GetTempPathW(MAX_PATH, tmpDir);
            wchar_t tmpFile[MAX_PATH];
            UINT n = ::GetTempFileNameW(tmpDir, L"wst", 0, tmpFile);
            if (!n) return fail(L"NTFS_FILTER setup", "GetTempFileName failed");

            // Make sure the file is closed so re-opening is what the test
            // measures (GetTempFileName creates an empty file already).
            // Pattern: `*<basename>`. The minifilter sees the normalized
            // path `\Device\HarddiskVolumeN\Users\…\wstXXXX.tmp`, and `*`
            // greedy-consumes everything before the literal basename.
            // We deliberately don't insert `\` after `*` — FsRtlIsName-
            // InExpression's `*` behavior across path separators is
            // finicky; `*<basename>` is the portable form.
            std::wstring base = std::wstring(L"*") +
                                std::filesystem::path(tmpFile).filename().wstring();

            auto id = ds.ntfsFilterAdd(base, DriverSession::FilterAction::Deny);
            if (!id) return fail(L"NTFS_FILTER_ADD", "could not install rule");

            HANDLE h = ::CreateFileW(tmpFile, GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD blockedErr = (h == INVALID_HANDLE_VALUE) ? ::GetLastError() : 0;
            if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
            if (blockedErr != ERROR_ACCESS_DENIED) {
                ds.ntfsFilterRemove(*id);
                ::DeleteFileW(tmpFile);
                wchar_t why[160];
                swprintf_s(why, L"open of %ls with DENY rule live; err=%lu (expected 5)",
                           tmpFile, blockedErr);
                ::SetLastError(blockedErr);
                char whyA[160];
                size_t n2 = 0; wcstombs_s(&n2, whyA, why, _TRUNCATE);
                return fail(L"NTFS_FILTER block path", whyA);
            }
            wprintf(L"  [ok ] NTFS_FILTER rule %u blocks CreateFile (err 5)\n", *id);

            // Remove the rule and confirm CreateFile works again.
            if (!ds.ntfsFilterRemove(*id))
                return fail(L"NTFS_FILTER_REMOVE", "could not remove rule");

            h = ::CreateFileW(tmpFile, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                DWORD postErr = ::GetLastError();
                ::DeleteFileW(tmpFile);
                ::SetLastError(postErr);
                return fail(L"NTFS_FILTER passthrough", "open still failed after remove");
            }
            ::CloseHandle(h);
            wprintf(L"  [ok ] NTFS_FILTER_REMOVE restores access\n");

            // Final list assertion — rule list should be empty (we just
            // removed our one rule, no others were present).
            auto rules = ds.ntfsFilterList();
            if (!rules.empty())
                fwprintf(stderr, L"  [warn] NTFS_FILTER_LIST: %zu leftover rules\n", rules.size());
            else
                wprintf(L"  [ok ] NTFS_FILTER_LIST is empty post-cleanup\n");

            ::DeleteFileW(tmpFile);
        }
    }

    wprintf(L"\nselftest: all checks passed.\n");
    return 0;
}

// Set the service-object DACL via SDDL. On engage we restrict everyone
// except SYSTEM to read-only — `sc stop` / `sc delete` from a different
// elevated admin gets ACCESS_DENIED. The owning CLI can still disengage
// because the SELFPROTECT_SET IOCTL is gated on caller-PID, not SCM ACL.
static bool SetServiceSddl(const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { ::LocalFree(sd); return false; }
    SC_HANDLE svc = ::OpenServiceW(scm, kServiceName,
                                   READ_CONTROL | WRITE_DAC | SERVICE_QUERY_CONFIG);
    if (!svc) {
        ::CloseServiceHandle(scm); ::LocalFree(sd); return false;
    }
    bool ok = ::SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd) != FALSE;
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);
    ::LocalFree(sd);
    return ok;
}

// SDDL strings: SY = SYSTEM, BA = Builtin Admins, AU = Authenticated Users.
// Mask chars for services: CC=QueryConfig LC=QueryStatus SW=EnumDeps LO=Interrogate
//                          CR=UserCtl RC=ReadControl RP=Start WP=Stop DT=PauseCont DC=Delete.
constexpr const wchar_t* kSddlPermissive =
    L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;AU)";
constexpr const wchar_t* kSddlRestricted =
    L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)";

// Self-protect leftover recovery — if a previous CLI invocation engaged
// selfprotect and then exited without disengaging, the service DACL is
// locked so admin can't `OpenService` for stop/delete (ACCESS_DENIED)
// and `CreateService` says ERROR_SERVICE_EXISTS. Recovery path: write
// a permissive DACL directly into the registry, then ask SCM to refresh.
// Registry writes are gated on standard regkey ACL (admin allowed) not
// on the service object's DACL, so they always succeed for admins.
static bool RecoverServiceRegistry() {
    HKEY hKey = nullptr;
    LONG rc = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Winternal", 0,
        KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return false;
    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sdLen = 0;
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kSddlPermissive, SDDL_REVISION_1, &sd, &sdLen)) {
        ::RegSetValueExW(hKey, L"Security", 0, REG_BINARY,
                         (const BYTE*)sd, sdLen);
        ::LocalFree(sd);
    } else {
        // Fall back to removing the Security value entirely — SCM will
        // default the DACL on next access.
        ::RegDeleteValueW(hKey, L"Security");
    }
    ::RegCloseKey(hKey);
    return true;
}

// Stand-alone recovery — for when the driver is gone, the service is
// stuck with a locked DACL, and you can't even run `winternal selfprotect
// off`. Writes a permissive DACL directly to the service's registry
// `Security` value. Requires admin + a reboot to take effect, since SCM
// only re-reads service ACLs across boots.
int CmdRecover() {
    if (!IsAdmin()) {
        fwprintf(stderr, L"recover: requires an elevated prompt.\n");
        return 1;
    }
    if (RecoverServiceRegistry()) {
        wprintf(L"recover: permissive DACL written to "
                L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winternal\\Security.\n"
                L"Reboot for SCM to pick it up. After reboot:\n"
                L"  winternal install      # to bring the driver back\n"
                L"  winternal uninstall    # to remove the service entirely\n");
        return 0;
    }
    fwprintf(stderr,
        L"recover: could not write to the service registry key.\n"
        L"  Verify the service entry exists:\n"
        L"    reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winternal\n");
    return 1;
}

int CmdSelfProtect(int argc, wchar_t** argv) {
    DriverSession ds;
    if (!ds.open()) {
        fwprintf(stderr, L"selfprotect: Winternal.sys not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    std::wstring_view sub = (argc < 1) ? std::wstring_view(L"status") : std::wstring_view(argv[0]);

    if (sub == L"status") {
        auto st = ds.selfProtectStatus();
        if (!st) { fwprintf(stderr, L"selfprotect: status IOCTL failed (%lu)\n", ::GetLastError()); return 1; }
        wprintf(L"selfprotect: %ls\n", st->engaged ? L"ENGAGED" : L"off");
        if (st->engaged) wprintf(L"owner PID:   %u\n", st->ownerPid);
        return 0;
    }
    if (sub == L"on") {
        DWORD me = ::GetCurrentProcessId();
        if (!ds.selfProtectSet(true, me)) {
            fwprintf(stderr, L"selfprotect on: IOCTL failed (%lu)\n", ::GetLastError());
            return 1;
        }
        if (!SetServiceSddl(kSddlRestricted))
            fwprintf(stderr, L"selfprotect on: service DACL not tightened (%lu) — driver protection still active.\n",
                     ::GetLastError());
        wprintf(L"selfprotect: ENGAGED. Driver + service are now locked down.\n");
        wprintf(L"  * SCM:    sc stop / sc delete from any non-SYSTEM caller -> ACCESS_DENIED\n");
        wprintf(L"  * Driver: weaken-protection IOCTLs (force-unload Winternal, protect-unlock\n");
        wprintf(L"            of owner, selfprotect-off) require the caller image's SHA-256 to\n");
        wprintf(L"            match this binary's SHA-256. Future invocations of THIS Winternal.exe\n");
        wprintf(L"            can disengage; nothing else can.\n");
        wprintf(L"  * CLI:    per-process OpenProcess filtering is NOT applied — this CLI is\n");
        wprintf(L"            one-shot and would only briefly cover itself anyway. For an\n");
        wprintf(L"            interactive session you want filtered, run:\n");
        wprintf(L"              winternal proc lock <pid> --force\n");
        wprintf(L"            from inside (or before) that session.\n");
        wprintf(L"To disengage: `winternal selfprotect off` from the same Winternal.exe. If you\n");
        wprintf(L"forget and the service becomes unreachable: `winternal recover` + reboot.\n");
        return 0;
    }
    if (sub == L"off") {
        if (!ds.selfProtectSet(false, 0)) {
            fwprintf(stderr, L"selfprotect off: IOCTL failed (%lu)\n", ::GetLastError());
            return 1;
        }
        // Driver-side gate is cleared. Now restore the SCM DACL. If SCM
        // refuses (the DACL was locked by a previous session and SCM has
        // it cached in memory), fall through to a direct registry write —
        // that survives a reboot, after which SCM picks up the permissive
        // DACL on next boot.
        if (!SetServiceSddl(kSddlPermissive)) {
            DWORD e = ::GetLastError();
            if (e == ERROR_ACCESS_DENIED && RecoverServiceRegistry()) {
                wprintf(L"selfprotect off: SCM ACL was cached-locked; wrote permissive DACL to "
                        L"registry. SCM will pick it up after a reboot. Driver-side gate is cleared "
                        L"now (\\\\.\\Winternal IOCTLs work).\n");
            } else {
                fwprintf(stderr, L"selfprotect off: service DACL not restored (%lu)\n", e);
            }
        }
        wprintf(L"selfprotect: off\n");
        return 0;
    }
    fwprintf(stderr,
             L"selfprotect: unknown subcommand '%ls'\n"
             L"usage: winternal selfprotect [on|off|status]\n", argv[0]);
    return 1;
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
int RunSelfProtect(int argc, wchar_t** argv){ return CmdSelfProtect(argc, argv); }
int RunRecover()                            { return CmdRecover(); }
}
