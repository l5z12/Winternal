// WinternalCLI - command-line front-end for WinternalCore.
//
// Usage:
//   winternal <command> [args]
//
// Commands:
//   ps                    list processes
//   ps --hidden           list processes + brute-force hidden PIDs
//   ps <pid>              detail one process (modules, command line)
//   dlls <pid>            list loaded modules for a process
//   drivers               list loaded kernel modules
//   svc                   list services
//   svc <name>            detail / startup type for a service
//   net                   list TCP+UDP connections (v4 + v6)
//   handles [--pid N]     list handles (optionally filtered)
//   obj <path>            list NT object directory entries
//   hooks <pid>           IAT hook scan for a process
//   hooks <pid> --inline  also do inline byte compare (slow)
//   kill <pid>            terminate a process
//   suspend <pid>         suspend a process
//   resume <pid>          resume a process
//   close <pid> <h>       force-close a handle in another process
//   kpids                 ask the Winternal kernel driver for its PID list and
//                         compare with the user-mode list (DKOM detection)
//   kver                  show Winternal driver version
//   help                  show this help
//
// Most read-only commands work without elevation. Process/handle inspection
// against system services and reading PEBs requires Administrator + the
// SeDebugPrivilege we attempt to enable on startup.

#include "WinternalCore.h"
#include "../Winternal/Public.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <cwctype>
#include <atomic>
#include <functional>
// PSAPI_VERSION 1 keeps unprefixed function names (EnumProcesses,
// GetMappedFileNameW, ...). Default v2 macro-renames them to K32* which
// then collides with winternal::EnumProcesses elsewhere in this file.
#define PSAPI_VERSION 1
#include <psapi.h>     // GetMappedFileNameW
#include <sddl.h>      // ConvertSidToStringSidW
#include "WClap.h"

using namespace winternal;

namespace winternal {
int RunInstall(int argc, wchar_t** argv);
int RunUninstall();
int RunStatus();
int RunSelftest();
int RunDriverMgmt(int argc, wchar_t** argv);
int RunNtfsCommand(int argc, wchar_t** argv);
namespace plugins { int RunPluginCommand(int argc, wchar_t** argv); }
}

namespace {

// Console output. We keep all our format strings as wide (wprintf), but route
// the bytes that hit stdout/stderr through UTF-8 so they render correctly in
// modern Windows consoles and stay sensible when piped.
void InitOutput() {
    ::SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
}

void PrintHelp() {
    auto cmd = [](const wchar_t* name, const wchar_t* display, const wchar_t* about) {
        return wclap::App(name).display(display).about(about);
    };
    auto under = [](const wchar_t* name, const wchar_t* display, const wchar_t* about,
                    const wchar_t* heading) {
        return wclap::App(name).display(display).about(about).help_heading(heading);
    };
    const wchar_t* H_DRV  = L"Kernel driver (requires admin + loaded Winternal.sys)";
    const wchar_t* H_NTFS = L"NTFS monitoring + analyzing";
    const wchar_t* H_SVC  = L"Service management (admin)";
    const wchar_t* H_PLUG = L"Plugins";
    const wchar_t* H_DMGT = L"Driver management (admin)";

    wclap::App app(L"winternal");
    app.about(L"winternal - Windows kernel-aware ARK toolkit");

    // Default group: core process / inspection.
    app.subcommand(cmd(L"ps",      L"ps [--hidden] [<pid>]",                 L"list processes (or detail one)"));
    app.subcommand(cmd(L"dlls",    L"dlls <pid>",                            L"list loaded modules in a process"));
    app.subcommand(cmd(L"drivers", L"drivers",                               L"list loaded kernel modules"));
    app.subcommand(cmd(L"svc",     L"svc [<name>]",                          L"list services"));
    app.subcommand(cmd(L"net",     L"net",                                   L"list TCP/UDP endpoints"));
    app.subcommand(cmd(L"handles", L"handles [--pid N]",                     L"list open handles"));
    app.subcommand(cmd(L"obj",     L"obj <path>",                            L"list NT object directory entries"));
    app.subcommand(cmd(L"hooks",   L"hooks <pid> [--inline]",                L"scan IAT (and optionally inline) hooks"));
    app.subcommand(cmd(L"kill",    L"kill <pid>",                            L"terminate a process"));
    app.subcommand(cmd(L"suspend", L"suspend <pid> | resume <pid>",          L"suspend/resume a process"));
    app.subcommand(cmd(L"close",   L"close <pid> <handle>",                  L"force-close a remote handle"));

    // Kernel-driver group.
    app.subcommand(under(L"kver",      L"kver",                          L"show driver version",                   H_DRV));
    app.subcommand(under(L"kpids",     L"kpids",                         L"kernel-side PID enum (DKOM detection)", H_DRV));
    app.subcommand(under(L"kr",        L"kr <addr> <len>",               L"read kernel memory (hexdump)",          H_DRV));
    app.subcommand(under(L"kw",        L"kw <addr> <hex>",               L"write kernel memory",                   H_DRV));
    app.subcommand(under(L"ksym",      L"ksym <name>",                   L"look up an ntoskrnl export address",    H_DRV));
    app.subcommand(under(L"kalloc",    L"kalloc <size> [paged|nonpaged]",L"allocate pool, print address",          H_DRV));
    app.subcommand(under(L"kfree",     L"kfree <addr>",                  L"free pool allocated by kalloc",         H_DRV));
    app.subcommand(under(L"kcall",     L"kcall <addr> [a1..a4]",         L"call a kernel routine with up to 4 args", H_DRV));
    app.subcommand(under(L"unprotect", L"unprotect <pid> [val] [off]",   L"clear EPROCESS->Protection (and Ob lock) on a PID", H_DRV));
    app.subcommand(under(L"protect",   L"protect <pid> [--level N] [--force]",
                                       L"set Protection (default 0x72); --force adds Ob lockdown", H_DRV));
    app.subcommand(under(L"protect-list", L"protect --list",             L"list force-protected PIDs",             H_DRV));
    app.subcommand(under(L"kkill",     L"kkill <pid|name> [--glob] [--all] [--tree|-t] [--dry-run] [--exit-code N]",
                                       L"terminate via the driver (PPL/PP-safe); see `kkill` with no args", H_DRV));
    app.subcommand(under(L"ghost",     L"ghost [--kill <pid>] [--kill-all] [--yes|-y]",
                                       L"list/kill processes the system is hiding (DKOM / zombie / image-deleted)", H_DRV));
    app.subcommand(under(L"tree",      L"tree",                          L"ASCII process tree (parent/child hierarchy)", H_DRV));
    app.subcommand(under(L"threads",   L"threads <pid>",                 L"list a process's threads (TID, start addr, state, wait reason)", H_DRV));
    app.subcommand(under(L"mem",       L"mem <pid> [--commit] [--exec]", L"VirtualQuery walk: regions, prot, type, mapped module", H_DRV));
    app.subcommand(under(L"token",     L"token <pid>",                   L"integrity level, elevation, UIAccess, privileges, user SID", H_DRV));
    app.subcommand(under(L"mitigations", L"mitigations <pid>",           L"DEP / ASLR / CFG / shadow-stack / signing policies", H_DRV));
    app.subcommand(under(L"win",       L"win <list|info|close|kill|hide|show|front|topmost|move> [args]",
                                       L"HWND utilities; run `winternal win` for subcommand help", H_DRV));
    app.subcommand(under(L"callbacks", L"callbacks [process|image|thread]", L"enumerate kernel notify-routine arrays", H_DRV));
    app.subcommand(under(L"kdrivers",  L"kdrivers",                      L"enumerate loaded kernel modules via the driver", H_DRV));
    app.subcommand(under(L"ssdt",      L"ssdt",                          L"enumerate KeServiceDescriptorTable entries", H_DRV));
    app.subcommand(under(L"lua",       L"lua [script | -e expr]",        L"run a Lua script in the wn binding (REPL if no arg)", H_DRV));

    // NTFS group.
    app.subcommand(under(L"ntfs-vols",    L"ntfs vols",                          L"list NTFS volumes + metadata", H_NTFS));
    app.subcommand(under(L"ntfs-usn",     L"ntfs usn <vol> [--count N] [--start U] [--tail]",
                                          L"USN journal snapshot or live tail (rootkit-resistant)", H_NTFS));
    app.subcommand(under(L"ntfs-mft",     L"ntfs mft <vol> [--limit N] [--name SUBSTR]",
                                          L"MFT walk via FSCTL_ENUM_USN_DATA (bypasses UM dir hooks)", H_NTFS));
    app.subcommand(under(L"ntfs-streams", L"ntfs streams <path>",                 L"list alternate data streams (ADS)", H_NTFS));
    app.subcommand(under(L"ntfs-compare", L"ntfs compare <path>",                 L"FindFirstFile vs MFT diff (hide detection)", H_NTFS));
    app.subcommand(under(L"ntfs-raw",     L"ntfs raw <device> <off> <len>",       L"driver-backed raw device read (bypasses minifilters)", H_NTFS));

    // Service management.
    app.subcommand(under(L"install",   L"install [--path SYS] [--no-start]", L"copy + register Winternal.sys (starts by default)", H_SVC));
    app.subcommand(under(L"uninstall", L"uninstall",                     L"stop + delete service, remove file", H_SVC));
    app.subcommand(under(L"status",    L"status",                        L"service state, signing, driver online?", H_SVC));
    app.subcommand(under(L"selftest",  L"selftest",                      L"end-to-end verification of every IOCTL", H_SVC));

    // Plugins.
    app.subcommand(under(L"plugin-list",    L"plugin list",              L"enumerate manifested plugins", H_PLUG));
    app.subcommand(under(L"plugin-info",    L"plugin info <name>",       L"dump a plugin's manifest", H_PLUG));
    app.subcommand(under(L"plugin-enable",  L"plugin enable | disable <name>", L"persist enable state", H_PLUG));
    app.subcommand(under(L"plugin-run",     L"plugin run <name> [args...]",
                                            L"execute one-shot; trailing args land in the plugin's `arg` table",
                                            H_PLUG));

    // Driver management.
    app.subcommand(under(L"drv-list",   L"drv list",                     L"list kernel-mode services", H_DMGT));
    app.subcommand(under(L"drv-load",   L"drv load <name> <sys-path>",   L"create + start a kernel service", H_DMGT));
    app.subcommand(under(L"drv-start",  L"drv start | stop <name>",      L"SCM start/stop", H_DMGT));
    app.subcommand(under(L"drv-enable", L"drv enable | disable <name>",  L"set StartType", H_DMGT));
    app.subcommand(under(L"drv-delete", L"drv delete <name>",            L"DeleteService", H_DMGT));
    app.subcommand(under(L"drv-unload", L"drv unload <name>",            L"force unload via Winternal.sys", H_DMGT));

    // Trailing meta — back in the default group.
    app.subcommand(cmd(L"help",        L"help",                          L"show this help"));

    app.print_help(stdout);
}

// Ctrl+C / Ctrl+Break handling.
//
// We hold a duplicated handle to the main thread so the console-control
// thread (spawned by kernel32 to deliver CTRL_*_EVENT) can call
// CancelSynchronousIo against the main thread. That makes any wedged
// DeviceIoControl return STATUS_CANCELLED, unwinds scope, runs RAII
// destructors so scoped patches (UIAccess, sig-level, code patches) get
// restored before the process exits.
//
// First Ctrl+C: graceful — print, mark aborted, cancel synchronous I/O,
//               return TRUE so default handler doesn't kill us yet.
// Second Ctrl+C: hard — return FALSE, default handler ExitProcess.
static HANDLE g_mainThread = nullptr;
static std::atomic<int>  g_ctrlCount{0};
static std::atomic<bool> g_aborted{false};

static bool Aborted() { return g_aborted.load(std::memory_order_acquire); }

static BOOL WINAPI WinternalCtrlHandler(DWORD ctrlType) {
    if (ctrlType != CTRL_C_EVENT &&
        ctrlType != CTRL_BREAK_EVENT &&
        ctrlType != CTRL_CLOSE_EVENT) return FALSE;
    int n = g_ctrlCount.fetch_add(1) + 1;
    if (n == 1 && ctrlType != CTRL_CLOSE_EVENT) {
        g_aborted.store(true, std::memory_order_release);
        fwprintf(stderr, L"\n^C aborting (press again to force-exit)\n");
        fflush(stderr);
        if (g_mainThread) ::CancelSynchronousIo(g_mainThread);
        return TRUE;
    }
    fwprintf(stderr, L"\n^C force-exiting\n");
    fflush(stderr);
    return FALSE;
}

// --debug mirrors what each major step is doing to stderr. The flag is
// filtered out of argv in wmain before commands parse their own args, so
// individual subcommands don't have to know about it. Output is fflush'd
// per line so the last line before a hang is actually visible.
static bool g_debug = false;
static void Dbg(const wchar_t* fmt, ...) {
    if (!g_debug) return;
    va_list ap;
    va_start(ap, fmt);
    fwprintf(stderr, L"[dbg] ");
    vfwprintf(stderr, fmt, ap);
    va_end(ap);
    fputwc(L'\n', stderr);
    fflush(stderr);
}

uint32_t ParseUint(std::wstring_view s) {
    if (s.starts_with(L"0x") || s.starts_with(L"0X")) {
        return (uint32_t)wcstoul(s.data() + 2, nullptr, 16);
    }
    return (uint32_t)wcstoul(std::wstring(s).c_str(), nullptr, 10);
}

void CmdPs(int argc, wchar_t** argv) {
    bool wantHidden = false;
    uint32_t detail = 0;
    for (int i = 0; i < argc; ++i) {
        if (wcscmp(argv[i], L"--hidden") == 0) wantHidden = true;
        else detail = ParseUint(argv[i]);
    }

    auto procs = EnumProcesses();

    if (detail) {
        for (auto& p : procs) if (p.pid == detail) {
            EnrichProcess(p);
            wprintf(L"PID:           %u\n", p.pid);
            wprintf(L"PPID:          %u\n", p.parentPid);
            wprintf(L"Image:         %s\n", p.imageName.c_str());
            wprintf(L"Path:          %s\n", p.imagePath.c_str());
            wprintf(L"User:          %s%s\n", p.user.c_str(), p.elevated ? L" (elevated)" : L"");
            wprintf(L"Integrity:     %s\n", p.integrityLevel.c_str());
            wprintf(L"Wow64:         %s\n", p.wow64 ? L"yes" : L"no");
            wprintf(L"Session:       %u\n", p.sessionId);
            wprintf(L"Threads:       %u   Handles: %u\n", p.threadCount, p.handleCount);
            wprintf(L"Working set:   %llu\n", (unsigned long long)p.workingSet);
            wprintf(L"Private bytes: %llu\n", (unsigned long long)p.privateBytes);
            wprintf(L"Command line:  %s\n", p.commandLine.c_str());
            return;
        }
        fwprintf(stderr, L"No process with PID %u\n", detail);
        return;
    }

    std::sort(procs.begin(), procs.end(),
              [](auto& a, auto& b){ return a.pid < b.pid; });

    wprintf(L"%-7s %-7s %-7s %-9s %-12s %s\n", L"PID", L"PPID", L"Sess", L"Threads", L"WSet(MB)", L"Image");
    for (auto& p : procs) {
        wprintf(L"%7u %7u %7u %9u %12.1f %s\n",
                p.pid, p.parentPid, p.sessionId, p.threadCount,
                p.workingSet / (1024.0 * 1024.0),
                p.imageName.c_str());
    }
    if (wantHidden) {
        auto hidden = DetectHiddenPids(procs);
        if (hidden.empty()) {
            wprintf(L"\nHidden PIDs: none detected.\n");
        } else {
            wprintf(L"\nHidden PIDs (openable but not in SystemProcessInformation):\n");
            for (auto pid : hidden) wprintf(L"  %u\n", pid);
        }
    }
}

void CmdDlls(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"dlls: missing PID\n"); return; }
    uint32_t pid = ParseUint(argv[0]);
    auto mods = EnumProcessModules(pid);
    if (mods.empty()) { fwprintf(stderr, L"No modules (insufficient access? PID exited?)\n"); return; }
    wprintf(L"%-18s %-10s %-6s %s\n", L"Base", L"Size(KB)", L"Disk", L"Path");
    for (auto& m : mods) {
        wprintf(L"0x%016llx %10u %-6s %s\n",
                (unsigned long long)m.baseAddress, m.size / 1024,
                m.fileMissing ? L"MISS" : L"ok",
                m.path.empty() ? m.name.c_str() : m.path.c_str());
    }
}

void CmdDrivers() {
    auto mods = EnumKernelModules();
    if (mods.empty()) {
        fwprintf(stderr, L"Failed to enumerate kernel modules (need elevation/SeDebugPrivilege)\n");
        return;
    }
    wprintf(L"%-3s %-18s %-10s %-6s %s\n", L"#", L"Base", L"Size(KB)", L"Disk", L"Path");
    int i = 0;
    for (auto& m : mods) {
        wprintf(L"%3d 0x%016llx %10u %-6s %s\n",
                i++, (unsigned long long)m.imageBase, m.imageSize / 1024,
                m.fileMissing ? L"MISS" : L"ok",
                m.path.c_str());
    }
}

void CmdSvc(int argc, wchar_t** argv) {
    auto svcs = EnumServices();
    if (argc >= 1) {
        std::wstring needle = argv[0];
        for (auto& s : svcs) if (_wcsicmp(s.name.c_str(), needle.c_str()) == 0) {
            wprintf(L"Name:         %s\n", s.name.c_str());
            wprintf(L"DisplayName:  %s\n", s.displayName.c_str());
            wprintf(L"Description:  %s\n", s.description.c_str());
            wprintf(L"BinPath:      %s\n", s.binPath.c_str());
            wprintf(L"Account:      %s\n", s.account.c_str());
            wprintf(L"State:        %u  Pid:%u  Type:%u  Start:%u  Kernel:%s\n",
                    (uint32_t)s.state, s.pid, (uint32_t)s.type, (uint32_t)s.startType,
                    s.kernel ? L"yes" : L"no");
            return;
        }
        fwprintf(stderr, L"Service not found: %s\n", needle.c_str());
        return;
    }
    std::sort(svcs.begin(), svcs.end(), [](auto& a, auto& b){ return a.name < b.name; });
    wprintf(L"%-32s %-10s %-7s %-7s %s\n", L"Name", L"State", L"PID", L"Type", L"DisplayName");
    for (auto& s : svcs) {
        const wchar_t* state =
            (s.state == SvcState::Running)  ? L"running"  :
            (s.state == SvcState::Stopped)  ? L"stopped"  :
            (s.state == SvcState::StartPending) ? L"start.." :
            (s.state == SvcState::StopPending)  ? L"stop.."  : L"?";
        const wchar_t* type = s.kernel ? L"kernel" : L"user";
        wprintf(L"%-32s %-10s %7u %-7s %s\n",
                s.name.c_str(), state, s.pid, type, s.displayName.c_str());
    }
}

void CmdNet() {
    auto cs = EnumConnections();
    auto procs = EnumProcesses();
    auto pidName = [&](uint32_t pid) -> std::wstring {
        for (auto& p : procs) if (p.pid == pid) return p.imageName;
        return L"";
    };
    wprintf(L"%-5s %-22s %-22s %-12s %-7s %s\n",
            L"Proto", L"Local", L"Remote", L"State", L"PID", L"Process");
    for (auto& c : cs) {
        const wchar_t* proto =
            c.proto == L4Proto::Tcp4 ? L"TCP4" :
            c.proto == L4Proto::Tcp6 ? L"TCP6" :
            c.proto == L4Proto::Udp4 ? L"UDP4" : L"UDP6";
        wprintf(L"%-5s %-22s %-22s %-12s %7u %s\n",
                proto, c.local.c_str(), c.remote.c_str(),
                c.stateName.empty() ? L"-" : c.stateName.c_str(),
                c.pid, pidName(c.pid).c_str());
    }
}

void CmdHandles(int argc, wchar_t** argv) {
    uint32_t pid = 0;
    for (int i = 0; i < argc; ++i) {
        if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) pid = ParseUint(argv[++i]);
    }
    auto hs = EnumHandles(true);
    wprintf(L"%-7s %-10s %-20s %-20s %s\n", L"PID", L"Handle", L"Type", L"Access", L"Name");
    for (auto& h : hs) {
        if (pid && h.pid != pid) continue;
        wchar_t access[20];
        swprintf_s(access, L"0x%08x", h.grantedAccess);
        wprintf(L"%7u 0x%-8x %-20s %-20s %s\n",
                h.pid, h.handleValue, h.typeName.c_str(), access, h.name.c_str());
    }
}

void CmdObj(int argc, wchar_t** argv) {
    std::wstring path = argc >= 1 ? argv[0] : L"\\";
    auto entries = ListObjectDir(path);
    if (entries.empty()) { fwprintf(stderr, L"No entries (or access denied) at %s\n", path.c_str()); return; }
    wprintf(L"%-24s %s\n", L"Type", L"Name");
    for (auto& e : entries) {
        wprintf(L"%-24s %s\n", e.type.c_str(), e.name.c_str());
    }
}

void CmdHooks(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"hooks: missing PID\n"); return; }
    uint32_t pid = ParseUint(argv[0]);
    bool inl = false;
    for (int i = 1; i < argc; ++i) if (wcscmp(argv[i], L"--inline") == 0) inl = true;

    auto iat = ScanIatHooks(pid);
    wprintf(L"-- IAT hooks: %zu --\n", iat.size());
    for (auto& h : iat) {
        wprintf(L"  %s!%s -> 0x%016llx (expected 0x%016llx, in %s)\n",
                h.victimModule.c_str(), h.victimFunction.c_str(),
                (unsigned long long)h.actualAddress,
                (unsigned long long)h.expectedAddress,
                h.resolvedModule.empty() ? L"<unknown>" : h.resolvedModule.c_str());
    }
    if (inl) {
        wprintf(L"\nScanning inline patches (slow)...\n");
        auto il = ScanInlineHooks(pid, 32);
        wprintf(L"-- Inline hooks: %zu --\n", il.size());
        for (auto& h : il) {
            wprintf(L"  %s!%s @ 0x%016llx differs from on-disk image\n",
                    h.victimModule.c_str(), h.victimFunction.c_str(),
                    (unsigned long long)h.actualAddress);
        }
    }
}

int CmdKill(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"kill: missing PID\n"); return 1; }
    uint32_t pid = ParseUint(argv[0]);
    if (TerminateProcessById(pid)) { wprintf(L"Terminated %u\n", pid); return 0; }
    fwprintf(stderr, L"Failed to terminate %u: %S\n", pid, FormatError(GetLastError()).c_str());
    return 1;
}

int CmdSuspend(int argc, wchar_t** argv, bool resume) {
    if (argc < 1) { fwprintf(stderr, L"%s: missing PID\n", resume ? L"resume" : L"suspend"); return 1; }
    uint32_t pid = ParseUint(argv[0]);
    bool ok = resume ? ResumeProcessById(pid) : SuspendProcessById(pid);
    if (ok) { wprintf(L"%s %u\n", resume ? L"Resumed" : L"Suspended", pid); return 0; }
    fwprintf(stderr, L"Failed (%u): %S\n", GetLastError(), FormatError(GetLastError()).c_str());
    return 1;
}

// Open the Winternal driver session, or print a setup hint and return false.
bool OpenDriverOrHint(DriverSession& s) {
    if (s.open()) return true;
    DWORD e = ::GetLastError();
    if (e == ERROR_FILE_NOT_FOUND) {
        fwprintf(stderr,
                 L"The Winternal driver is not loaded. To load it (test-signing + admin required):\n"
                 L"  bcdedit /set testsigning on  (then reboot)\n"
                 L"  sc create Winternal type= kernel binPath= <full-path>\\Winternal.sys\n"
                 L"  sc start Winternal\n");
    } else {
        fwprintf(stderr, L"Cannot open %s (%lu)\n", WINTERNAL_USER_OPEN_PATH, e);
    }
    return false;
}

int CmdKver() {
    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    auto v = s.getVersion();
    if (!v) { fwprintf(stderr, L"GET_VERSION failed: %lu\n", ::GetLastError()); return 1; }
    wprintf(L"Winternal driver version: %u.%u\n", v->major, v->minor);
    return 0;
}

int CmdKpids() {
    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    auto kernelPids = s.enumPids();
    wprintf(L"Driver enumerated %zu processes.\n", kernelPids.size());

    auto userVisible = EnumProcesses();
    std::unordered_set<uint32_t> visible;
    for (auto& p : userVisible) visible.insert(p.pid);

    int hidden = 0;
    for (auto& e : kernelPids) {
        if (!visible.contains(e.pid)) {
            wprintf(L"  HIDDEN: PID %u (%S) parent=%u\n", e.pid, e.imageName.c_str(), e.parentPid);
            ++hidden;
        }
    }
    if (hidden == 0) wprintf(L"No DKOM-style hidden processes detected.\n");
    return 0;
}

// Parse 0x... or decimal into 64-bit.
uint64_t ParseU64(std::wstring_view s) {
    if (s.starts_with(L"0x") || s.starts_with(L"0X")) return _wcstoui64(s.data() + 2, nullptr, 16);
    return _wcstoui64(std::wstring(s).c_str(), nullptr, 10);
}

// Hexdump: 16 bytes per row, ASCII gutter.
void HexDump(uint64_t base, const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        wprintf(L"%016llx  ", (unsigned long long)(base + i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) wprintf(L"%02x ", data[i + j]); else wprintf(L"   ");
        }
        wprintf(L" |");
        for (size_t j = 0; j < 16 && i + j < n; ++j) {
            uint8_t c = data[i + j];
            wprintf(L"%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        wprintf(L"|\n");
    }
}

// Parse a hex string like "deadbeef" or "de ad be ef" into a byte vector.
std::vector<uint8_t> ParseHexBytes(std::wstring_view s) {
    std::vector<uint8_t> out;
    auto hex = [](wchar_t c) -> int {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
        if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
        return -1;
    };
    int hi = -1;
    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t') continue;
        int v = hex(c);
        if (v < 0) return {};
        if (hi < 0) hi = v;
        else { out.push_back((uint8_t)((hi << 4) | v)); hi = -1; }
    }
    return out;
}

int CmdKread(int argc, wchar_t** argv) {
    if (argc < 2) { fwprintf(stderr, L"kr: kr <addr> <len>\n"); return 1; }
    uint64_t addr = ParseU64(argv[0]);
    uint32_t len = (uint32_t)ParseU64(argv[1]);
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto data = s.kread(addr, len);
    if (!data) { fwprintf(stderr, L"kread failed: %lu\n", ::GetLastError()); return 1; }
    HexDump(addr, data->data(), data->size());
    return 0;
}

int CmdKwrite(int argc, wchar_t** argv) {
    if (argc < 2) { fwprintf(stderr, L"kw: kw <addr> <hex-bytes>\n"); return 1; }
    uint64_t addr = ParseU64(argv[0]);
    auto bytes = ParseHexBytes(argv[1]);
    if (bytes.empty()) { fwprintf(stderr, L"kw: invalid hex string\n"); return 1; }
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    if (!s.kwrite(addr, bytes.data(), (uint32_t)bytes.size())) {
        fwprintf(stderr, L"kwrite failed: %lu\n", ::GetLastError()); return 1;
    }
    wprintf(L"Wrote %zu bytes at 0x%016llx\n", bytes.size(), (unsigned long long)addr);
    return 0;
}

int CmdKsym(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"ksym: ksym <name>\n"); return 1; }
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto a = s.ksym(argv[0]);
    if (!a) { fwprintf(stderr, L"ksym %s: not found\n", argv[0]); return 1; }
    wprintf(L"%s = 0x%016llx\n", argv[0], (unsigned long long)*a);
    return 0;
}

int CmdKalloc(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"kalloc: kalloc <size> [paged|nonpaged]\n"); return 1; }
    uint32_t sz = (uint32_t)ParseU64(argv[0]);
    bool np = true;
    if (argc >= 2 && wcscmp(argv[1], L"paged") == 0) np = false;
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto a = s.kalloc(sz, 0, np);
    if (!a) { fwprintf(stderr, L"kalloc failed: %lu\n", ::GetLastError()); return 1; }
    wprintf(L"0x%016llx\n", (unsigned long long)*a);
    return 0;
}

int CmdKfree(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"kfree: kfree <addr>\n"); return 1; }
    uint64_t a = ParseU64(argv[0]);
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    if (!s.kfree(a)) { fwprintf(stderr, L"kfree failed: %lu\n", ::GetLastError()); return 1; }
    return 0;
}

int CmdKcall(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"kcall: kcall <addr> [a1] [a2] [a3] [a4]\n"); return 1; }
    uint64_t addr = ParseU64(argv[0]);
    uint64_t a[4] = {0,0,0,0};
    for (int i = 1; i < argc && i <= 4; ++i) a[i-1] = ParseU64(argv[i]);
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto r = s.kcall(addr, a[0], a[1], a[2], a[3]);
    if (!r) { fwprintf(stderr, L"kcall failed: %lu\n", ::GetLastError()); return 1; }
    wprintf(L"ret=0x%016llx%s\n", (unsigned long long)r->returnValue, r->faulted ? L" (FAULTED)" : L"");
    return 0;
}

int CmdUnprotect(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"unprotect: unprotect <pid> [new-value] [offset]\n"); return 1; }
    uint32_t pid = (uint32_t)ParseU64(argv[0]);
    uint8_t newVal = 0;
    uint32_t off = 0;
    if (argc >= 2) newVal = (uint8_t)ParseU64(argv[1]);
    if (argc >= 3) off = (uint32_t)ParseU64(argv[2]);
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto r = s.unprotectProcess(pid, newVal, off);
    if (!r) { fwprintf(stderr, L"unprotect failed: %lu\n", ::GetLastError()); return 1; }
    // Also remove from Ob-callback lock list if `protect --force` had added it.
    // Errors ignored — the PID may simply not be locked.
    s.protectUnlock(pid);
    wprintf(L"pid=%u offset=0x%x prev=0x%02x -> 0x%02x  (Ob lock cleared if present)\n",
            pid, r->fieldOffsetUsed, r->prevValue, newVal);
    return 0;
}

// Forward decls for helpers that live alongside kkill below.
bool IsAllDigits(std::wstring_view s);
bool EqualsCI(std::wstring_view a, std::wstring_view b);
const ProcessInfo* FindByPid(const std::vector<ProcessInfo>& ps, uint32_t pid);

// protect ------------------------------------------------------------------
//
// `protect <pid>`              — set EPROCESS->Protection (PPL/PP); blocks
//                                 same-or-lower-protected user-mode callers.
// `protect <pid> --force`      — also register an Ob pre-op callback that
//                                 strips destructive + informational access
//                                 from EVERY new user-mode open of the PID,
//                                 and revokes existing destructive handles
//                                 other processes already hold.
// `protect <pid> --level N`    — override the Protection byte (default 0x72,
//                                 PsProtectedSignerWinTcb-Full).
// `protect --list`             — print currently force-protected PIDs.
//
// The default level (0x72) and the Ob strip mask are picked for maximum
// user-mode opacity; kernel-mode callers (including this driver) are
// unaffected so the protection can always be cleared with `unprotect`.

// Close every user-mode handle other processes already hold against the
// kernel object identified by `targetObject`. Identification is by kernel
// pointer so we don't accidentally close unrelated Process handles. Caller
// supplies a system-wide handle snapshot taken BEFORE the Ob lock went
// live, since with the lock on, fresh EnumHandles + OpenProcess on the
// target may be denied.
static uint32_t RevokeHandlesAgainstObject(uint64_t targetObject,
                                           const std::vector<HandleInfo>& snapshot) {
    constexpr uint32_t kDestructive =
        PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD |
        PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION;
    if (!targetObject) return 0;
    uint32_t selfPid = ::GetCurrentProcessId();
    uint32_t closed = 0;
    for (auto& h : snapshot) {
        if (h.pid == selfPid) continue;
        if (h.object != targetObject) continue;
        if ((h.grantedAccess & kDestructive) == 0) continue;
        if (CloseHandleInProcess(h.pid, h.handleValue)) ++closed;
    }
    return closed;
}

int CmdProtect(int argc, wchar_t** argv) {
    bool list = false;
    bool force = false;
    uint8_t level = 0x72;   // PsProtectedSignerWinTcb-Full
    std::wstring pidArg;

    for (int i = 0; i < argc; ++i) {
        std::wstring_view a = argv[i];
        if      (a == L"--list")  list = true;
        else if (a == L"--force") force = true;
        else if (a == L"--level" && i + 1 < argc) level = (uint8_t)ParseU64(argv[++i]);
        else if (!a.empty() && a[0] == L'-') {
            fwprintf(stderr, L"protect: unknown flag %s\n", argv[i]); return 1;
        }
        else if (pidArg.empty()) pidArg = argv[i];
        else { fwprintf(stderr, L"protect: only one <pid> allowed\n"); return 1; }
    }

    Dbg(L"protect: pid=%s level=0x%02x force=%d list=%d",
        pidArg.empty() ? L"(none)" : pidArg.c_str(), level, force, list);
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    Dbg(L"protect: driver session open");

    if (list) {
        auto pids = s.protectList();
        if (pids.empty()) { wprintf(L"protect: no PIDs currently force-locked\n"); return 0; }
        auto procs = EnumProcesses();
        wprintf(L"force-protected PIDs:\n");
        for (auto pid : pids) {
            auto* p = FindByPid(procs, pid);
            wprintf(L"  %6u  %s\n", pid, p ? p->imageName.c_str() : L"(dead)");
        }
        return 0;
    }

    if (pidArg.empty()) {
        fwprintf(stderr, L"protect <pid> [--level N] [--force]\n"
                         L"protect --list\n");
        return 1;
    }
    if (!IsAllDigits(pidArg)) { fwprintf(stderr, L"protect: <pid> must be numeric\n"); return 1; }
    uint32_t pid = (uint32_t)wcstoul(pidArg.c_str(), nullptr, 10);

    // Always set the EPROCESS->Protection byte first — it's the weakest form
    // but also the one that survives if the Ob callback registration fails.
    auto r = s.unprotectProcess(pid, level, 0);   // same IOCTL, non-zero NewValue
    if (!r) { fwprintf(stderr, L"protect: setProtection failed: %lu\n", ::GetLastError()); return 1; }
    wprintf(L"pid=%u  Protection: 0x%02x -> 0x%02x\n", pid, r->prevValue, level);

    if (force) {
        Dbg(L"protect --force: opening target pid=%u before lock", pid);
        HandleGuard self(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!self.valid()) {
            fwprintf(stderr, L"protect --force: cannot open pid %u (%lu); aborting before Ob lock\n",
                     pid, ::GetLastError());
            return 1;
        }
        auto snap = EnumHandles(false);
        uint64_t targetObject = 0;
        uint32_t selfPid = ::GetCurrentProcessId();
        for (auto& h : snap) {
            if (h.pid == selfPid && (HANDLE)(uintptr_t)h.handleValue == self.get()) {
                targetObject = h.object;
                break;
            }
        }

        Dbg(L"protect --force: invoking protectLock IOCTL");
        if (!s.protectLock(pid)) {
            DWORD e = ::GetLastError();
            fwprintf(stderr, L"protect --force: Ob callback registration failed (%lu).\n"
                             L"  EPROCESS->Protection is still set; user-mode tools with equal\n"
                             L"  protection may still touch the process. Some Windows SKUs enforce\n"
                             L"  signing on ObRegisterCallbacks even with testsigning on.\n", e);
            return 1;
        }
        wprintf(L"pid=%u  Ob callback installed (destructive + read + query access stripped)\n", pid);

        // Now revoke pre-existing cross-process handles using the snapshot
        // taken BEFORE the lock — fresh enumeration could come back without
        // our pre-existing handles depending on what other processes do
        // with their handle tables once they realise opens are failing.
        uint32_t closed = RevokeHandlesAgainstObject(targetObject, snap);
        wprintf(L"pid=%u  revoked %u pre-existing cross-process handle(s)\n", pid, closed);
    }
    return 0;
}

// kkill helpers -------------------------------------------------------------

bool IsAllDigits(std::wstring_view s) {
    if (s.empty()) return false;
    for (wchar_t c : s) if (c < L'0' || c > L'9') return false;
    return true;
}

bool EqualsCI(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

// Standard linear-time glob with `*` (zero or more) and `?` (exactly one).
// Case-insensitive; pattern and string are both wide.
bool GlobMatchCI(std::wstring_view pat, std::wstring_view s) {
    size_t pi = 0, si = 0;
    size_t starPi = SIZE_MAX, starSi = 0;
    while (si < s.size()) {
        if (pi < pat.size() && (pat[pi] == L'?' || towlower(pat[pi]) == towlower(s[si]))) {
            ++pi; ++si;
        } else if (pi < pat.size() && pat[pi] == L'*') {
            starPi = pi++;
            starSi = si;
        } else if (starPi != SIZE_MAX) {
            pi = starPi + 1;
            si = ++starSi;
        } else {
            return false;
        }
    }
    while (pi < pat.size() && pat[pi] == L'*') ++pi;
    return pi == pat.size();
}

const ProcessInfo* FindByPid(const std::vector<ProcessInfo>& ps, uint32_t pid) {
    for (auto& p : ps) if (p.pid == pid) return &p;
    return nullptr;
}

void KkillUsage() {
    fwprintf(stderr,
        L"kkill <pid|name> [flags]\n"
        L"  <pid>         numeric PID to terminate (driver IOCTL)\n"
        L"  <name>        process name match (default: case-insensitive exact, e.g. notepad.exe)\n"
        L"\n"
        L"  --glob        treat <name> as a glob (`*`, `?`)\n"
        L"  --all         when a name matches multiple PIDs, kill them all (default: refuse)\n"
        L"  --tree, -t    also terminate every descendant of the target(s)\n"
        L"  --dry-run     list targets without killing\n"
        L"  --exit-code N pass N to ZwTerminateProcess (default: 1)\n");
}

int CmdKkill(int argc, wchar_t** argv) {
    std::wstring target;
    bool useGlob = false;
    bool killAll = false;
    bool tree    = false;
    bool dryRun  = false;
    uint32_t exitCode = 1;

    for (int i = 0; i < argc; ++i) {
        std::wstring_view a = argv[i];
        if      (a == L"--glob")      useGlob = true;
        else if (a == L"--all")       killAll = true;
        else if (a == L"--tree" || a == L"-t") tree = true;
        else if (a == L"--dry-run")   dryRun = true;
        else if (a == L"--exit-code" && i + 1 < argc) exitCode = ParseUint(argv[++i]);
        else if (!a.empty() && a[0] == L'-') {
            fwprintf(stderr, L"kkill: unknown flag %s\n", argv[i]);
            KkillUsage();
            return 1;
        }
        else if (target.empty()) target = argv[i];
        else {
            fwprintf(stderr, L"kkill: only one positional <pid|name> allowed\n");
            return 1;
        }
    }

    if (target.empty()) { KkillUsage(); return 1; }

    Dbg(L"kkill: target=%s glob=%d all=%d tree=%d dryRun=%d exitCode=%u",
        target.c_str(), useGlob, killAll, tree, dryRun, exitCode);
    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    Dbg(L"kkill: driver session open");

    auto procs = EnumProcesses();
    Dbg(L"kkill: EnumProcesses returned %zu rows", procs.size());

    // Resolve <target> to seed PIDs.
    std::vector<uint32_t> seeds;
    if (IsAllDigits(target)) {
        seeds.push_back((uint32_t)wcstoul(target.c_str(), nullptr, 10));
    } else {
        for (auto& p : procs) {
            bool match = useGlob
                ? GlobMatchCI(target, p.imageName)
                : EqualsCI(target, p.imageName);
            if (match) seeds.push_back(p.pid);
        }
        if (seeds.empty()) {
            fwprintf(stderr, L"kkill: no process matches '%s'%s\n",
                     target.c_str(), useGlob ? L"" : L" (pass --glob for wildcards)");
            return 1;
        }
        if (seeds.size() > 1 && !killAll) {
            fwprintf(stderr, L"kkill: '%s' matches %zu processes; pass --all to kill them all:\n",
                     target.c_str(), seeds.size());
            for (auto pid : seeds) {
                auto* p = FindByPid(procs, pid);
                fwprintf(stderr, L"  %6u  %s\n", pid, p ? p->imageName.c_str() : L"?");
            }
            return 1;
        }
    }

    // Tree expansion: BFS the parent map from each seed. Snapshot taken
    // above — descendants reparent to PID 4 after their parent dies, so we
    // must enumerate the tree before any kill happens.
    if (tree) {
        std::unordered_map<uint32_t, std::vector<uint32_t>> children;
        for (auto& p : procs) children[p.parentPid].push_back(p.pid);

        std::unordered_set<uint32_t> all(seeds.begin(), seeds.end());
        std::vector<uint32_t> stack = seeds;
        while (!stack.empty()) {
            uint32_t pid = stack.back();
            stack.pop_back();
            auto it = children.find(pid);
            if (it == children.end()) continue;
            for (auto c : it->second) {
                if (all.insert(c).second) stack.push_back(c);
            }
        }
        seeds.assign(all.begin(), all.end());

        // Kill youngest-first (descendants before ancestors) so a still-alive
        // parent doesn't get a chance to react to a child dying.
        std::unordered_map<uint32_t, uint64_t> bornAt;
        for (auto& p : procs) bornAt[p.pid] = p.createTimeFt;
        std::sort(seeds.begin(), seeds.end(), [&](uint32_t a, uint32_t b) {
            return bornAt[a] > bornAt[b];
        });
    }

    if (dryRun) {
        wprintf(L"dry-run: would terminate %zu process(es):\n", seeds.size());
        for (auto pid : seeds) {
            auto* p = FindByPid(procs, pid);
            wprintf(L"  %6u  %s\n", pid, p ? p->imageName.c_str() : L"?");
        }
        return 0;
    }

    Dbg(L"kkill: %zu seeds after expansion", seeds.size());
    struct KillResult { uint32_t pid; bool ioctlOk; DWORD lastError; };
    std::vector<KillResult> results;
    results.reserve(seeds.size());
    for (auto pid : seeds) {
        Dbg(L"  kkill IOCTL pid=%u", pid);
        bool ok = s.killProcess(pid, exitCode);
        DWORD err = ok ? 0 : ::GetLastError();
        Dbg(L"  ...%s (err=%lu)", ok ? L"OK" : L"FAIL", err);
        results.push_back({pid, ok, err});
    }

    // Verify: a successful IOCTL doesn't guarantee the process actually died
    // (PID 4 used to be the prime example before the driver check). Wait a
    // beat and re-enumerate; anything still present is reported as ALIVE.
    ::Sleep(200);
    auto post = EnumProcesses();
    std::unordered_set<uint32_t> stillAlive;
    for (auto& p : post) stillAlive.insert(p.pid);

    int failures = 0;
    for (auto& r : results) {
        auto* p = FindByPid(procs, r.pid);
        const wchar_t* name = p ? p->imageName.c_str() : L"?";
        if (!r.ioctlOk) {
            fwprintf(stderr, L"[FAIL ] %6u %s : kkill IOCTL failed (%lu)\n",
                     r.pid, name, r.lastError);
            ++failures;
        } else if (stillAlive.contains(r.pid)) {
            fwprintf(stderr, L"[ALIVE] %6u %s : IOCTL returned success but PID still present\n",
                     r.pid, name);
            ++failures;
        } else {
            wprintf(L"[OK   ] %6u %s\n", r.pid, name);
        }
    }
    return failures ? 1 : 0;
}

int CmdCallbacks(int argc, wchar_t** argv) {
    CallbackKind kind = CallbackKind::Process;
    if (argc >= 1) {
        if (wcscmp(argv[0], L"process") == 0) kind = CallbackKind::Process;
        else if (wcscmp(argv[0], L"image") == 0) kind = CallbackKind::Image;
        else if (wcscmp(argv[0], L"thread") == 0) kind = CallbackKind::Thread;
        else { fwprintf(stderr, L"callbacks: kind must be process|image|thread\n"); return 1; }
    }
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto cbs = s.enumCallbacks(kind);
    wprintf(L"%-3s %-18s %-18s %s\n", L"#", L"Routine", L"ModBase", L"Module");
    int i = 0;
    for (auto& c : cbs) {
        wprintf(L"%3d 0x%016llx 0x%016llx %S\n",
                i++, (unsigned long long)c.routine, (unsigned long long)c.moduleBase,
                c.moduleName.c_str());
    }
    return 0;
}

int CmdKdrivers() {
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto ds = s.enumKernelDrivers();
    wprintf(L"%-18s %-10s %s\n", L"Base", L"Size(KB)", L"Path");
    for (auto& d : ds) {
        wprintf(L"0x%016llx %10u %S\n", (unsigned long long)d.imageBase, d.imageSize / 1024, d.fullPath.c_str());
    }
    return 0;
}

int CmdSsdt() {
    DriverSession s; if (!OpenDriverOrHint(s)) return 1;
    auto es = s.enumSsdt();
    wprintf(L"%-5s %-18s %s\n", L"#", L"Routine", L"Module");
    for (auto& e : es) {
        wprintf(L"%5u 0x%016llx %S\n", e.index, (unsigned long long)e.routine, e.moduleName.c_str());
    }
    return 0;
}

// ghost --------------------------------------------------------------------
//
// A "ghost" is a process the system is in some way lying about. Three
// vectors of detection, in order of strength:
//
//   1. KERNEL_HIDDEN  — DKOM-style. PsLookupProcessByProcessId can find
//                       the PID (via brute-force in the driver), but it
//                       does NOT show in NtQuerySystemInformation. Rootkit
//                       unlinked the EPROCESS from ActiveProcessLinks.
//   2. ZOMBIE         — NtQuerySystemInformation lists the PID with zero
//                       threads. Process has exited but its EPROCESS is
//                       still pinned (typically by an outstanding handle).
//   3. IMAGE_DELETED  — Process exists with running threads, but its
//                       primary image file no longer exists on disk
//                       (classic "drop & delete" persistence trick).
//
// Killing uses the kkill IOCTL — runs at kernel mode, opens via
// ObOpenObjectByPointer, and works on hidden EPROCESS pointers.
//
// Flags:
//   --kill <pid>      terminate a specific ghost PID (must be in the list)
//   --kill-all        terminate every detected ghost
//   --yes / -y        skip the interactive confirm prompt for --kill-all

struct GhostInfo {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::wstring name;
    bool hidden       = false;   // (1)
    bool zombie       = false;   // (2)
    bool imageDeleted = false;   // (3)
};

static const wchar_t* GhostReason(const GhostInfo& g) {
    static wchar_t buf[64];
    int n = 0;
    if (g.hidden)       n += swprintf_s(buf + n, 64 - n, L"%sHIDDEN", n ? L"+" : L"");
    if (g.zombie)       n += swprintf_s(buf + n, 64 - n, L"%sZOMBIE", n ? L"+" : L"");
    if (g.imageDeleted) n += swprintf_s(buf + n, 64 - n, L"%sIMG-GONE", n ? L"+" : L"");
    return buf;
}

static std::vector<GhostInfo> DetectGhosts() {
    std::vector<GhostInfo> out;

    DriverSession s;
    auto userPs = EnumProcesses();
    std::unordered_map<uint32_t, const ProcessInfo*> byPid;
    for (auto& p : userPs) byPid[p.pid] = &p;

    // Vector 1: kernel-vs-user diff. Requires the driver.
    if (s.open()) {
        auto kernelPs = s.enumPids();
        for (auto& k : kernelPs) {
            if (!byPid.contains(k.pid) && k.pid > 4) {
                GhostInfo g;
                g.pid = k.pid;
                g.parentPid = k.parentPid;
                // imageName from kernel is 8.3 ANSI; widen.
                wchar_t wide[64]{};
                ::MultiByteToWideChar(CP_UTF8, 0, k.imageName.c_str(), -1, wide, 64);
                g.name = wide;
                g.hidden = true;
                out.push_back(std::move(g));
            }
        }
    }

    // Vectors 2 and 3 walk the user-mode list.
    for (auto& p : userPs) {
        if (p.pid <= 4) continue;

        bool z = (p.threadCount == 0);
        bool d = false;
        if (!z) {
            // Enrich to get the on-disk path. EnrichProcess opens the
            // process; if that fails it leaves imagePath empty.
            ProcessInfo enriched = p;
            EnrichProcess(enriched);
            if (!enriched.imagePath.empty()) {
                DWORD attr = ::GetFileAttributesW(enriched.imagePath.c_str());
                if (attr == INVALID_FILE_ATTRIBUTES &&
                    ::GetLastError() == ERROR_FILE_NOT_FOUND) {
                    d = true;
                }
            }
        }
        if (!z && !d) continue;

        GhostInfo g;
        g.pid = p.pid;
        g.parentPid = p.parentPid;
        g.name = p.imageName;
        g.zombie = z;
        g.imageDeleted = d;
        out.push_back(std::move(g));
    }

    return out;
}

int CmdGhost(int argc, wchar_t** argv) {
    bool killAll  = false;
    bool yes      = false;
    uint32_t killOne = 0;
    bool haveKillOne = false;

    for (int i = 0; i < argc; ++i) {
        std::wstring_view a = argv[i];
        if      (a == L"--kill-all")        killAll = true;
        else if (a == L"--yes" || a == L"-y") yes = true;
        else if (a == L"--kill" && i + 1 < argc) {
            killOne = ParseUint(argv[++i]);
            haveKillOne = true;
        }
        else {
            fwprintf(stderr, L"ghost: unknown arg %s\n", argv[i]);
            fwprintf(stderr,
                L"usage: winternal ghost [--kill <pid>] [--kill-all] [--yes|-y]\n");
            return 1;
        }
    }

    Dbg(L"ghost: killAll=%d yes=%d kill=%u%s", killAll, yes, killOne, haveKillOne ? L" set" : L"");
    auto ghosts = DetectGhosts();
    Dbg(L"ghost: detected %zu ghost rows", ghosts.size());

    if (ghosts.empty()) {
        wprintf(L"No ghosts found.\n");
        return 0;
    }

    if (!haveKillOne && !killAll) {
        wprintf(L"%-6s %-7s %-22s %s\n", L"PID", L"PPID", L"NAME", L"REASON");
        for (auto& g : ghosts) {
            wprintf(L"%-6u %-7u %-22s %s\n",
                    g.pid, g.parentPid, g.name.c_str(), GhostReason(g));
        }
        return 0;
    }

    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;

    auto killOnePid = [&](uint32_t pid, const wchar_t* name) {
        if (s.killProcess(pid)) {
            wprintf(L"[OK   ] %6u %s\n", pid, name);
            return true;
        }
        fwprintf(stderr, L"[FAIL ] %6u %s : kkill IOCTL failed (%lu)\n",
                 pid, name, ::GetLastError());
        return false;
    };

    if (haveKillOne) {
        for (auto& g : ghosts) {
            if (g.pid == killOne) return killOnePid(g.pid, g.name.c_str()) ? 0 : 1;
        }
        fwprintf(stderr,
            L"ghost --kill %u: PID is not in the ghost list (run `winternal ghost` first).\n",
            killOne);
        return 1;
    }

    // killAll path.
    if (!yes) {
        wprintf(L"About to terminate %zu ghost process(es):\n", ghosts.size());
        for (auto& g : ghosts) {
            wprintf(L"  %6u  %-22s  %s\n", g.pid, g.name.c_str(), GhostReason(g));
        }
        wprintf(L"Type YES to confirm, anything else to cancel: ");
        fflush(stdout);
        wchar_t line[64]{};
        if (!fgetws(line, 64, stdin)) return 1;
        // Trim trailing newline.
        for (wchar_t* p = line; *p; ++p) if (*p == L'\n' || *p == L'\r') { *p = 0; break; }
        if (wcscmp(line, L"YES") != 0) {
            wprintf(L"Cancelled.\n");
            return 1;
        }
    }

    int failures = 0;
    for (auto& g : ghosts) {
        if (!killOnePid(g.pid, g.name.c_str())) ++failures;
    }
    return failures ? 1 : 0;
}

// win ----------------------------------------------------------------------
//
// HWND-level utilities for top-level windows. Uses pure user32; nothing
// here needs the driver.
//
//   win list [--pid N] [--title PAT] [--class PAT] [--visible]
//   win info <hwnd>
//   win close <hwnd>               WM_CLOSE — polite, may be ignored
//   win kill  <hwnd>               WM_CLOSE, then kkill the owner if it survives
//   win hide  <hwnd>               ShowWindow(SW_HIDE)
//   win show  <hwnd>               ShowWindow(SW_SHOWNA)
//   win front <hwnd>               SetForegroundWindow + AttachThreadInput trick
//   win topmost <hwnd> [off]       toggle WS_EX_TOPMOST
//   win move  <hwnd> <x> <y> [w h]
//
// HWND can be hex (0x...) or decimal. PAT matches via simple GlobMatchCI.

struct WinRow {
    HWND     hwnd;
    DWORD    pid;
    DWORD    tid;
    std::wstring title;
    std::wstring cls;
    bool     visible;
    RECT     rect;
};

static std::wstring GetWindowTextSafe(HWND h) {
    wchar_t buf[512]{};
    int n = ::GetWindowTextW(h, buf, 512);
    return std::wstring(buf, (size_t)n);
}

static std::wstring GetClassNameSafe(HWND h) {
    wchar_t buf[256]{};
    int n = ::GetClassNameW(h, buf, 256);
    return std::wstring(buf, (size_t)n);
}

struct WinCollect {
    std::vector<WinRow>* rows;
    DWORD filterPid;
    const wchar_t* titlePat;
    const wchar_t* classPat;
    bool visibleOnly;
};

static BOOL CALLBACK WinCollectProc(HWND h, LPARAM lp) {
    auto* ctx = reinterpret_cast<WinCollect*>(lp);
    WinRow r{};
    r.hwnd = h;
    r.tid = ::GetWindowThreadProcessId(h, &r.pid);
    r.visible = ::IsWindowVisible(h) != 0;
    r.title = GetWindowTextSafe(h);
    r.cls   = GetClassNameSafe(h);
    ::GetWindowRect(h, &r.rect);

    if (ctx->filterPid && r.pid != ctx->filterPid) return TRUE;
    if (ctx->visibleOnly && !r.visible) return TRUE;
    if (ctx->titlePat && *ctx->titlePat && !GlobMatchCI(ctx->titlePat, r.title)) return TRUE;
    if (ctx->classPat && *ctx->classPat && !GlobMatchCI(ctx->classPat, r.cls))   return TRUE;
    ctx->rows->push_back(std::move(r));
    return TRUE;
}

static HWND ParseHwnd(const wchar_t* s) {
    return (HWND)(uintptr_t)ParseU64(s);
}

static int CmdWinList(int argc, wchar_t** argv) {
    Dbg(L"win list: argc=%d", argc);
    DWORD pid = 0;
    const wchar_t* titlePat = nullptr;
    const wchar_t* classPat = nullptr;
    bool visibleOnly = false;
    for (int i = 0; i < argc; ++i) {
        std::wstring_view a = argv[i];
        if      (a == L"--pid"     && i + 1 < argc) pid = ParseUint(argv[++i]);
        else if (a == L"--title"   && i + 1 < argc) titlePat = argv[++i];
        else if (a == L"--class"   && i + 1 < argc) classPat = argv[++i];
        else if (a == L"--visible") visibleOnly = true;
        else { fwprintf(stderr, L"win list: unknown arg %s\n", argv[i]); return 1; }
    }
    std::vector<WinRow> rows;
    WinCollect ctx{ &rows, pid, titlePat, classPat, visibleOnly };
    ::EnumWindows(WinCollectProc, (LPARAM)&ctx);

    wprintf(L"%-18s %-6s %-3s %-22s %s\n", L"HWND", L"PID", L"V", L"CLASS", L"TITLE");
    for (auto& r : rows) {
        wprintf(L"0x%016llx %-6lu %-3s %-22.22s %s\n",
                (unsigned long long)(uintptr_t)r.hwnd,
                r.pid,
                r.visible ? L"y" : L"n",
                r.cls.c_str(),
                r.title.c_str());
    }
    return 0;
}

static int CmdWinInfo(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win info <hwnd>\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win info: not a window: %s\n", argv[0]); return 1; }

    DWORD pid = 0;
    DWORD tid = ::GetWindowThreadProcessId(h, &pid);
    LONG_PTR style   = ::GetWindowLongPtrW(h, GWL_STYLE);
    LONG_PTR exStyle = ::GetWindowLongPtrW(h, GWL_EXSTYLE);
    RECT rect{};
    ::GetWindowRect(h, &rect);
    HWND parent = ::GetParent(h);
    HWND owner  = ::GetWindow(h, GW_OWNER);

    auto procs = EnumProcesses();
    const wchar_t* name = L"?";
    for (auto& p : procs) if (p.pid == pid) { name = p.imageName.c_str(); break; }

    wprintf(L"hwnd:       0x%016llx\n", (unsigned long long)(uintptr_t)h);
    wprintf(L"title:      %s\n", GetWindowTextSafe(h).c_str());
    wprintf(L"class:      %s\n", GetClassNameSafe(h).c_str());
    wprintf(L"pid/tid:    %lu / %lu  (%s)\n", pid, tid, name);
    wprintf(L"visible:    %s\n", ::IsWindowVisible(h) ? L"yes" : L"no");
    wprintf(L"enabled:    %s\n", ::IsWindowEnabled(h) ? L"yes" : L"no");
    wprintf(L"minimized:  %s\n", ::IsIconic(h) ? L"yes" : L"no");
    wprintf(L"maximized:  %s\n", ::IsZoomed(h) ? L"yes" : L"no");
    wprintf(L"style:      0x%08llx\n", (unsigned long long)style);
    wprintf(L"ex-style:   0x%08llx  (topmost=%s)\n", (unsigned long long)exStyle,
            (exStyle & WS_EX_TOPMOST) ? L"yes" : L"no");
    wprintf(L"rect:       (%ld,%ld) %ldx%ld\n",
            rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);
    wprintf(L"parent:     0x%016llx\n", (unsigned long long)(uintptr_t)parent);
    wprintf(L"owner:      0x%016llx\n", (unsigned long long)(uintptr_t)owner);
    return 0;
}

static int CmdWinClose(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win close <hwnd>\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win close: not a window\n"); return 1; }
    if (!::PostMessageW(h, WM_CLOSE, 0, 0)) {
        fwprintf(stderr, L"win close: PostMessage failed (%lu)\n", ::GetLastError()); return 1;
    }
    wprintf(L"WM_CLOSE posted.\n");
    return 0;
}

static int CmdWinKill(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win kill <hwnd>\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win kill: not a window\n"); return 1; }
    DWORD pid = 0;
    ::GetWindowThreadProcessId(h, &pid);
    ::PostMessageW(h, WM_CLOSE, 0, 0);
    // Give the window a moment to respond. If the owning process is still
    // alive afterwards, drop to the driver-side kkill — works on PPL/PP
    // processes that won't die to a polite WM_CLOSE.
    ::Sleep(500);
    if (pid && ::IsWindow(h)) {
        DriverSession s;
        if (OpenDriverOrHint(s)) {
            if (s.killProcess(pid)) {
                wprintf(L"win kill: WM_CLOSE ignored; kkilled pid %lu\n", pid);
                return 0;
            }
            fwprintf(stderr, L"win kill: kkill pid %lu failed (%lu)\n", pid, ::GetLastError());
            return 1;
        }
        return 1;
    }
    wprintf(L"win kill: window closed via WM_CLOSE.\n");
    return 0;
}

static int CmdWinShowHide(const wchar_t* hwndArg, int cmd) {
    HWND h = ParseHwnd(hwndArg);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win: not a window\n"); return 1; }
    ::ShowWindow(h, cmd);
    return 0;
}

static int CmdWinFront(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win front <hwnd>\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win front: not a window\n"); return 1; }
    // SetForegroundWindow is rate-limited by Windows. Attach our input
    // thread to the target's thread first — that bypasses the lockout.
    DWORD fgTid = ::GetWindowThreadProcessId(::GetForegroundWindow(), nullptr);
    DWORD myTid = ::GetCurrentThreadId();
    BOOL attached = ::AttachThreadInput(myTid, fgTid, TRUE);
    ::ShowWindow(h, SW_RESTORE);
    BOOL ok = ::SetForegroundWindow(h);
    if (attached) ::AttachThreadInput(myTid, fgTid, FALSE);
    if (!ok) { fwprintf(stderr, L"win front: SetForegroundWindow refused (%lu)\n", ::GetLastError()); return 1; }
    return 0;
}

static int CmdWinTopmost(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win topmost <hwnd> [off]\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win topmost: not a window\n"); return 1; }
    bool off = (argc >= 2 && (EqualsCI(argv[1], L"off") || EqualsCI(argv[1], L"false") || EqualsCI(argv[1], L"0")));
    if (!::SetWindowPos(h, off ? HWND_NOTOPMOST : HWND_TOPMOST,
                        0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
        fwprintf(stderr, L"win topmost: SetWindowPos failed (%lu)\n", ::GetLastError()); return 1;
    }
    wprintf(L"topmost = %s\n", off ? L"off" : L"on");
    return 0;
}

// zbid: read / set the window's Z-band, an internal user32 dimension that
// stacks windows above the normal Z-order. Undocumented exports:
//   BOOL WINAPI SetWindowBand(HWND hWnd, HWND hwndInsertAfter, DWORD dwBand);
//   BOOL WINAPI GetWindowBand(HWND hWnd, PDWORD pdwBand);
// Known band IDs (Win10/11, build-stable):
//   0  DEFAULT                7  IMMERSIVE_EDGY
//   1  DESKTOP                8  IMMERSIVE_INACTIVEMOBODY
//   2  UIACCESS               9  IMMERSIVE_INACTIVEDOCK
//   3  IMMERSIVE_IHM         10  IMMERSIVE_ACTIVEMOBODY
//   4  IMMERSIVE_NOTIFICATION 11 IMMERSIVE_ACTIVEDOCK
//   5  IMMERSIVE_APPCHROME   12  IMMERSIVE_BACKGROUND
//   6  IMMERSIVE_MOGO        13  IMMERSIVE_SEARCH
//                            14  GENUINE_WINDOWS
//                            15  IMMERSIVE_RESTRICTED
//                            16  SYSTEM_TOOLS
//                            17  LOCK
//                            18  ABOVELOCK_UX
typedef BOOL (WINAPI *PFN_SetWindowBand)(HWND, HWND, DWORD);
typedef BOOL (WINAPI *PFN_GetWindowBand)(HWND, PDWORD);

static const wchar_t* ZbidName(DWORD b) {
    switch (b) {
    case  0: return L"DEFAULT";
    case  1: return L"DESKTOP";
    case  2: return L"UIACCESS";
    case  3: return L"IMMERSIVE_IHM";
    case  4: return L"IMMERSIVE_NOTIFICATION";
    case  5: return L"IMMERSIVE_APPCHROME";
    case  6: return L"IMMERSIVE_MOGO";
    case  7: return L"IMMERSIVE_EDGY";
    case  8: return L"IMMERSIVE_INACTIVEMOBODY";
    case  9: return L"IMMERSIVE_INACTIVEDOCK";
    case 10: return L"IMMERSIVE_ACTIVEMOBODY";
    case 11: return L"IMMERSIVE_ACTIVEDOCK";
    case 12: return L"IMMERSIVE_BACKGROUND";
    case 13: return L"IMMERSIVE_SEARCH";
    case 14: return L"GENUINE_WINDOWS";
    case 15: return L"IMMERSIVE_RESTRICTED";
    case 16: return L"SYSTEM_TOOLS";
    case 17: return L"LOCK";
    case 18: return L"ABOVELOCK_UX";
    }
    return L"?";
}

// RAII helper that flips TOKEN_HAS_UI_ACCESS on the current process via
// the driver and restores the previous state when it goes out of scope.
class ScopedUIAccess {
public:
    ScopedUIAccess() {
        Dbg(L"ScopedUIAccess: opening driver");
        if (!session_.open()) { Dbg(L"ScopedUIAccess: open failed (%lu)", ::GetLastError()); return; }
        Dbg(L"ScopedUIAccess: setting TOKEN_HAS_UI_ACCESS on pid %lu", ::GetCurrentProcessId());
        uint32_t prev = 0;
        if (!session_.setTokenUIAccess(::GetCurrentProcessId(), true, &prev, nullptr)) {
            Dbg(L"ScopedUIAccess: IOCTL failed (%lu)", ::GetLastError());
            return;
        }
        prevFlags_ = prev;
        applied_ = true;
        Dbg(L"ScopedUIAccess: applied (prev TokenFlags=0x%08x)", prev);
    }
    ~ScopedUIAccess() {
        if (!applied_) return;
        bool wasOn = (prevFlags_ & 0x10) != 0;
        Dbg(L"~ScopedUIAccess: %s prior bit", wasOn ? L"leaving (was already set)" : L"clearing");
        if (!wasOn) session_.setTokenUIAccess(::GetCurrentProcessId(), false, nullptr, nullptr);
    }
    bool applied() const { return applied_; }
    ScopedUIAccess(const ScopedUIAccess&) = delete;
    ScopedUIAccess& operator=(const ScopedUIAccess&) = delete;
private:
    DriverSession session_;
    uint32_t prevFlags_ = 0;
    bool applied_ = false;
};

// Flip the "immersive broker" flag on OUR OWN tagPROCESSINFO so that
// win32kbase!IsImmersiveBroker(our_pi) returns TRUE for the duration of
// our SetWindowBand call. tagPROCESSINFO lives in kernel pool — fully
// writable, no HVCI / CR0.WP needed.
//
// IsImmersiveBroker decompile (win32kbase.sys 24H2 26100):
//     if ((p[102] & 0x30) == 0x20) return 1;     // a[102] = QWORD at +0x330
//     ...two session-global pointer comparisons...
//     return 0;
// So we need (p->qword[0x330] & 0x30) == 0x20, i.e. bit 0x20 set, 0x10 clear.
//
// Knock-on effect in NtUserSetWindowBand / _DeferWindowPosAndBand:
//   IsImmersiveBroker(pi)=1 → xxxSetWindowBand called with opts=3
//   (opts & 2)!=0 → IAMThreadAccessGranted check skipped
//   IsValidBandForProcess() first line short-circuits to 1.
// Both gates dissolve from one pool byte mutation on a 64-bit field.
class ScopedWin32kBandBypass {
public:
    ScopedWin32kBandBypass() {
        Dbg(L"ScopedWin32kBandBypass: opening driver");
        if (!session_.open()) { Dbg(L"...open failed (%lu)", ::GetLastError()); return; }

        Dbg(L"ScopedWin32kBandBypass: resolving our tagPROCESSINFO");
        auto pi = session_.getWin32Process(::GetCurrentProcessId());
        if (!pi || *pi == 0) {
            Dbg(L"...getWin32Process returned %s",
                pi ? L"0 (no GUI state on this process)" : L"FAILED");
            return;
        }
        piAddr_ = *pi;
        flagAddr_ = piAddr_ + kFlagOffset;
        Dbg(L"  tagPROCESSINFO = 0x%016llx (flag at +0x%X = 0x%016llx)",
            piAddr_, kFlagOffset, flagAddr_);

        Dbg(L"ScopedWin32kBandBypass: kread current flag QWORD");
        auto save = session_.kread(flagAddr_, sizeof(uint64_t));
        if (!save || save->size() != sizeof(uint64_t)) {
            Dbg(L"...kread FAILED (%lu)", ::GetLastError());
            return;
        }
        std::memcpy(&origVal_, save->data(), sizeof(origVal_));
        Dbg(L"  orig flags QWORD = 0x%016llx", origVal_);

        // Set bit 0x20, clear bit 0x10 → (val & 0x30) == 0x20.
        uint64_t patched = (origVal_ & ~0x10ULL) | 0x20ULL;
        Dbg(L"  patched flags    = 0x%016llx  (bit 0x20 set, 0x10 clear)", patched);

        Dbg(L"ScopedWin32kBandBypass: kwrite patched flag");
        if (!session_.kwrite(flagAddr_, &patched, sizeof(patched))) {
            Dbg(L"...kwrite FAILED (%lu)", ::GetLastError());
            return;
        }
        applied_ = true;
        Dbg(L"ScopedWin32kBandBypass: IsImmersiveBroker(our PI) now returns 1");
    }
    ~ScopedWin32kBandBypass() {
        if (!applied_) return;
        Dbg(L"~ScopedWin32kBandBypass: restoring original flag QWORD");
        session_.kwrite(flagAddr_, &origVal_, sizeof(origVal_));
    }
    bool applied() const { return applied_; }
    ScopedWin32kBandBypass(const ScopedWin32kBandBypass&) = delete;
    ScopedWin32kBandBypass& operator=(const ScopedWin32kBandBypass&) = delete;
private:
    static constexpr uint32_t kFlagOffset = 0x330;  // tagPROCESSINFO + 0x330
    DriverSession session_;
    uint64_t piAddr_   = 0;
    uint64_t flagAddr_ = 0;
    uint64_t origVal_  = 0;
    bool applied_ = false;
};

// Same pattern for EPROCESS->SignatureLevel + SectionSignatureLevel.
// Bumps both to SE_SIGNING_LEVEL_WINDOWS (0x0C) on construction so
// win32k's high-band gate sees the process as MS-signed, restores the
// originals on destruction so we don't leave the process permanently
// "more trusted" than it really is.
class ScopedMsSig {
public:
    ScopedMsSig() {
        Dbg(L"ScopedMsSig: opening driver");
        if (!session_.open()) { Dbg(L"ScopedMsSig: open failed (%lu)", ::GetLastError()); return; }
        Dbg(L"ScopedMsSig: setting EPROCESS+0x878/879 = SE_SIGNING_LEVEL_WINDOWS");
        uint8_t prevSig = 0, prevSec = 0;
        if (!session_.setSignatureLevel(::GetCurrentProcessId(),
                                        WINTERNAL_SIGLEVEL_WINDOWS,
                                        WINTERNAL_SIGLEVEL_WINDOWS,
                                        &prevSig, &prevSec)) {
            Dbg(L"ScopedMsSig: IOCTL failed (%lu)", ::GetLastError());
            return;
        }
        prevSig_ = prevSig;
        prevSec_ = prevSec;
        applied_ = true;
        Dbg(L"ScopedMsSig: applied (prev sig=0x%02x section=0x%02x)", prevSig, prevSec);
    }
    ~ScopedMsSig() {
        if (!applied_) return;
        Dbg(L"~ScopedMsSig: restoring sig=0x%02x section=0x%02x", prevSig_, prevSec_);
        session_.setSignatureLevel(::GetCurrentProcessId(), prevSig_, prevSec_, nullptr, nullptr);
    }
    bool applied() const { return applied_; }
    ScopedMsSig(const ScopedMsSig&) = delete;
    ScopedMsSig& operator=(const ScopedMsSig&) = delete;
private:
    DriverSession session_;
    uint8_t prevSig_ = 0, prevSec_ = 0;
    bool applied_ = false;
};

static int CmdWinZbid(int argc, wchar_t** argv) {
    if (argc < 1) { fwprintf(stderr, L"win zbid <hwnd> [band 0..18]\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win zbid: not a window\n"); return 1; }
    HMODULE u32 = ::GetModuleHandleW(L"user32.dll");

    if (argc == 1) {
        auto fn = (PFN_GetWindowBand)::GetProcAddress(u32, "GetWindowBand");
        if (!fn) { fwprintf(stderr, L"win zbid: user32!GetWindowBand not exported on this build\n"); return 1; }
        DWORD band = 0;
        if (!fn(h, &band)) { fwprintf(stderr, L"win zbid: GetWindowBand failed (%lu)\n", ::GetLastError()); return 1; }
        wprintf(L"zbid = %lu  (%s)\n", band, ZbidName(band));
        return 0;
    }

    auto fn = (PFN_SetWindowBand)::GetProcAddress(u32, "SetWindowBand");
    if (!fn) { fwprintf(stderr, L"win zbid: user32!SetWindowBand not exported on this build\n"); return 1; }
    DWORD band = (DWORD)ParseU64(argv[1]);

    Dbg(L"zbid: stage 0 — calling user32!SetWindowBand directly");
    if (fn(h, NULL, band)) {
        Dbg(L"zbid: stage 0 OK");
        wprintf(L"zbid -> %lu (%s)\n", band, ZbidName(band));
        return 0;
    }
    DWORD firstErr = ::GetLastError();
    Dbg(L"zbid: stage 0 returned %lu", firstErr);
    if (firstErr != ERROR_ACCESS_DENIED) {
        fwprintf(stderr, L"win zbid: SetWindowBand(%lu) failed (%lu)\n", band, firstErr);
        return 1;
    }

    // Direct call refused us. Climb up the access ladder:
    //   stage 1 — UIAccess flip (TOKEN_HAS_UI_ACCESS): satisfies the gate
    //             for bands 0..13 and the standard UIAccess-only bands.
    //   stage 2 — MS-sig flip (EPROCESS->SignatureLevel/SectionSignatureLevel):
    //             satisfies win32k's high-band gate (SYSTEM_TOOLS, LOCK,
    //             ABOVELOCK_UX, GENUINE_WINDOWS) which checks that the
    //             caller's image is Microsoft-signed.
    // Both flips are RAII-scoped — the bits are restored on return.
    // References:
    //   https://github.com/arcanine300/CreateWindowInBand — winlogon-token
    //   relaunch trick. We skip the relaunch by writing both fields from
    //   the kernel side, no process restart, no token theft.

    Dbg(L"zbid: entering stage 1 (UIAccess flip)");
    ScopedUIAccess ua;
    if (!ua.applied()) {
        fwprintf(stderr,
            L"win zbid: SetWindowBand refused (5) and the driver UIAccess flip\n"
            L"  failed too. Is Winternal.sys loaded? (`winternal status`)\n");
        return 1;
    }
    Dbg(L"zbid: stage 1 active — retrying SetWindowBand");
    if (fn(h, NULL, band)) {
        Dbg(L"zbid: stage 1 OK");
        wprintf(L"zbid -> %lu (%s)  [driver-assisted: UIAccess]\n", band, ZbidName(band));
        return 0;
    }
    DWORD uaErr = ::GetLastError();
    Dbg(L"zbid: stage 1 retry returned %lu", uaErr);
    if (uaErr != ERROR_ACCESS_DENIED) {
        fwprintf(stderr, L"win zbid: SetWindowBand(%lu) failed with UIAccess (%lu)\n", band, uaErr);
        return 1;
    }

    // Still denied — escalate to MS-signature spoof. Bands like
    // GENUINE_WINDOWS / SYSTEM_TOOLS need this in addition to UIAccess.
    Dbg(L"zbid: entering stage 2 (MS-sig spoof)");
    ScopedMsSig sig;
    if (!sig.applied()) {
        fwprintf(stderr,
            L"win zbid: SetWindowBand still refused after UIAccess; couldn't apply\n"
            L"  the MS-signature spoof either (driver write failed).\n");
        return 1;
    }
    Dbg(L"zbid: stage 2 active — retrying SetWindowBand");
    if (fn(h, NULL, band)) {
        Dbg(L"zbid: stage 2 OK");
        wprintf(L"zbid -> %lu (%s)  [driver-assisted: UIAccess + MS-sig spoof]\n",
                band, ZbidName(band));
        return 0;
    }
    DWORD sigErr = ::GetLastError();
    Dbg(L"zbid: stage 2 retry returned %lu", sigErr);
    if (sigErr != ERROR_ACCESS_DENIED) {
        fwprintf(stderr, L"win zbid: SetWindowBand(%lu) failed with sig spoof (%lu)\n", band, sigErr);
        return 1;
    }

    Dbg(L"zbid: entering stage 3 (win32kfull patch)");
    ScopedWin32kBandBypass w32;
    if (!w32.applied()) {
        fwprintf(stderr,
            L"win zbid: couldn't apply the win32kfull patches.\n"
            L"  Common causes: HVCI / VBS rejecting the code write, or RVAs differ\n"
            L"  on this build (see ScopedWin32kBandBypass: 0x2E390 / 0x2B1B08).\n");
        return 1;
    }
    Dbg(L"zbid: stage 3 active — retrying SetWindowBand");
    if (fn(h, NULL, band)) {
        Dbg(L"zbid: stage 3 OK");
        wprintf(L"zbid -> %lu (%s)  [driver-assisted: UIAccess + MS-sig + win32kfull patch]\n",
                band, ZbidName(band));
        return 0;
    }
    DWORD w32Err = ::GetLastError();
    Dbg(L"zbid: stage 3 retry returned %lu", w32Err);
    fwprintf(stderr,
        L"win zbid: SetWindowBand(%lu) refused even with full bypass (%lu).\n",
        band, w32Err);
    return 1;
}

// privacy: SetWindowDisplayAffinity — controls whether the window's pixels
// appear to screen-capture APIs (PrintWindow, BitBlt of the desktop DC,
// Graphics.CopyFromScreen, Win+Shift+S, GraphicsCapture, etc).
//   none     WDA_NONE                  (0x00)   visible to capture
//   monitor  WDA_MONITOR               (0x01)   blacked out in capture, still on screen
//   hide     WDA_EXCLUDEFROMCAPTURE    (0x11)   missing from capture entirely (Win10 2004+)
#ifndef WDA_NONE
#define WDA_NONE                0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR             0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE  0x00000011
#endif

typedef BOOL (WINAPI *PFN_GetWindowDisplayAffinity)(HWND, DWORD*);

static const wchar_t* AffinityName(DWORD a) {
    switch (a) {
    case WDA_NONE:               return L"NONE (capturable)";
    case WDA_MONITOR:            return L"MONITOR (blacked out)";
    case WDA_EXCLUDEFROMCAPTURE: return L"EXCLUDE-FROM-CAPTURE (invisible)";
    }
    return L"?";
}

static int CmdWinPrivacy(int argc, wchar_t** argv) {
    if (argc < 1) {
        fwprintf(stderr,
            L"win privacy <hwnd>                       show current state\n"
            L"win privacy <hwnd> <none|monitor|hide>   set state\n");
        return 1;
    }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win privacy: not a window\n"); return 1; }

    if (argc == 1) {
        // GetWindowDisplayAffinity is exported on the same builds as Set,
        // but we resolve via GetProcAddress to keep the binary loadable on
        // older targets (delay-loading user32 is more pain than it's worth).
        HMODULE u32 = ::GetModuleHandleW(L"user32.dll");
        auto fn = (PFN_GetWindowDisplayAffinity)::GetProcAddress(u32, "GetWindowDisplayAffinity");
        if (!fn) { fwprintf(stderr, L"win privacy: user32!GetWindowDisplayAffinity unavailable\n"); return 1; }
        DWORD a = 0;
        if (!fn(h, &a)) { fwprintf(stderr, L"win privacy: GetWindowDisplayAffinity failed (%lu)\n", ::GetLastError()); return 1; }
        wprintf(L"privacy = 0x%02lx  (%s)\n", a, AffinityName(a));
        return 0;
    }

    std::wstring_view mode = argv[1];
    DWORD a;
    if      (EqualsCI(mode, L"none"))    a = WDA_NONE;
    else if (EqualsCI(mode, L"monitor")) a = WDA_MONITOR;
    else if (EqualsCI(mode, L"hide") || EqualsCI(mode, L"exclude")) a = WDA_EXCLUDEFROMCAPTURE;
    else { fwprintf(stderr, L"win privacy: mode must be none|monitor|hide\n"); return 1; }

    if (!::SetWindowDisplayAffinity(h, a)) {
        fwprintf(stderr, L"win privacy: SetWindowDisplayAffinity(0x%02lx) failed (%lu)\n",
                 a, ::GetLastError());
        return 1;
    }
    wprintf(L"privacy -> 0x%02lx (%s)\n", a, AffinityName(a));
    return 0;
}

static int CmdWinMove(int argc, wchar_t** argv) {
    if (argc < 3) { fwprintf(stderr, L"win move <hwnd> <x> <y> [w h]\n"); return 1; }
    HWND h = ParseHwnd(argv[0]);
    if (!::IsWindow(h)) { fwprintf(stderr, L"win move: not a window\n"); return 1; }
    int x = (int)ParseU64(argv[1]);
    int y = (int)ParseU64(argv[2]);
    UINT flags = SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSIZE;
    int w = 0, ht = 0;
    if (argc >= 5) {
        w  = (int)ParseU64(argv[3]);
        ht = (int)ParseU64(argv[4]);
        flags &= ~SWP_NOSIZE;
    }
    if (!::SetWindowPos(h, nullptr, x, y, w, ht, flags)) {
        fwprintf(stderr, L"win move: SetWindowPos failed (%lu)\n", ::GetLastError()); return 1;
    }
    return 0;
}

int CmdWin(int argc, wchar_t** argv) {
    if (argc < 1) {
        fwprintf(stderr,
            L"usage: winternal win <subcommand> [args]\n"
            L"  list [--pid N] [--title PAT] [--class PAT] [--visible]\n"
            L"  info  <hwnd>\n"
            L"  close <hwnd>                  WM_CLOSE (polite)\n"
            L"  kill  <hwnd>                  WM_CLOSE + driver kkill if it survives\n"
            L"  hide  <hwnd>                  ShowWindow(SW_HIDE)\n"
            L"  show  <hwnd>                  ShowWindow(SW_SHOWNA)\n"
            L"  front <hwnd>                  set foreground (with attach-input bypass)\n"
            L"  topmost <hwnd> [off]          toggle WS_EX_TOPMOST\n"
            L"  zbid <hwnd> [band 0..18]      read or set the internal Z-band (above topmost)\n"
            L"  privacy <hwnd> [none|monitor|hide]\n"
            L"                                read or set screen-capture display affinity\n"
            L"  move  <hwnd> <x> <y> [w h]    reposition (and optionally resize)\n");
        return 1;
    }
    std::wstring_view sub = argv[0];
    int rest = argc - 1;
    wchar_t** ra = argv + 1;

    if (sub == L"list")    return CmdWinList(rest, ra);
    if (sub == L"info")    return CmdWinInfo(rest, ra);
    if (sub == L"close")   return CmdWinClose(rest, ra);
    if (sub == L"kill")    return CmdWinKill(rest, ra);
    if (sub == L"hide")    return rest >= 1 ? CmdWinShowHide(ra[0], SW_HIDE)   : (fwprintf(stderr, L"win hide <hwnd>\n"), 1);
    if (sub == L"show")    return rest >= 1 ? CmdWinShowHide(ra[0], SW_SHOWNA) : (fwprintf(stderr, L"win show <hwnd>\n"), 1);
    if (sub == L"front")   return CmdWinFront(rest, ra);
    if (sub == L"topmost") return CmdWinTopmost(rest, ra);
    if (sub == L"zbid")    return CmdWinZbid(rest, ra);
    if (sub == L"privacy") return CmdWinPrivacy(rest, ra);
    if (sub == L"move")    return CmdWinMove(rest, ra);

    fwprintf(stderr, L"win: unknown subcommand %s\n", argv[0]);
    return 1;
}

// tree -- ASCII parent/child process tree -------------------------------
//
// Walks EnumProcesses(), builds parent->children map, renders depth-first
// with box-drawing characters. Roots are PIDs whose ParentPid isn't itself
// in the list (System, services orphaned by their original parent, etc).

static void PrintTreeNode(uint32_t pid,
                          const std::unordered_map<uint32_t, const ProcessInfo*>& byPid,
                          const std::unordered_map<uint32_t, std::vector<uint32_t>>& kids,
                          const std::wstring& prefix, bool last) {
    auto pit = byPid.find(pid);
    const ProcessInfo* p = pit != byPid.end() ? pit->second : nullptr;
    const wchar_t* name = p ? p->imageName.c_str() : L"(gone)";
    wprintf(L"%s%s %u %s\n",
            prefix.c_str(),
            last ? L"└─" : L"├─",   // └─ or ├─
            pid, name);

    auto kit = kids.find(pid);
    if (kit == kids.end()) return;
    std::wstring childPrefix = prefix + (last ? L"   " : L"│  ");  // "│  "
    const auto& v = kit->second;
    for (size_t i = 0; i < v.size(); ++i) {
        PrintTreeNode(v[i], byPid, kids, childPrefix, i + 1 == v.size());
    }
}

// Unified process row so the tree builder doesn't care whether the rows
// came from the kernel (DriverSession::enumPids) or user-mode
// (NtQuerySystemInformation via EnumProcesses).
struct TreeRow {
    uint32_t pid       = 0;
    uint32_t parentPid = 0;
    std::wstring name;
};

int CmdTree(int argc, wchar_t** argv) {
    wclap::App app(L"winternal tree");
    app.about(L"ASCII process tree. Defaults to kernel-side PID enum (DKOM-resistant) "
              L"if Winternal.sys is loaded, falls back to user-mode NtQSI otherwise.")
       .arg(wclap::Arg(L"user").long_name(L"user").help(L"Force user-mode enum (skip driver)"));
    auto m = app.parse(argc, argv);

    std::vector<TreeRow> rows;
    bool usedDriver = false;

    if (!m.present(L"user")) {
        DriverSession s;
        if (s.open()) {
            Dbg(L"tree: using driver enumPids");
            auto kpids = s.enumPids();
            rows.reserve(kpids.size());
            for (auto& k : kpids) {
                TreeRow r{ k.pid, k.parentPid, {} };
                wchar_t wide[64]{};
                ::MultiByteToWideChar(CP_UTF8, 0, k.imageName.c_str(), -1, wide, 64);
                r.name = wide;
                rows.push_back(std::move(r));
            }
            usedDriver = true;
        }
    }

    if (rows.empty()) {
        Dbg(L"tree: using user-mode EnumProcesses");
        auto procs = EnumProcesses();
        rows.reserve(procs.size());
        for (auto& p : procs) rows.push_back({ p.pid, p.parentPid, p.imageName });
    }

    // Build parent->children map and find roots.
    std::unordered_map<uint32_t, const TreeRow*> byPid;
    std::unordered_map<uint32_t, std::vector<uint32_t>> kids;
    std::unordered_set<uint32_t> known;
    for (auto& r : rows) { byPid[r.pid] = &r; known.insert(r.pid); }
    for (auto& r : rows) kids[r.parentPid].push_back(r.pid);
    for (auto& v : kids) std::sort(v.second.begin(), v.second.end());

    std::vector<uint32_t> roots;
    for (auto& r : rows) {
        if (r.parentPid == 0 || !known.contains(r.parentPid)) roots.push_back(r.pid);
    }
    std::sort(roots.begin(), roots.end());

    // Adapter: PrintTreeNode wants byPid keyed to ProcessInfo*, which has
    // imageName. Reuse it by translating via a small lambda; cleaner than
    // duplicating the recursion.
    std::function<void(uint32_t, const std::wstring&, bool)> printNode =
        [&](uint32_t pid, const std::wstring& prefix, bool last) {
            auto it = byPid.find(pid);
            const wchar_t* name = (it != byPid.end()) ? it->second->name.c_str() : L"(gone)";
            wprintf(L"%ls%ls %u %ls\n",
                    prefix.c_str(), last ? L"\\-" : L"|-", pid, name);
            auto kit = kids.find(pid);
            if (kit == kids.end()) return;
            std::wstring childPrefix = prefix + (last ? L"   " : L"|  ");
            for (size_t i = 0; i < kit->second.size(); ++i) {
                printNode(kit->second[i], childPrefix, i + 1 == kit->second.size());
            }
        };

    Dbg(L"tree: %s, %zu rows, %zu roots",
        usedDriver ? L"kernel enum" : L"user-mode enum", rows.size(), roots.size());
    for (size_t i = 0; i < roots.size(); ++i) {
        printNode(roots[i], L"", i + 1 == roots.size());
    }
    return 0;
}

// threads <pid> -- list a process's threads with start address + state ---

struct ThreadRow {
    uint32_t tid = 0;
    uint64_t startAddr = 0;
    int32_t  priority = 0;
    uint32_t state = 0;
    uint32_t waitReason = 0;
    uint64_t createTimeFt = 0;
    uint64_t kernelTime100Ns = 0;
    uint64_t userTime100Ns = 0;
};

static const wchar_t* ThreadStateName(uint32_t s) {
    static const wchar_t* names[] = {
        L"Initialized", L"Ready", L"Running", L"Standby", L"Terminated",
        L"Waiting",     L"Transition", L"DeferredReady", L"GateWaitObsolete",
        L"WaitingForProcessInSwap"
    };
    return s < (sizeof(names) / sizeof(names[0])) ? names[s] : L"?";
}

static const wchar_t* WaitReasonName(uint32_t r) {
    static const wchar_t* names[] = {
        L"Executive", L"FreePage", L"PageIn", L"PoolAllocation", L"DelayExecution",
        L"Suspended", L"UserRequest", L"WrExecutive", L"WrFreePage", L"WrPageIn",
        L"WrPoolAllocation", L"WrDelayExecution", L"WrSuspended", L"WrUserRequest",
        L"WrEventPair", L"WrQueue", L"WrLpcReceive", L"WrLpcReply", L"WrVirtualMemory",
        L"WrPageOut", L"WrRendezvous", L"WrKeyedEvent", L"WrTerminated",
        L"WrProcessInSwap", L"WrCpuRateControl", L"WrCalloutStack", L"WrKernel",
        L"WrResource", L"WrPushLock", L"WrMutex", L"WrQuantumEnd", L"WrDispatchInt",
        L"WrPreempted", L"WrYieldExecution", L"WrFastMutex", L"WrGuardedMutex",
        L"WrRundown", L"WrAlertByThreadId", L"WrDeferredPreempt", L"WrPhysicalFault"
    };
    return r < (sizeof(names) / sizeof(names[0])) ? names[r] : L"?";
}

int CmdThreads(int argc, wchar_t** argv) {
    wclap::App app(L"winternal threads");
    app.about(L"List a process's threads via the driver (kernel-mode "
              L"ZwQuerySystemInformation — bypasses user-mode hooks).")
       .arg(wclap::Arg(L"pid").positional().required().help(L"Process ID"));
    auto m = app.parse(argc, argv);
    uint32_t pid = (uint32_t)*m.value_u64(L"pid");

    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    auto threads = s.enumThreads(pid);
    if (threads.empty()) { fwprintf(stderr, L"threads: no threads for pid %u\n", pid); return 1; }

    wprintf(L"%-6s %-18s %-10s %-26s %-4s %s\n",
            L"TID", L"StartAddr", L"State", L"WaitReason", L"Pri", L"CPU");
    for (auto& t : threads) {
        uint64_t cpuUs = (t.kernelTime100Ns + t.userTime100Ns) / 10;
        wprintf(L"%-6u 0x%016llx %-10s %-26s %-4d %.2fs\n",
                t.tid, (unsigned long long)t.startAddress,
                ThreadStateName(t.state), WaitReasonName(t.waitReason),
                t.priority, cpuUs / 1e6);
    }
    return 0;
}

// mem <pid> -- VirtualQueryEx walk -------------------------------------

static const wchar_t* ProtName(DWORD p) {
    p &= 0xFF;
    switch (p) {
    case PAGE_NOACCESS:          return L"---";
    case PAGE_READONLY:          return L"R--";
    case PAGE_READWRITE:         return L"RW-";
    case PAGE_WRITECOPY:         return L"RWC";
    case PAGE_EXECUTE:           return L"--X";
    case PAGE_EXECUTE_READ:      return L"R-X";
    case PAGE_EXECUTE_READWRITE: return L"RWX";
    case PAGE_EXECUTE_WRITECOPY: return L"RWX-C";
    }
    return L"?";
}

static const wchar_t* StateName(DWORD s) {
    switch (s) {
    case MEM_COMMIT:  return L"commit";
    case MEM_RESERVE: return L"reserve";
    case MEM_FREE:    return L"free";
    }
    return L"?";
}

static const wchar_t* TypeName(DWORD t) {
    switch (t) {
    case MEM_IMAGE:   return L"image";
    case MEM_MAPPED:  return L"mapped";
    case MEM_PRIVATE: return L"private";
    }
    return L"?";
}

int CmdMem(int argc, wchar_t** argv) {
    wclap::App app(L"winternal mem");
    app.about(L"VirtualQueryEx-equivalent walk via the driver (KeStackAttach + "
              L"ZwQueryVirtualMemory), so PPL/protected targets resolve too.")
       .arg(wclap::Arg(L"pid").positional().required().help(L"Process ID"))
       .arg(wclap::Arg(L"commit").long_name(L"commit").help(L"Show only committed regions"))
       .arg(wclap::Arg(L"exec").long_name(L"exec").help(L"Show only executable regions"));
    auto m = app.parse(argc, argv);
    uint32_t pid = (uint32_t)*m.value_u64(L"pid");
    bool commitOnly = m.present(L"commit");
    bool execOnly   = m.present(L"exec");

    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    bool truncated = false;
    auto regions = s.queryMemRegions(pid, &truncated);
    if (regions.empty()) { fwprintf(stderr, L"mem: no regions returned (pid %u alive?)\n", pid); return 1; }

    // Module path comes from user-mode GetMappedFileNameW — needs a handle.
    // Open one if we can; if it fails (PPL etc.) we leave module column blank.
    HandleGuard ph(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));

    wprintf(L"%-18s %-18s %-7s %-7s %-7s %s\n",
            L"Base", L"Size", L"State", L"Prot", L"Type", L"Module");
    uint64_t totalCommit = 0, totalReserve = 0, totalImage = 0;
    for (auto& r : regions) {
        bool show = true;
        if (commitOnly && r.state != MEM_COMMIT) show = false;
        if (execOnly && !(r.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) show = false;
        if (show) {
            wchar_t modName[MAX_PATH] = L"";
            if (ph.valid() && r.type == MEM_IMAGE) {
                ::GetMappedFileNameW(ph.get(), (LPVOID)(uintptr_t)r.baseAddress, modName, MAX_PATH);
            }
            wprintf(L"0x%016llx 0x%016llx %-7s %-7s %-7s %s\n",
                    (unsigned long long)r.baseAddress,
                    (unsigned long long)r.regionSize,
                    StateName(r.state),
                    r.state == MEM_COMMIT ? ProtName(r.protect) : L"-",
                    TypeName(r.type),
                    modName);
        }
        if (r.state == MEM_COMMIT)  totalCommit += r.regionSize;
        if (r.state == MEM_RESERVE) totalReserve += r.regionSize;
        if (r.type == MEM_IMAGE && r.state == MEM_COMMIT) totalImage += r.regionSize;
    }
    wprintf(L"\ntotal commit  = %llu MB\n", totalCommit / (1024ULL * 1024));
    wprintf(L"total reserve = %llu MB\n", totalReserve / (1024ULL * 1024));
    wprintf(L"image-mapped  = %llu MB\n", totalImage / (1024ULL * 1024));
    if (truncated) wprintf(L"\n[truncated at %d regions]\n", WINTERNAL_MAX_MEM_REGIONS);
    return 0;
}

// token <pid> -- token integrity / privileges / groups ---------------

static std::wstring SidToString(PSID sid) {
    wchar_t* str = nullptr;
    if (!::ConvertSidToStringSidW(sid, &str)) return L"<?>";
    std::wstring s = str;
    ::LocalFree(str);
    return s;
}

static std::wstring LookupSid(PSID sid) {
    wchar_t name[256] = {}, domain[256] = {};
    DWORD nLen = 256, dLen = 256;
    SID_NAME_USE use{};
    if (::LookupAccountSidW(nullptr, sid, name, &nLen, domain, &dLen, &use)) {
        std::wstring s;
        if (dLen) { s += domain; s += L"\\"; }
        s += name;
        return s;
    }
    return SidToString(sid);
}

static const wchar_t* IntegrityLabel(DWORD rid) {
    if (rid <  0x1000) return L"Untrusted";
    if (rid <  0x2000) return L"Low";
    if (rid <  0x3000) return L"Medium";
    if (rid <  0x3100) return L"Medium+";
    if (rid <  0x4000) return L"High";
    if (rid <  0x5000) return L"System";
    return L"Protected";
}

int CmdToken(int argc, wchar_t** argv) {
    wclap::App app(L"winternal token");
    app.about(L"Token user/integrity/privileges via driver "
              L"(ZwOpenProcessTokenEx + ZwQueryInformationToken in kernel).")
       .arg(wclap::Arg(L"pid").positional().required().help(L"Process ID"));
    auto m = app.parse(argc, argv);
    uint32_t pid = (uint32_t)*m.value_u64(L"pid");

    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    auto tk = s.queryTokenInfo(pid);
    if (!tk) { fwprintf(stderr, L"token: query failed (%lu)\n", ::GetLastError()); return 1; }

    // User SID resolution still needs LookupAccountSid (user-mode advapi32).
    if (!tk->userSid.empty()) {
        wprintf(L"user:        %s\n", LookupSid((PSID)tk->userSid.data()).c_str());
    }
    if (!tk->integritySid.empty()) {
        wprintf(L"integrity:   %s (rid=0x%04x)\n", IntegrityLabel(tk->integrityRid), tk->integrityRid);
    }
    const wchar_t* et = L"default";
    if (tk->elevationType == 2) et = L"full";
    else if (tk->elevationType == 3) et = L"limited";
    wprintf(L"elevated:    %s  type=%s\n", tk->elevated ? L"YES" : L"no", et);
    wprintf(L"UIAccess:    %s\n", tk->uiAccess ? L"yes" : L"no");
    wprintf(L"session:     %u\n", tk->sessionId);

    if (!tk->privileges.empty()) {
        wprintf(L"privileges:  %zu\n", tk->privileges.size());
        for (auto& p : tk->privileges) {
            LUID luid{ (DWORD)(p.luid & 0xFFFFFFFFu), (LONG)(p.luid >> 32) };
            wchar_t name[64] = {};
            DWORD nl = 64;
            ::LookupPrivilegeNameW(nullptr, &luid, name, &nl);
            const wchar_t* state = (p.attributes & SE_PRIVILEGE_ENABLED) ? L"on " :
                                   (p.attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? L"def" : L"off";
            wprintf(L"   [%s] %s\n", state, name);
        }
    }
    return 0;
}

// mitigations <pid> -- process mitigation policies ------------------

#ifndef ProcessDEPPolicy
#define ProcessDEPPolicy                      0
#define ProcessASLRPolicy                     1
#define ProcessDynamicCodePolicy              2
#define ProcessStrictHandleCheckPolicy        3
#define ProcessSystemCallDisablePolicy        4
#define ProcessMitigationOptionsMask          5
#define ProcessExtensionPointDisablePolicy    6
#define ProcessControlFlowGuardPolicy         7
#define ProcessSignaturePolicy                8
#define ProcessFontDisablePolicy              9
#define ProcessImageLoadPolicy               10
#define ProcessSystemCallFilterPolicy        11
#define ProcessPayloadRestrictionPolicy      12
#define ProcessChildProcessPolicy            13
#define ProcessSideChannelIsolationPolicy    14
#define ProcessUserShadowStackPolicy         15
#endif

int CmdMitigations(int argc, wchar_t** argv) {
    wclap::App app(L"winternal mitigations");
    app.about(L"Process mitigation policies via driver "
              L"(ZwQueryInformationProcess(ProcessMitigationPolicy) in kernel).")
       .arg(wclap::Arg(L"pid").positional().required().help(L"Process ID"));
    auto m = app.parse(argc, argv);
    uint32_t pid = (uint32_t)*m.value_u64(L"pid");

    static const wchar_t* kNames[] = {
        L"DEP", L"ASLR", L"DynamicCode", L"StrictHandle", L"SysCallDisable",
        L"<reserved>", L"ExtPointDis", L"CFG", L"Signature", L"FontDisable",
        L"ImageLoad", L"SysCallFilter", L"PayloadRest", L"ChildProcess",
        L"SideChannel", L"ShadowStack",
    };

    DriverSession s;
    if (!OpenDriverOrHint(s)) return 1;
    auto items = s.queryMitigations(pid);
    if (items.empty()) { fwprintf(stderr, L"mitigations: query failed (%lu)\n", ::GetLastError()); return 1; }
    for (auto& it : items) {
        const wchar_t* n = (it.policyId < (sizeof(kNames)/sizeof(kNames[0])))
                           ? kNames[it.policyId] : L"?";
        if (it.ntStatus == 0) {
            wprintf(L"%-16s 0x%llx\n", n, (unsigned long long)it.value);
        } else if (it.ntStatus == (int32_t)0xC000000DL /* STATUS_INVALID_PARAMETER */) {
            // policy not supported on this build — silently skip.
        } else {
            wprintf(L"%-16s <nt 0x%08x>\n", n, (unsigned int)it.ntStatus);
        }
    }
    return 0;
}

int CmdClose(int argc, wchar_t** argv) {
    if (argc < 2) { fwprintf(stderr, L"close: need <pid> <handle>\n"); return 1; }
    uint32_t pid = ParseUint(argv[0]);
    uint32_t hv = ParseUint(argv[1]);
    if (CloseHandleInProcess(pid, hv)) { wprintf(L"Closed handle 0x%x in pid %u\n", hv, pid); return 0; }
    fwprintf(stderr, L"Close failed: %S\n", FormatError(GetLastError()).c_str());
    return 1;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    // The Lua engine uses narrow stdio (fwrite/printf) which is incompatible
    // with _O_U8TEXT mode. Skip the wide-stdio init for the lua subcommand;
    // the console code page is still UTF-8 from any other Winternal invocation
    // on the same console, and Lua's print() emits UTF-8 bytes directly.
    // Capture a thread handle the ctrl-handler can target with
    // CancelSynchronousIo. DuplicateHandle promotes the pseudo-handle
    // (-2) into a real handle the other thread can safely use.
    ::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentThread(),
                      ::GetCurrentProcess(), &g_mainThread,
                      THREAD_TERMINATE | SYNCHRONIZE, FALSE, 0);
    ::SetConsoleCtrlHandler(WinternalCtrlHandler, TRUE);

    // Filter --debug out of argv up front so subcommands don't need to
    // know about it. Sets g_debug as a side effect.
    {
        int j = 1;
        for (int i = 1; i < argc; ++i) {
            if (wcscmp(argv[i], L"--debug") == 0) g_debug = true;
            else argv[j++] = argv[i];
        }
        argc = j;
    }

    bool isLua = (argc >= 2 && wcscmp(argv[1], L"lua") == 0);
    if (!isLua) InitOutput();
    else ::SetConsoleOutputCP(CP_UTF8);
    EnableDebugPrivilege();

    if (argc < 2) { PrintHelp(); return 0; }
    std::wstring_view cmd = argv[1];
    int sub = argc - 2;
    wchar_t** sa = argv + 2;
    Dbg(L"dispatch cmd=%s argc=%d", argv[1], argc);

    if (cmd == L"help" || cmd == L"-h" || cmd == L"--help") { PrintHelp(); return 0; }
    if (cmd == L"ps")      { CmdPs(sub, sa); return 0; }
    if (cmd == L"dlls")    { CmdDlls(sub, sa); return 0; }
    if (cmd == L"drivers") { CmdDrivers(); return 0; }
    if (cmd == L"svc")     { CmdSvc(sub, sa); return 0; }
    if (cmd == L"net")     { CmdNet(); return 0; }
    if (cmd == L"handles") { CmdHandles(sub, sa); return 0; }
    if (cmd == L"obj")     { CmdObj(sub, sa); return 0; }
    if (cmd == L"hooks")   { CmdHooks(sub, sa); return 0; }
    if (cmd == L"kill")    { return CmdKill(sub, sa); }
    if (cmd == L"suspend") { return CmdSuspend(sub, sa, false); }
    if (cmd == L"resume")  { return CmdSuspend(sub, sa, true); }
    if (cmd == L"close")   { return CmdClose(sub, sa); }
    if (cmd == L"kver")      { return CmdKver(); }
    if (cmd == L"kpids")     { return CmdKpids(); }
    if (cmd == L"kr")        { return CmdKread(sub, sa); }
    if (cmd == L"kw")        { return CmdKwrite(sub, sa); }
    if (cmd == L"ksym")      { return CmdKsym(sub, sa); }
    if (cmd == L"kalloc")    { return CmdKalloc(sub, sa); }
    if (cmd == L"kfree")     { return CmdKfree(sub, sa); }
    if (cmd == L"kcall")     { return CmdKcall(sub, sa); }
    if (cmd == L"unprotect") { return CmdUnprotect(sub, sa); }
    if (cmd == L"protect")   { return CmdProtect(sub, sa); }
    if (cmd == L"kkill")     { return CmdKkill(sub, sa); }
    if (cmd == L"ghost" || cmd == L"ghosts") { return CmdGhost(sub, sa); }
    if (cmd == L"win")       { return CmdWin(sub, sa); }
    if (cmd == L"tree")        { return CmdTree(sub, sa); }
    if (cmd == L"threads")     { return CmdThreads(sub, sa); }
    if (cmd == L"mem")         { return CmdMem(sub, sa); }
    if (cmd == L"token")       { return CmdToken(sub, sa); }
    if (cmd == L"mitigations") { return CmdMitigations(sub, sa); }
    if (cmd == L"callbacks") { return CmdCallbacks(sub, sa); }
    if (cmd == L"kdrivers")  { return CmdKdrivers(); }
    if (cmd == L"ssdt")      { return CmdSsdt(); }
    if (cmd == L"lua")       { extern int LuaMain(int, wchar_t**); return LuaMain(sub, sa); }
    if (cmd == L"install")   { return winternal::RunInstall(sub, sa); }
    if (cmd == L"uninstall") { return winternal::RunUninstall(); }
    if (cmd == L"status")    { return winternal::RunStatus(); }
    if (cmd == L"selftest")  { return winternal::RunSelftest(); }
    if (cmd == L"plugin" || cmd == L"plugins") { return winternal::plugins::RunPluginCommand(sub, sa); }
    if (cmd == L"drv")       { return winternal::RunDriverMgmt(sub, sa); }
    if (cmd == L"ntfs")      { return winternal::RunNtfsCommand(sub, sa); }

    fwprintf(stderr, L"Unknown command: %s\n", argv[1]);
    PrintHelp();
    return 1;
}
