#include "Process.h"
#include "NtApi.h"
#include "Util.h"
#include <vector>
#include <unordered_set>
#include <sddl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

using namespace winternal::nt;

namespace winternal {

static std::wstring GetIntegrityLevelString(HANDLE token) {
    DWORD cb = 0;
    ::GetTokenInformation(token, ::TokenIntegrityLevel, nullptr, 0, &cb);
    if (cb == 0) return L"";
    std::vector<BYTE> buf(cb);
    if (!::GetTokenInformation(token, ::TokenIntegrityLevel, buf.data(), cb, &cb)) return L"";
    auto* mil = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    DWORD rid = *::GetSidSubAuthority(mil->Label.Sid, (DWORD)(UCHAR)(*::GetSidSubAuthorityCount(mil->Label.Sid) - 1));
    switch (rid) {
        case SECURITY_MANDATORY_UNTRUSTED_RID: return L"Untrusted";
        case SECURITY_MANDATORY_LOW_RID:       return L"Low";
        case SECURITY_MANDATORY_MEDIUM_RID:    return L"Medium";
        case SECURITY_MANDATORY_HIGH_RID:      return L"High";
        case SECURITY_MANDATORY_SYSTEM_RID:    return L"System";
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return L"Protected";
        default:                               return L"Unknown";
    }
}

static std::wstring GetTokenUserString(HANDLE token) {
    DWORD cb = 0;
    ::GetTokenInformation(token, ::TokenUser, nullptr, 0, &cb);
    if (cb == 0) return L"";
    std::vector<BYTE> buf(cb);
    if (!::GetTokenInformation(token, ::TokenUser, buf.data(), cb, &cb)) return L"";
    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    wchar_t name[256], domain[256];
    DWORD nlen = 256, dlen = 256;
    SID_NAME_USE u;
    if (::LookupAccountSidW(nullptr, tu->User.Sid, name, &nlen, domain, &dlen, &u)) {
        std::wstring out;
        if (dlen > 0) { out.append(domain, dlen); out += L"\\"; }
        out.append(name, nlen);
        return out;
    }
    return L"";
}

void EnrichProcess(ProcessInfo& p) {
    HandleGuard h(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, p.pid));
    if (!h.valid()) {
        h.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
    }
    if (!h.valid()) return;

    if (auto path = ImagePathFromHandle(h.get())) p.imagePath = *path;

    BOOL wow = FALSE;
    if (::IsWow64Process(h.get(), &wow)) p.wow64 = !!wow;

    HANDLE tok = nullptr;
    if (::OpenProcessToken(h.get(), TOKEN_QUERY, &tok)) {
        p.integrityLevel = GetIntegrityLevelString(tok);
        p.user = GetTokenUserString(tok);
        TOKEN_ELEVATION te{};
        DWORD cb = 0;
        if (::GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb)) {
            p.elevated = te.TokenIsElevated != 0;
        }
        ::CloseHandle(tok);
    }

    // CommandLine via PEB read.
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG ret = 0;
    if (NT_SUCCESS(NtQueryInformationProcess(h.get(), ProcessBasicInformationClass, &pbi, sizeof(pbi), &ret)) && pbi.PebBaseAddress) {
        struct PebSlim { BYTE pad1[0x20]; PVOID ProcessParameters; };
        PebSlim peb{};
        SIZE_T r = 0;
        if (::ReadProcessMemory(h.get(), pbi.PebBaseAddress, &peb, sizeof(peb), &r) && peb.ProcessParameters) {
            // RTL_USER_PROCESS_PARAMETERS: CommandLine UNICODE_STRING is at offset 0x70 on x64.
            // (Microsoft documents this layout in winternl.h via RTL_USER_PROCESS_PARAMETERS.)
            RTL_USER_PROCESS_PARAMETERS upp{};
            if (::ReadProcessMemory(h.get(), peb.ProcessParameters, &upp, sizeof(upp), &r)) {
                if (upp.CommandLine.Length && upp.CommandLine.Buffer) {
                    std::wstring cmd(upp.CommandLine.Length / 2, L'\0');
                    if (::ReadProcessMemory(h.get(), upp.CommandLine.Buffer, cmd.data(), upp.CommandLine.Length, &r)) {
                        p.commandLine = std::move(cmd);
                    }
                }
            }
        }
    }
}

std::vector<ProcessInfo> EnumProcesses() {
    std::vector<BYTE> buf(256 * 1024);
    ULONG needed = 0;
    NTSTATUS s = kStatusInfoLengthMismatch;
    while (true) {
        s = NtQuerySystemInformation(SystemProcessInformationClass, buf.data(), (ULONG)buf.size(), &needed);
        if (s == 0) break;
        if (s == kStatusInfoLengthMismatch || (ULONG)buf.size() < needed) {
            buf.resize((needed ? needed : buf.size()) * 2);
            continue;
        }
        return {};
    }

    std::vector<ProcessInfo> out;
    BYTE* p = buf.data();
    while (true) {
        auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_X*>(p);
        ProcessInfo pi{};
        pi.pid = (uint32_t)(uintptr_t)spi->UniqueProcessId;
        pi.parentPid = (uint32_t)(uintptr_t)spi->InheritedFromUniqueProcessId;
        pi.sessionId = spi->SessionId;
        pi.threadCount = spi->NumberOfThreads;
        pi.handleCount = spi->HandleCount;
        pi.workingSet = spi->WorkingSetSize;
        pi.privateBytes = spi->PrivatePageCount;
        pi.kernelTime100Ns = (uint64_t)spi->KernelTime.QuadPart;
        pi.userTime100Ns = (uint64_t)spi->UserTime.QuadPart;
        pi.createTimeFt = (uint64_t)spi->CreateTime.QuadPart;
        if (spi->ImageName.Length && spi->ImageName.Buffer) {
            pi.imageName.assign(spi->ImageName.Buffer, spi->ImageName.Length / 2);
        } else if (pi.pid == 0) {
            pi.imageName = L"[System Idle Process]";
        } else if (pi.pid == 4) {
            pi.imageName = L"System";
        }
        out.push_back(std::move(pi));
        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
    return out;
}

std::vector<uint32_t> DetectHiddenPids(const std::vector<ProcessInfo>& visible) {
    std::unordered_set<uint32_t> known;
    known.reserve(visible.size());
    for (auto& p : visible) known.insert(p.pid);

    std::vector<uint32_t> hidden;
    // PIDs are quad-aligned.
    for (uint32_t pid = 4; pid < 0x10000; pid += 4) {
        if (known.contains(pid)) continue;
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            hidden.push_back(pid);
            ::CloseHandle(h);
        }
    }
    return hidden;
}

bool TerminateProcessById(uint32_t pid, uint32_t exitCode) {
    HandleGuard h(::OpenProcess(PROCESS_TERMINATE, FALSE, pid));
    if (!h.valid()) return false;
    return ::TerminateProcess(h.get(), exitCode) != 0;
}

bool SuspendProcessById(uint32_t pid) {
    HandleGuard h(::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid));
    if (!h.valid()) return false;
    return NT_SUCCESS(NtSuspendProcess(h.get()));
}

bool ResumeProcessById(uint32_t pid) {
    HandleGuard h(::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid));
    if (!h.valid()) return false;
    return NT_SUCCESS(NtResumeProcess(h.get()));
}

// ---- aggressive termination helpers ----

namespace {

// Wait briefly for a process to actually exit. Returns true if the
// process is gone within the timeout. Lets the caller distinguish
// "syscall succeeded" from "process actually died" — important because
// DUPLICATE_CLOSE_SOURCE can succeed without the target ever crashing
// (it only crashes when a load-bearing handle gets closed).
bool WaitProcessGone(uint32_t pid, uint32_t timeoutMs) {
    HandleGuard h(::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h.valid()) {
        // OpenProcess failing with ERROR_INVALID_PARAMETER usually means
        // the PID is already gone (no EPROCESS).
        DWORD e = ::GetLastError();
        return (e == ERROR_INVALID_PARAMETER);
    }
    DWORD r = ::WaitForSingleObject(h.get(), timeoutMs);
    return r == WAIT_OBJECT_0;
}

// Walk every handle in the system, find ones owned by `pid`, and yank
// them out using DuplicateHandle(..., DUPLICATE_CLOSE_SOURCE). This is
// the trick Win11 Task Manager's End Task uses when direct termination
// is denied. Requires PROCESS_DUP_HANDLE on the target — if our protect
// rule stripped that bit, this path is dead.
bool YankAllHandles(uint32_t pid) {
    HandleGuard self(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, ::GetCurrentProcessId()));
    if (!self.valid()) return false;

    HandleGuard target(::OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!target.valid()) return false;

    // SystemExtendedHandleInformation returns the full Ex layout we
    // already have a struct for in NtApi.h. Bigger than the legacy
    // SystemHandleInformation (8-byte fields) but easier to parse.
    std::vector<uint8_t> buf(0x40000);
    ULONG ret = 0;
    NTSTATUS s = (NTSTATUS)0xC0000004u;  // STATUS_INFO_LENGTH_MISMATCH
    for (int i = 0; i < 6 && s == (NTSTATUS)0xC0000004u; ++i) {
        s = NtQuerySystemInformation(SystemExtendedHandleInformationClass,
                                     buf.data(), (ULONG)buf.size(), &ret);
        if (s == (NTSTATUS)0xC0000004u) buf.resize((size_t)ret + 0x10000);
    }
    if (!NT_SUCCESS(s)) return false;

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX_X*>(buf.data());
    bool any = false;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        if ((uint32_t)e.UniqueProcessId != pid) continue;
        HANDLE out = nullptr;
        if (::DuplicateHandle(target.get(),
                              (HANDLE)(ULONG_PTR)e.HandleValue,
                              self.get(), &out, 0, FALSE,
                              DUPLICATE_CLOSE_SOURCE)) {
            if (out) ::CloseHandle(out);
            any = true;
        }
    }
    return any;
}

// Enumerate threads of `pid` via NtQuerySystemInformation(SystemProcess
// InformationClass) — the same buffer EnumProcesses already uses — and
// open + terminate each. Once every thread is dead the process tears
// down. Requires THREAD_TERMINATE on each thread (stripped by pattern
// protect rules, so this also dead-ends against a real Winternal rule).
bool TerminateAllThreads(uint32_t pid) {
    std::vector<uint8_t> buf(0x40000);
    ULONG needed = 0;
    NTSTATUS s = (NTSTATUS)0xC0000004u;  // STATUS_INFO_LENGTH_MISMATCH
    for (int i = 0; i < 6 && s == (NTSTATUS)0xC0000004u; ++i) {
        s = NtQuerySystemInformation(SystemProcessInformationClass,
                                     buf.data(), (ULONG)buf.size(), &needed);
        if (s == (NTSTATUS)0xC0000004u) buf.resize((size_t)needed + 0x10000);
    }
    if (!NT_SUCCESS(s)) return false;

    bool any = false;
    uint8_t* p = buf.data();
    while (true) {
        auto* pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_X*>(p);
        if ((uint32_t)(ULONG_PTR)pi->UniqueProcessId == pid) {
            auto* th = reinterpret_cast<SYSTEM_THREAD_INFORMATION_X*>(pi + 1);
            for (ULONG i = 0; i < pi->NumberOfThreads; ++i) {
                uint32_t tid = (uint32_t)(ULONG_PTR)th[i].ClientId.UniqueThread;
                HandleGuard h(::OpenThread(THREAD_TERMINATE, FALSE, tid));
                if (h.valid() && ::TerminateThread(h.get(), 1)) any = true;
            }
            break;
        }
        if (!pi->NextEntryOffset) break;
        p += pi->NextEntryOffset;
    }
    return any;
}

} // anonymous

KillMethod TerminateProcessByIdAggressive(uint32_t pid, uint32_t exitCode) {
    // 1) The cheap path. Works when nothing is stripping PROCESS_TERMINATE.
    {
        HandleGuard h(::OpenProcess(PROCESS_TERMINATE, FALSE, pid));
        if (h.valid() && ::TerminateProcess(h.get(), exitCode)) {
            (void)WaitProcessGone(pid, 250);
            return KillMethod::Terminate;
        }
    }

    // 2) Yank handles -- Task Manager's fallback.
    if (YankAllHandles(pid)) {
        if (WaitProcessGone(pid, 500)) return KillMethod::HandleDupClose;
        // The yank succeeded for some handles but the process is still
        // limping along — keep escalating rather than reporting success.
    }

    // 3) Per-thread terminate. If the protect rule strips THREAD_TERMINATE
    // too (it does), this fails too — but for unprotected processes that
    // somehow refuse direct TerminateProcess (rare), it's still useful.
    if (TerminateAllThreads(pid)) {
        if (WaitProcessGone(pid, 500)) return KillMethod::ThreadTerminate;
    }

    return KillMethod::Failed;
}

const wchar_t* KillMethodName(KillMethod m) {
    switch (m) {
    case KillMethod::Terminate:       return L"TerminateProcess";
    case KillMethod::HandleDupClose:  return L"DuplicateHandle/CLOSE_SOURCE";
    case KillMethod::ThreadTerminate: return L"per-thread TerminateThread";
    case KillMethod::Failed:
    default:                          return L"failed";
    }
}

} // namespace winternal
