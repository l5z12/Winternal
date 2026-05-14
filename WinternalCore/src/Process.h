#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace winternal {

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    uint32_t sessionId = 0;
    uint32_t threadCount = 0;
    uint32_t handleCount = 0;
    uint64_t workingSet = 0;       // bytes
    uint64_t privateBytes = 0;
    uint64_t kernelTime100Ns = 0;
    uint64_t userTime100Ns = 0;
    uint64_t createTimeFt = 0;     // FILETIME
    std::wstring imageName;        // basename only
    std::wstring imagePath;        // full path on disk (best effort)
    std::wstring commandLine;      // best effort, may be empty
    std::wstring user;             // domain\user
    bool elevated = false;
    bool wow64 = false;
    bool secure = false;           // unusual rights / protected
    bool hidden = false;           // detected by cross-check
    std::wstring integrityLevel;
};

// Enumerate processes via NtQuerySystemInformation(SystemProcessInformation).
// Authoritative kernel view; covers processes that are hidden from
// CreateToolhelp32Snapshot user-mode hooks but still in the process list.
std::vector<ProcessInfo> EnumProcesses();

// Brute-force every PID via OpenProcess and report any PID that opens but is
// not present in the SystemProcessInformation list. PIDs are multiples of 4
// up to 0xFFFC.
std::vector<uint32_t> DetectHiddenPids(const std::vector<ProcessInfo>& visible);

bool TerminateProcessById(uint32_t pid, uint32_t exitCode = 1);
bool SuspendProcessById(uint32_t pid);
bool ResumeProcessById(uint32_t pid);

// Best-effort: fill commandLine, imagePath, user, elevated, integrity, wow64.
void EnrichProcess(ProcessInfo& p);

} // namespace winternal
