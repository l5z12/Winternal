#include "Hook64.h"
#include <Windows.h>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace winternal::hook {

namespace {

// Encoding of an absolute jmp via RIP-relative load:
//   FF 25 00 00 00 00      jmp qword ptr [rip+0]
//   <8 bytes: target>
// Total 14 bytes. Position-independent and trivial to install.
constexpr size_t kJmpAbsoluteSize = 14;

void WriteJmpAbsolute(uint8_t* dst, uintptr_t to) {
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0; dst[3] = 0; dst[4] = 0; dst[5] = 0;
    std::memcpy(dst + 6, &to, 8);
}

std::mutex& Registry_mutex() { static std::mutex m; return m; }
std::unordered_map<uintptr_t, Hook>& Registry() {
    static std::unordered_map<uintptr_t, Hook> r; return r;
}

bool MakeWritable(void* p, size_t n, DWORD* oldProtect) {
    return ::VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, oldProtect) != 0;
}

void RestoreProtect(void* p, size_t n, DWORD oldProtect) {
    DWORD ignored;
    ::VirtualProtect(p, n, oldProtect, &ignored);
    ::FlushInstructionCache(::GetCurrentProcess(), p, n);
}

} // namespace

uintptr_t Install(uintptr_t target, uintptr_t detour, uint32_t prologueSize) {
    if (!target || !detour) { ::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (prologueSize < kJmpAbsoluteSize || prologueSize > sizeof(Hook{}.savedBytes)) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    std::lock_guard<std::mutex> lock(Registry_mutex());
    if (Registry().count(target)) { ::SetLastError(ERROR_ALREADY_EXISTS); return 0; }

    // Allocate a trampoline near the target so jumps back are easy. We use
    // 14-byte absolute jumps so reachability isn't required, but RWX pages
    // are still nice to have local. Two pages worth: 8K is plenty for the
    // saved prologue + the jump-back.
    void* tramp = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return 0;  // GetLastError already set

    // Trampoline layout:
    //   <saved prologue bytes>
    //   FF 25 00 00 00 00
    //   <target + prologueSize>
    std::memcpy(tramp, (void*)target, prologueSize);
    WriteJmpAbsolute(static_cast<uint8_t*>(tramp) + prologueSize, target + prologueSize);
    ::FlushInstructionCache(::GetCurrentProcess(), tramp, prologueSize + kJmpAbsoluteSize);

    // Patch target. NOP-fill any bytes past the jmp so a disassembler doesn't
    // get confused reading the leftover prologue tail.
    DWORD oldProtect = 0;
    if (!MakeWritable((void*)target, prologueSize, &oldProtect)) {
        DWORD err = ::GetLastError();
        ::VirtualFree(tramp, 0, MEM_RELEASE);
        ::SetLastError(err);
        return 0;
    }

    Hook h{};
    h.target = target;
    h.detour = detour;
    h.trampoline = (uintptr_t)tramp;
    h.prologueSize = prologueSize;
    std::memcpy(h.savedBytes, (void*)target, prologueSize);

    uint8_t* tp = (uint8_t*)target;
    WriteJmpAbsolute(tp, detour);
    for (uint32_t i = kJmpAbsoluteSize; i < prologueSize; ++i) tp[i] = 0x90;  // NOP fill

    RestoreProtect((void*)target, prologueSize, oldProtect);

    Registry().emplace(target, h);
    return (uintptr_t)tramp;
}

bool Uninstall(uintptr_t target) {
    std::lock_guard<std::mutex> lock(Registry_mutex());
    auto it = Registry().find(target);
    if (it == Registry().end()) { ::SetLastError(ERROR_NOT_FOUND); return false; }

    Hook& h = it->second;
    DWORD oldProtect = 0;
    if (!MakeWritable((void*)h.target, h.prologueSize, &oldProtect)) return false;
    std::memcpy((void*)h.target, h.savedBytes, h.prologueSize);
    RestoreProtect((void*)h.target, h.prologueSize, oldProtect);

    ::VirtualFree((void*)h.trampoline, 0, MEM_RELEASE);
    Registry().erase(it);
    return true;
}

void UninstallAll() {
    std::lock_guard<std::mutex> lock(Registry_mutex());
    for (auto& [_, h] : Registry()) {
        DWORD oldProtect = 0;
        if (MakeWritable((void*)h.target, h.prologueSize, &oldProtect)) {
            std::memcpy((void*)h.target, h.savedBytes, h.prologueSize);
            RestoreProtect((void*)h.target, h.prologueSize, oldProtect);
        }
        ::VirtualFree((void*)h.trampoline, 0, MEM_RELEASE);
    }
    Registry().clear();
}

} // namespace winternal::hook
