// Minimal x64 user-mode inline hook engine for Winternal.
//
// Install: overwrite `prologueSize` bytes at `target` with a 14-byte absolute
// JMP `[rip+0] / <detour-address>` (padding nops to prologueSize). The
// original prologue bytes are copied into a separately-allocated executable
// trampoline buffer followed by a 14-byte JMP back to `target+prologueSize`,
// so the detour can call the trampoline to reach the original function.
//
// Caller is responsible for picking a prologueSize that's >= 14 and falls on
// an instruction boundary with no RIP-relative or branch instructions —
// otherwise the trampoline copy will be broken. The default prologueSize of
// 16 works on most Win32 APIs whose prologues start with sub rsp, imm /
// mov [rsp+...], rcx etc, but verify with a disassembler before trusting it.
//
// The engine does NOT detect or handle: SMP-safe atomic patching (use
// SuspendThread/FlushInstructionCache when needed), thread-stack mid-call
// inside the prologue (caller must ensure no thread is mid-prologue), or
// CFG bits (calls into the detour from inside a CFG-protected target may
// raise STATUS_STACK_BUFFER_OVERRUN if the detour wasn't registered as a
// valid call target).
//
#pragma once
#include <cstdint>
#include <optional>

namespace winternal::hook {

struct Hook {
    uintptr_t target;            // patched function address
    uintptr_t detour;            // address that target now jumps to
    uintptr_t trampoline;        // address to invoke the original function
    uint32_t  prologueSize;      // bytes overwritten at target
    uint8_t   savedBytes[64];    // original prologue (up to prologueSize)
};

// Install an inline hook. Returns the trampoline address on success (the
// detour can `call trampoline` to invoke the original). Returns 0 on failure
// (GetLastError holds the reason).
uintptr_t Install(uintptr_t target, uintptr_t detour, uint32_t prologueSize = 16);

// Uninstall a previously installed hook on `target`. Returns true on success.
bool Uninstall(uintptr_t target);

// Remove every hook installed by this process. Used at process shutdown so
// unhooking is deterministic even if a script panics.
void UninstallAll();

} // namespace winternal::hook
