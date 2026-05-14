// Lua 5.4 scripting front-end for Winternal.
//
// All Winternal capabilities — user-mode enumeration helpers from
// WinternalCore plus the Winternal.sys IOCTLs — are exposed as a global
// `wn` table:
//
//   wn.ps()                              -> {pid, ppid, name, ...}
//   wn.dlls(pid)                         -> {{base, size, path}, ...}
//   wn.drivers()                         -> {{base, size, path}, ...}
//   wn.svc()                             -> {{name, displayName, state, pid}, ...}
//   wn.net()                             -> {{proto, local, remote, state, pid}, ...}
//   wn.handles([pid])                    -> {{pid, value, type, access, name}, ...}
//   wn.obj(path)                         -> {{type, name}, ...}
//   wn.hooks(pid)                        -> {{module, fn, expected, actual, in}, ...}
//   wn.kill(pid) / wn.suspend(pid) / wn.resume(pid)
//
//   wn.kver()                            -> {major, minor}
//   wn.kpids()                           -> {{pid, ppid, name}, ...}
//   wn.kread(addr, n)                    -> string (bytes)
//   wn.kwrite(addr, str)
//   wn.ksym(name)                        -> integer
//   wn.kalloc(size [, nonpaged=true])    -> integer
//   wn.kfree(addr)
//   wn.kcall(addr, a1, a2, a3, a4)       -> {ret, faulted}
//   wn.unprotect(pid [, newval [, off]]) -> {offset, prev}
//   wn.kkill(pid)                        -> bool
//   wn.callbacks(kind)                   -> {{routine, modBase, module}, ...}
//                                           kind = "process" | "image" | "thread"
//   wn.kdrivers()                        -> {{base, size, path}, ...}
//   wn.ssdt()                            -> {{index, routine, modBase, module}, ...}
//
// Generic Win32 FFI — anything LoadLibrary + GetProcAddress can reach:
//
//   wn.proc(module, name)                -> integer (function pointer)
//   wn.call(module, name, ...)           -> integer (return value, x64 ABI)
//                                           Up to 16 args; ints/pointers only.
//                                           Strings auto-marshal to char* (UTF-8);
//                                           tables {wstr=s} marshal to wide.
//   wn.alloc(size)                       -> integer (VirtualAlloc, RW)
//   wn.free(ptr)                         -> VirtualFree
//   wn.read(ptr, n)                      -> string (user-mode peek)
//   wn.write(ptr, str)                   -> user-mode poke
//   wn.wreadstr(ptr [, max])             -> string (UTF-8 from wide)
//   wn.cstr(str)                         -> integer (pointer to interned char*)
//   wn.wstr(str)                         -> integer (pointer to interned WCHAR*)
//   wn.lasterror()                       -> integer (GetLastError)
//
// Integers are Lua's native 64-bit type, so all kernel pointers round-trip.
// kread returns a Lua string (binary-safe); kwrite accepts strings or tables
// of integers.
//
// Usage:
//   winternal lua                         REPL
//   winternal lua script.lua [args...]   run a file (args end up in `arg`)
//   winternal lua -e "print(#wn.ps())"   one-liner

#include "WinternalCore.h"
#include "../Winternal/Public.h"
#include "Hook64.h"
#include "PluginAPI.h"
#include "WinternalPlugins.h"
#include <filesystem>
#include <fstream>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <string>
#include <vector>

using namespace winternal;

namespace {

// ---- error helpers ----
// Lua 5.4's lua_pushfstring (used by luaL_error) accepts a tiny subset of
// printf specifiers — no length modifiers (%lu / %llx) and no hex/unsigned
// conversions. Format anything fancier into a small stack buffer and feed it
// in via %s.
#define WN_FMTBUF char _fmtbuf[64]
#define WN_HEX64(v) (_snprintf_s(_fmtbuf, sizeof(_fmtbuf), _TRUNCATE, "0x%llx", (unsigned long long)(v)), _fmtbuf)
#define WN_DEC32(v) (_snprintf_s(_fmtbuf, sizeof(_fmtbuf), _TRUNCATE, "%lu",   (unsigned long)(v)),       _fmtbuf)

int Win32Err(lua_State* L, const char* what) {
    DWORD e = ::GetLastError();
    WN_FMTBUF;
    return luaL_error(L, "%s failed (Win32 %s)", what, WN_DEC32(e));
}

// On x64 Windows the calling convention is fixed: first 4 int/ptr args go in
// RCX/RDX/R8/R9, the rest spill to stack at [rsp+0x20+]. The callee picks up
// whichever it declared, so a "cast to N-arg function pointer and call"
// trampoline works for any non-float Windows API up to N args.
//
// We keep N at 16 — more than enough for every documented Win32 API.
//
using U64 = uint64_t;
// __stdcall is silently ignored on x64 but the type-system can still confuse
// /GS instrumentation when an SEH-wrapped indirect call crosses the boundary,
// causing spurious stack-cookie reports on shutdown. The x64 Microsoft ABI
// has a single calling convention anyway, so just use the plain type.
using FN0  = U64 (*)();
using FN1  = U64 (*)(U64);
using FN2  = U64 (*)(U64,U64);
using FN3  = U64 (*)(U64,U64,U64);
using FN4  = U64 (*)(U64,U64,U64,U64);
using FN5  = U64 (*)(U64,U64,U64,U64,U64);
using FN6  = U64 (*)(U64,U64,U64,U64,U64,U64);
using FN7  = U64 (*)(U64,U64,U64,U64,U64,U64,U64);
using FN8  = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64);
using FN9  = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN10 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN11 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN12 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN13 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN14 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN15 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);
using FN16 = U64 (*)(U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64,U64);

// SEH wrappers. These live in their own functions because MSVC (C2712) rejects
// __try in any function that owns C++ destructible locals. The wrappers
// strictly use POD types and an out-param.

static bool SehMemcpy(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool SehWStrLen(const wchar_t* p, size_t maxLen, size_t* outLen) {
    __try {
        size_t i = 0;
        while (i < maxLen && p[i]) ++i;
        *outLen = i;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

U64 CallNArgs(void* fn, int n, U64* a) {
    // __stdcall == __cdecl on x64 (only __vectorcall differs), so this is
    // the right convention for nearly every Win32 export. WINAPI macros
    // collapse to __stdcall and then to nothing on x64.
    switch (n) {
    case 0:  return ((FN0)fn)();
    case 1:  return ((FN1)fn)(a[0]);
    case 2:  return ((FN2)fn)(a[0],a[1]);
    case 3:  return ((FN3)fn)(a[0],a[1],a[2]);
    case 4:  return ((FN4)fn)(a[0],a[1],a[2],a[3]);
    case 5:  return ((FN5)fn)(a[0],a[1],a[2],a[3],a[4]);
    case 6:  return ((FN6)fn)(a[0],a[1],a[2],a[3],a[4],a[5]);
    case 7:  return ((FN7)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6]);
    case 8:  return ((FN8)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
    case 9:  return ((FN9)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]);
    case 10: return ((FN10)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9]);
    case 11: return ((FN11)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10]);
    case 12: return ((FN12)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11]);
    case 13: return ((FN13)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12]);
    case 14: return ((FN14)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12],a[13]);
    case 15: return ((FN15)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12],a[13],a[14]);
    case 16: return ((FN16)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15]);
    }
    return 0;
}

static bool SehCallN(void* fn, int n, U64* args, U64* outRet, DWORD* outCode) {
    __try {
        *outRet = CallNArgs(fn, n, args);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *outCode = GetExceptionCode();
        return false;
    }
}

// Resolve module + symbol -> function pointer. Caches LoadLibraryW handles
// in a static map for cheap repeat lookups.
void* ResolveProc(const wchar_t* moduleName, const char* fnName) {
    HMODULE m = ::GetModuleHandleW(moduleName);
    if (!m) m = ::LoadLibraryW(moduleName);
    if (!m) return nullptr;
    return reinterpret_cast<void*>(::GetProcAddress(m, fnName));
}

// Driver session shared by the whole process. Lazy open; reused across calls.
static DriverSession g_driver;

// Non-throwing accessor for code paths outside a Lua call (plugin loader).
DriverSession* GetDriverNoThrow() {
    if (!g_driver.isOpen()) g_driver.open();
    return &g_driver;
}

// Lua-context accessor. Raises a Lua error on failure.
DriverSession* GetDriver(lua_State* L) {
    if (!g_driver.isOpen()) {
        if (!g_driver.open()) {
            WN_FMTBUF;
            luaL_error(L, "Winternal driver is not loaded (open failed: %s). "
                          "Load Winternal.sys with sc.exe and try again.",
                       WN_DEC32(::GetLastError()));
            return nullptr;
        }
    }
    return &g_driver;
}

// ---- string conversions ----
std::wstring LuaToWide(lua_State* L, int idx) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, idx, &n);
    if (n == 0) return L"";
    int wlen = ::MultiByteToWideChar(CP_UTF8, 0, s, (int)n, nullptr, 0);
    std::wstring w(wlen, 0);
    ::MultiByteToWideChar(CP_UTF8, 0, s, (int)n, w.data(), wlen);
    return w;
}

void PushUtf8(lua_State* L, std::wstring_view w) {
    if (w.empty()) { lua_pushlstring(L, "", 0); return; }
    int u = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(u, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), u, nullptr, nullptr);
    lua_pushlstring(L, s.data(), s.size());
}

// table["key"] = value, helpers.
void TSetStr(lua_State* L, const char* k, std::string_view v)        { lua_pushlstring(L, v.data(), v.size()); lua_setfield(L, -2, k); }
void TSetWStr(lua_State* L, const char* k, std::wstring_view v)      { PushUtf8(L, v); lua_setfield(L, -2, k); }
void TSetInt(lua_State* L, const char* k, lua_Integer v)             { lua_pushinteger(L, v); lua_setfield(L, -2, k); }
void TSetBool(lua_State* L, const char* k, bool v)                   { lua_pushboolean(L, v); lua_setfield(L, -2, k); }
void TSetNum(lua_State* L, const char* k, lua_Number v)              { lua_pushnumber(L, v); lua_setfield(L, -2, k); }

// ---- user-mode bindings ----

int LuaPs(lua_State* L) {
    auto ps = EnumProcesses();
    lua_createtable(L, (int)ps.size(), 0);
    for (size_t i = 0; i < ps.size(); ++i) {
        lua_createtable(L, 0, 8);
        TSetInt(L, "pid", ps[i].pid);
        TSetInt(L, "ppid", ps[i].parentPid);
        TSetWStr(L, "name", ps[i].imageName);
        TSetInt(L, "threads", ps[i].threadCount);
        TSetInt(L, "handles", ps[i].handleCount);
        TSetInt(L, "session", ps[i].sessionId);
        TSetInt(L, "workingSet", (lua_Integer)ps[i].workingSet);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaDlls(lua_State* L) {
    uint32_t pid = (uint32_t)luaL_checkinteger(L, 1);
    auto mods = EnumProcessModules(pid);
    lua_createtable(L, (int)mods.size(), 0);
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_createtable(L, 0, 4);
        TSetInt(L, "base", (lua_Integer)mods[i].baseAddress);
        TSetInt(L, "size", mods[i].size);
        TSetWStr(L, "name", mods[i].name);
        TSetWStr(L, "path", mods[i].path);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaDrivers(lua_State* L) {
    auto mods = EnumKernelModules();
    lua_createtable(L, (int)mods.size(), 0);
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_createtable(L, 0, 3);
        TSetInt(L, "base", (lua_Integer)mods[i].imageBase);
        TSetInt(L, "size", mods[i].imageSize);
        TSetWStr(L, "path", mods[i].path);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaSvc(lua_State* L) {
    auto svcs = EnumServices();
    lua_createtable(L, (int)svcs.size(), 0);
    for (size_t i = 0; i < svcs.size(); ++i) {
        lua_createtable(L, 0, 6);
        TSetWStr(L, "name", svcs[i].name);
        TSetWStr(L, "displayName", svcs[i].displayName);
        TSetInt(L, "state", (int)svcs[i].state);
        TSetInt(L, "pid", svcs[i].pid);
        TSetInt(L, "type", (int)svcs[i].type);
        TSetBool(L, "kernel", svcs[i].kernel);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaNet(lua_State* L) {
    auto cs = EnumConnections();
    lua_createtable(L, (int)cs.size(), 0);
    for (size_t i = 0; i < cs.size(); ++i) {
        lua_createtable(L, 0, 6);
        TSetInt(L, "proto", (int)cs[i].proto);
        TSetWStr(L, "local", cs[i].local);
        TSetWStr(L, "remote", cs[i].remote);
        TSetWStr(L, "state", cs[i].stateName);
        TSetInt(L, "pid", cs[i].pid);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaHandles(lua_State* L) {
    uint32_t filter = 0;
    if (!lua_isnoneornil(L, 1)) filter = (uint32_t)luaL_checkinteger(L, 1);
    auto hs = EnumHandles(true);
    lua_newtable(L);
    int idx = 0;
    for (auto& h : hs) {
        if (filter && h.pid != filter) continue;
        lua_createtable(L, 0, 5);
        TSetInt(L, "pid", h.pid);
        TSetInt(L, "value", h.handleValue);
        TSetWStr(L, "type", h.typeName);
        TSetInt(L, "access", h.grantedAccess);
        TSetWStr(L, "name", h.name);
        lua_rawseti(L, -2, ++idx);
    }
    return 1;
}

int LuaObj(lua_State* L) {
    std::wstring p = LuaToWide(L, 1);
    auto es = ListObjectDir(p);
    lua_createtable(L, (int)es.size(), 0);
    for (size_t i = 0; i < es.size(); ++i) {
        lua_createtable(L, 0, 2);
        TSetWStr(L, "type", es[i].type);
        TSetWStr(L, "name", es[i].name);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaHooks(lua_State* L) {
    uint32_t pid = (uint32_t)luaL_checkinteger(L, 1);
    auto hs = ScanIatHooks(pid);
    lua_createtable(L, (int)hs.size(), 0);
    for (size_t i = 0; i < hs.size(); ++i) {
        lua_createtable(L, 0, 5);
        TSetWStr(L, "module", hs[i].victimModule);
        TSetWStr(L, "fn", hs[i].victimFunction);
        TSetInt(L, "expected", (lua_Integer)hs[i].expectedAddress);
        TSetInt(L, "actual", (lua_Integer)hs[i].actualAddress);
        TSetWStr(L, "in", hs[i].resolvedModule);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaKill(lua_State* L)    { lua_pushboolean(L, TerminateProcessById((uint32_t)luaL_checkinteger(L, 1))); return 1; }
int LuaSuspend(lua_State* L) { lua_pushboolean(L, SuspendProcessById((uint32_t)luaL_checkinteger(L, 1))); return 1; }
int LuaResume(lua_State* L)  { lua_pushboolean(L, ResumeProcessById((uint32_t)luaL_checkinteger(L, 1))); return 1; }

// ---- driver bindings ----

int LuaKver(lua_State* L) {
    auto v = GetDriver(L)->getVersion();
    if (!v) return Win32Err(L, "kver");
    lua_createtable(L, 0, 3);
    TSetInt(L, "major", v->major);
    TSetInt(L, "minor", v->minor);
    TSetInt(L, "buildTime", v->buildTime);
    return 1;
}

int LuaKpids(lua_State* L) {
    auto pids = GetDriver(L)->enumPids();
    lua_createtable(L, (int)pids.size(), 0);
    for (size_t i = 0; i < pids.size(); ++i) {
        lua_createtable(L, 0, 3);
        TSetInt(L, "pid", pids[i].pid);
        TSetInt(L, "ppid", pids[i].parentPid);
        TSetStr(L, "name", pids[i].imageName);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaKread(lua_State* L) {
    uint64_t addr = (uint64_t)luaL_checkinteger(L, 1);
    uint32_t len = (uint32_t)luaL_checkinteger(L, 2);
    auto data = GetDriver(L)->kread(addr, len);
    if (!data) return Win32Err(L, "kread");
    lua_pushlstring(L, reinterpret_cast<const char*>(data->data()), data->size());
    return 1;
}

int LuaKwrite(lua_State* L) {
    uint64_t addr = (uint64_t)luaL_checkinteger(L, 1);
    size_t n = 0;
    const char* s = luaL_checklstring(L, 2, &n);
    if (!GetDriver(L)->kwrite(addr, s, (uint32_t)n)) return Win32Err(L, "kwrite");
    return 0;
}

int LuaKsym(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    auto a = GetDriver(L)->ksym(name);
    if (!a) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)*a);
    return 1;
}

int LuaKalloc(lua_State* L) {
    uint32_t sz = (uint32_t)luaL_checkinteger(L, 1);
    bool np = true;
    if (!lua_isnoneornil(L, 2)) np = (lua_toboolean(L, 2) != 0);
    auto a = GetDriver(L)->kalloc(sz, 0, np);
    if (!a) return Win32Err(L, "kalloc");
    lua_pushinteger(L, (lua_Integer)*a);
    return 1;
}

int LuaKfree(lua_State* L) {
    if (!GetDriver(L)->kfree((uint64_t)luaL_checkinteger(L, 1))) return Win32Err(L, "kfree");
    return 0;
}

int LuaKcall(lua_State* L) {
    uint64_t addr = (uint64_t)luaL_checkinteger(L, 1);
    uint64_t a[4] = {0,0,0,0};
    for (int i = 0; i < 4; ++i) {
        if (!lua_isnoneornil(L, i + 2)) a[i] = (uint64_t)luaL_checkinteger(L, i + 2);
    }
    auto r = GetDriver(L)->kcall(addr, a[0], a[1], a[2], a[3]);
    if (!r) return Win32Err(L, "kcall");
    lua_createtable(L, 0, 2);
    TSetInt(L, "ret", (lua_Integer)r->returnValue);
    TSetBool(L, "faulted", r->faulted);
    return 1;
}

int LuaUnprotect(lua_State* L) {
    uint32_t pid = (uint32_t)luaL_checkinteger(L, 1);
    uint8_t nv = 0;
    uint32_t off = 0;
    if (!lua_isnoneornil(L, 2)) nv = (uint8_t)luaL_checkinteger(L, 2);
    if (!lua_isnoneornil(L, 3)) off = (uint32_t)luaL_checkinteger(L, 3);
    auto r = GetDriver(L)->unprotectProcess(pid, nv, off);
    if (!r) return Win32Err(L, "unprotect");
    lua_createtable(L, 0, 2);
    TSetInt(L, "offset", r->fieldOffsetUsed);
    TSetInt(L, "prev", r->prevValue);
    return 1;
}

int LuaKkill(lua_State* L) {
    lua_pushboolean(L, GetDriver(L)->killProcess((uint32_t)luaL_checkinteger(L, 1)));
    return 1;
}

int LuaCallbacks(lua_State* L) {
    const char* kindName = luaL_optstring(L, 1, "process");
    CallbackKind k = CallbackKind::Process;
    if (strcmp(kindName, "image") == 0) k = CallbackKind::Image;
    else if (strcmp(kindName, "thread") == 0) k = CallbackKind::Thread;
    auto cbs = GetDriver(L)->enumCallbacks(k);
    lua_createtable(L, (int)cbs.size(), 0);
    for (size_t i = 0; i < cbs.size(); ++i) {
        lua_createtable(L, 0, 3);
        TSetInt(L, "routine", (lua_Integer)cbs[i].routine);
        TSetInt(L, "modBase", (lua_Integer)cbs[i].moduleBase);
        TSetStr(L, "module", cbs[i].moduleName);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaKdrivers(lua_State* L) {
    auto ds = GetDriver(L)->enumKernelDrivers();
    lua_createtable(L, (int)ds.size(), 0);
    for (size_t i = 0; i < ds.size(); ++i) {
        lua_createtable(L, 0, 3);
        TSetInt(L, "base", (lua_Integer)ds[i].imageBase);
        TSetInt(L, "size", ds[i].imageSize);
        TSetStr(L, "path", ds[i].fullPath);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

int LuaSsdt(lua_State* L) {
    auto es = GetDriver(L)->enumSsdt();
    lua_createtable(L, (int)es.size(), 0);
    for (size_t i = 0; i < es.size(); ++i) {
        lua_createtable(L, 0, 4);
        TSetInt(L, "index", es[i].index);
        TSetInt(L, "routine", (lua_Integer)es[i].routine);
        TSetInt(L, "modBase", (lua_Integer)es[i].moduleBase);
        TSetStr(L, "module", es[i].moduleName);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

// ---- generic Win32 FFI ----

int LuaProc(lua_State* L) {
    std::wstring mod = LuaToWide(L, 1);
    const char* fn = luaL_checkstring(L, 2);
    void* p = ResolveProc(mod.c_str(), fn);
    if (!p) return Win32Err(L, "GetProcAddress");
    lua_pushinteger(L, (lua_Integer)(uintptr_t)p);
    return 1;
}

// Marshal one Lua arg into a U64 cell. Strings become char* pointers into
// pinned storage that lives until the call returns; tables of the form
// {wstr=s} marshal into WCHAR*; booleans become 0/1; integers/lightuserdata
// pass straight through.
//
// Storage for marshalled buffers is the `pins` vector — each entry owns
// the underlying allocation. RAII frees them after the call.
struct MarshalPin {
    std::string a;
    std::wstring w;
    void* ptr() {
        if (!w.empty() || (a.empty() && w.empty())) return (void*)w.c_str();
        return (void*)a.c_str();
    }
};

U64 MarshalArg(lua_State* L, int idx, std::vector<MarshalPin>& pins) {
    switch (lua_type(L, idx)) {
    case LUA_TNIL:
        return 0;
    case LUA_TBOOLEAN:
        return lua_toboolean(L, idx) ? 1 : 0;
    case LUA_TNUMBER:
        if (lua_isinteger(L, idx)) return (U64)(int64_t)lua_tointeger(L, idx);
        return (U64)(int64_t)lua_tonumber(L, idx);
    case LUA_TSTRING: {
        size_t n = 0;
        const char* s = lua_tolstring(L, idx, &n);
        // Pin: copy so caller can keep using the buffer even after Lua GCs the string.
        pins.push_back({});
        pins.back().a.assign(s, n);
        return (U64)(uintptr_t)pins.back().a.c_str();
    }
    case LUA_TLIGHTUSERDATA:
    case LUA_TUSERDATA:
        return (U64)(uintptr_t)lua_touserdata(L, idx);
    case LUA_TTABLE: {
        // {wstr="hello"}   -> wide string pointer
        // {ptr=N}          -> raw integer pointer
        // {int=N}          -> raw integer (no pointer-conversion)
        lua_getfield(L, idx, "wstr");
        if (!lua_isnil(L, -1)) {
            std::wstring w = LuaToWide(L, lua_absindex(L, -1));
            lua_pop(L, 1);
            pins.push_back({});
            pins.back().w = std::move(w);
            return (U64)(uintptr_t)pins.back().w.c_str();
        }
        lua_pop(L, 1);
        lua_getfield(L, idx, "ptr");
        if (!lua_isnil(L, -1)) {
            U64 v = (U64)luaL_checkinteger(L, lua_absindex(L, -1));
            lua_pop(L, 1);
            return v;
        }
        lua_pop(L, 1);
        lua_getfield(L, idx, "int");
        if (!lua_isnil(L, -1)) {
            U64 v = (U64)(int64_t)luaL_checkinteger(L, lua_absindex(L, -1));
            lua_pop(L, 1);
            return v;
        }
        lua_pop(L, 1);
        return 0;
    }
    }
    return 0;
}

int LuaCall(lua_State* L) {
    std::wstring mod = LuaToWide(L, 1);
    const char* fn = luaL_checkstring(L, 2);
    void* p = ResolveProc(mod.c_str(), fn);
    if (!p) return Win32Err(L, "GetProcAddress");

    int top = lua_gettop(L);
    int n = top - 2;
    if (n < 0) n = 0;
    if (n > 16) return luaL_error(L, "wn.call supports up to 16 args (got %d)", n);

    U64 args[16] = {0};
    std::vector<MarshalPin> pins;
    pins.reserve(n);
    for (int i = 0; i < n; ++i) args[i] = MarshalArg(L, 3 + i, pins);

    ::SetLastError(0);
    U64 ret = 0;
    DWORD seh = 0;
    bool ok = SehCallN(p, n, args, &ret, &seh);
    if (!ok) {
        WN_FMTBUF;
        return luaL_error(L, "wn.call: target raised SEH %s", WN_HEX64(seh));
    }
    lua_pushinteger(L, (lua_Integer)ret);
    return 1;
}

int LuaAlloc(lua_State* L) {
    size_t sz = (size_t)luaL_checkinteger(L, 1);
    void* p = ::VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return Win32Err(L, "VirtualAlloc");
    lua_pushinteger(L, (lua_Integer)(uintptr_t)p);
    return 1;
}

int LuaFree(lua_State* L) {
    void* p = (void*)(uintptr_t)luaL_checkinteger(L, 1);
    if (!::VirtualFree(p, 0, MEM_RELEASE)) return Win32Err(L, "VirtualFree");
    return 0;
}

int LuaRead(lua_State* L) {
    void* p = (void*)(uintptr_t)luaL_checkinteger(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    std::string buf(n, 0);
    if (!SehMemcpy(buf.data(), p, n)) {
        WN_FMTBUF;
        return luaL_error(L, "wn.read: access violation at %s", WN_HEX64((uintptr_t)p));
    }
    lua_pushlstring(L, buf.data(), buf.size());
    return 1;
}

int LuaWrite(lua_State* L) {
    void* p = (void*)(uintptr_t)luaL_checkinteger(L, 1);
    size_t n = 0;
    const char* s = luaL_checklstring(L, 2, &n);
    if (!SehMemcpy(p, s, n)) {
        WN_FMTBUF;
        return luaL_error(L, "wn.write: access violation at %s", WN_HEX64((uintptr_t)p));
    }
    return 0;
}

int LuaWReadStr(lua_State* L) {
    const wchar_t* p = (const wchar_t*)(uintptr_t)luaL_checkinteger(L, 1);
    size_t maxLen = (size_t)luaL_optinteger(L, 2, 4096);
    size_t len = 0;
    if (!SehWStrLen(p, maxLen, &len)) {
        WN_FMTBUF;
        return luaL_error(L, "wn.wreadstr: access violation at %s", WN_HEX64((uintptr_t)p));
    }
    PushUtf8(L, std::wstring_view(p, len));
    return 1;
}

// cstr / wstr return a pointer to a buffer that is GC-anchored on the Lua
// state via a hidden registry table — once the script drops references the
// buffer is freed at the next GC cycle. For tight loops, callers should
// reuse the pointer (it stays alive as long as the value is reachable).
int LuaPinUserdataGC(lua_State* L) {
    void** p = (void**)lua_touserdata(L, 1);
    if (p && *p) { ::HeapFree(::GetProcessHeap(), 0, *p); *p = nullptr; }
    return 0;
}

void* PinNewBuffer(lua_State* L, size_t n) {
    void** ud = (void**)lua_newuserdata(L, sizeof(void*));
    *ud = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    if (luaL_newmetatable(L, "winternal.pin")) {
        lua_pushcfunction(L, LuaPinUserdataGC);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    // Keep a strong reference in the registry's pin pool so the buffer
    // outlives the immediate caller; key is the pointer address.
    lua_pushlightuserdata(L, *ud);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    lua_pop(L, 1);  // pop userdata; registry still holds it
    return *ud;
}

int LuaCstr(lua_State* L) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, 1, &n);
    void* buf = PinNewBuffer(L, n + 1);
    if (!buf) return luaL_error(L, "wn.cstr: out of memory");
    memcpy(buf, s, n);
    lua_pushinteger(L, (lua_Integer)(uintptr_t)buf);
    return 1;
}

int LuaWstr(lua_State* L) {
    std::wstring w = LuaToWide(L, 1);
    size_t bytes = (w.size() + 1) * sizeof(wchar_t);
    void* buf = PinNewBuffer(L, bytes);
    if (!buf) return luaL_error(L, "wn.wstr: out of memory");
    memcpy(buf, w.data(), bytes);
    lua_pushinteger(L, (lua_Integer)(uintptr_t)buf);
    return 1;
}

int LuaLastError(lua_State* L) { lua_pushinteger(L, ::GetLastError()); return 1; }

// ---- user-mode inline hooks ----

int LuaHook(lua_State* L) {
    uintptr_t target = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t detour = (uintptr_t)luaL_checkinteger(L, 2);
    uint32_t  prologueSize = (uint32_t)luaL_optinteger(L, 3, 16);
    uintptr_t tramp = winternal::hook::Install(target, detour, prologueSize);
    if (!tramp) return Win32Err(L, "wn.hook");
    lua_pushinteger(L, (lua_Integer)tramp);
    return 1;
}

int LuaUnhook(lua_State* L) {
    if (!winternal::hook::Uninstall((uintptr_t)luaL_checkinteger(L, 1)))
        return Win32Err(L, "wn.unhook");
    return 0;
}

int LuaUnhookAll(lua_State* L) { winternal::hook::UninstallAll(); return 0; }

int LuaAllocExec(lua_State* L) {
    size_t sz = (size_t)luaL_checkinteger(L, 1);
    void* p = ::VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return Win32Err(L, "VirtualAlloc (RWX)");
    lua_pushinteger(L, (lua_Integer)(uintptr_t)p);
    return 1;
}

// ---- kernel-mode hooks (via driver) ----

int LuaKhook(lua_State* L) {
    uint64_t target = (uint64_t)luaL_checkinteger(L, 1);
    uint64_t detour = (uint64_t)luaL_checkinteger(L, 2);
    uint32_t prolog = (uint32_t)luaL_optinteger(L, 3, 16);
    auto t = GetDriver(L)->khookInstall(target, detour, prolog);
    if (!t) return Win32Err(L, "wn.khook");
    lua_pushinteger(L, (lua_Integer)*t);
    return 1;
}

int LuaKunhook(lua_State* L) {
    if (!GetDriver(L)->khookUninstall((uint64_t)luaL_checkinteger(L, 1)))
        return Win32Err(L, "wn.kunhook");
    return 0;
}

int LuaKunhookAll(lua_State* L) {
    if (!GetDriver(L)->khookUninstallAll()) return Win32Err(L, "wn.kunhook_all");
    return 0;
}

// ---- lockdown / audit ----

int LuaLockdownEngage(lua_State* L) {
    auto r = GetDriver(L)->lockdownEngage();
    if (!r) return Win32Err(L, "wn.lockdown_engage");
    lua_createtable(L, 0, 2);
    lua_pushboolean(L, r->engaged); lua_setfield(L, -2, "engaged");
    lua_pushinteger(L, r->engagedTickMs); lua_setfield(L, -2, "engagedTickMs");
    return 1;
}

int LuaLockdownStatus(lua_State* L) {
    auto r = GetDriver(L)->lockdownStatus();
    if (!r) return Win32Err(L, "wn.lockdown_status");
    lua_createtable(L, 0, 2);
    lua_pushboolean(L, r->engaged); lua_setfield(L, -2, "engaged");
    lua_pushinteger(L, r->engagedTickMs); lua_setfield(L, -2, "engagedTickMs");
    return 1;
}

// Kernel-side force-unload of another driver by short name.
int LuaForceUnload(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    if (!GetDriver(L)->forceUnloadDriver(name)) return Win32Err(L, "wn.drv_unload");
    lua_pushboolean(L, 1);
    return 1;
}

// Kernel-level service ops via Winternal.sys (Zw*Key + Zw*Driver).
int LuaKdrvRegister(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    std::wstring path = LuaToWide(L, 2);
    uint32_t start = (uint32_t)luaL_optinteger(L, 3, 3);
    if (!GetDriver(L)->kdrvRegister(name, path, start)) return Win32Err(L, "wn.kdrv_register");
    return 0;
}
int LuaKdrvDeregister(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    if (!GetDriver(L)->kdrvDeregister(name)) return Win32Err(L, "wn.kdrv_deregister");
    return 0;
}
int LuaKdrvLoad(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    if (!GetDriver(L)->kdrvLoad(name)) return Win32Err(L, "wn.kdrv_load");
    return 0;
}
int LuaKdrvUnload(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    if (!GetDriver(L)->kdrvUnload(name)) return Win32Err(L, "wn.kdrv_unload");
    return 0;
}
int LuaKdrvSetStart(lua_State* L) {
    std::wstring name = LuaToWide(L, 1);
    uint32_t start = (uint32_t)luaL_checkinteger(L, 2);
    if (!GetDriver(L)->kdrvSetStart(name, start)) return Win32Err(L, "wn.kdrv_set_start");
    return 0;
}

int LuaAuditTail(lua_State* L) {
    uint32_t max = (uint32_t)luaL_optinteger(L, 1, 256);
    auto rows = GetDriver(L)->auditTail(max);
    lua_createtable(L, (int)rows.size(), 0);
    for (size_t i = 0; i < rows.size(); ++i) {
        auto& r = rows[i];
        lua_createtable(L, 0, 6);
        lua_pushinteger(L, (lua_Integer)r.timestampNs); lua_setfield(L, -2, "timestampNs");
        lua_pushinteger(L, r.ioControlCode);           lua_setfield(L, -2, "ioctl");
        lua_pushinteger(L, r.callerPid);               lua_setfield(L, -2, "pid");
        lua_pushinteger(L, (lua_Integer)r.target);     lua_setfield(L, -2, "target");
        lua_pushinteger(L, r.length);                  lua_setfield(L, -2, "length");
        lua_pushinteger(L, r.status);                  lua_setfield(L, -2, "status");
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

// Ship a Lua script to the driver for kernel-mode execution. Returns the
// captured output (string) and the Lua status (integer, 0 on success).
int LuaKernelRun(lua_State* L) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, 1, &n);
    auto r = GetDriver(L)->luaExec(std::string_view(s, n));
    if (!r) return Win32Err(L, "wn.kernel_run");
    lua_pushlstring(L, r->output.data(), r->output.size());
    lua_pushinteger(L, r->luaStatus);
    return 2;
}

int LuaFlushIcache(lua_State* L) {
    void* p = (void*)(uintptr_t)luaL_checkinteger(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    ::FlushInstructionCache(::GetCurrentProcess(), p, n);
    return 0;
}

const luaL_Reg kBindings[] = {
    // user-mode
    {"ps",        LuaPs},
    {"dlls",      LuaDlls},
    {"drivers",   LuaDrivers},
    {"svc",       LuaSvc},
    {"net",       LuaNet},
    {"handles",   LuaHandles},
    {"obj",       LuaObj},
    {"hooks",     LuaHooks},
    {"kill",      LuaKill},
    {"suspend",   LuaSuspend},
    {"resume",    LuaResume},
    // driver
    {"kver",      LuaKver},
    {"kpids",     LuaKpids},
    {"kread",     LuaKread},
    {"kwrite",    LuaKwrite},
    {"ksym",      LuaKsym},
    {"kalloc",    LuaKalloc},
    {"kfree",     LuaKfree},
    {"kcall",     LuaKcall},
    {"unprotect", LuaUnprotect},
    {"kkill",     LuaKkill},
    {"callbacks", LuaCallbacks},
    {"kdrivers",  LuaKdrivers},
    {"ssdt",      LuaSsdt},
    // Win32 FFI
    {"proc",      LuaProc},
    {"call",      LuaCall},
    {"alloc",     LuaAlloc},
    {"free",      LuaFree},
    {"read",      LuaRead},
    {"write",     LuaWrite},
    {"wreadstr",  LuaWReadStr},
    {"cstr",      LuaCstr},
    {"wstr",      LuaWstr},
    {"lasterror", LuaLastError},
    // user-mode inline hooks
    {"hook",       LuaHook},
    {"unhook",     LuaUnhook},
    {"unhook_all", LuaUnhookAll},
    {"alloc_exec", LuaAllocExec},
    {"flush_icache", LuaFlushIcache},
    // kernel-mode hooks
    {"khook",        LuaKhook},
    {"kunhook",      LuaKunhook},
    {"kunhook_all",  LuaKunhookAll},
    // kernel-mode lua execution
    {"kernel_run",   LuaKernelRun},
    // lockdown / audit
    {"lockdown_engage", LuaLockdownEngage},
    {"lockdown_status", LuaLockdownStatus},
    {"audit_tail",      LuaAuditTail},
    {"drv_unload",        LuaForceUnload},
    {"kdrv_register",     LuaKdrvRegister},
    {"kdrv_deregister",   LuaKdrvDeregister},
    {"kdrv_load",         LuaKdrvLoad},
    {"kdrv_unload",       LuaKdrvUnload},
    {"kdrv_set_start",    LuaKdrvSetStart},
    {nullptr, nullptr},
};

// Generic SEH wrapper for every wn.* binding. A bogus pointer or a misbehaving
// Windows API can raise an access violation deep inside a binding; without this
// wrapper that would terminate the whole CLI process. Lua errors (luaL_error)
// use longjmp and propagate normally — they don't hit __except.
//
// Implementation detail: the actual call must be funneled through a function
// that owns no C++ destructible locals — MSVC's C2712 rule. InvokeWithSeh is
// noinline + POD-only and stays the SEH boundary for every binding.
__declspec(noinline)
static int InvokeWithSeh(lua_State* L, lua_CFunction fn, DWORD* outCode) {
    int r = 0;
    __try { r = fn(L); *outCode = 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { *outCode = GetExceptionCode(); }
    return r;
}

static int SehTrampoline(lua_State* L) {
    lua_CFunction inner = (lua_CFunction)lua_touserdata(L, lua_upvalueindex(1));
    const char* name    = lua_tostring(L, lua_upvalueindex(2));
    DWORD code = 0;
    int r = InvokeWithSeh(L, inner, &code);
    if (code) {
        WN_FMTBUF;
        return luaL_error(L, "%s: SEH %s", name ? name : "wn.?", WN_HEX64(code));
    }
    return r;
}

void Register(lua_State* L) {
    lua_newtable(L);
    for (const luaL_Reg* r = kBindings; r->name; ++r) {
        lua_pushlightuserdata(L, (void*)r->func);
        lua_pushstring(L, r->name);
        lua_pushcclosure(L, SehTrampoline, 2);
        lua_setfield(L, -2, r->name);
    }
    lua_setglobal(L, "wn");
}

// ---- Plugins ----
//
// All plugin discovery + load is now in WinternalPlugins.cpp. This thin
// wrapper bridges Lua startup into the registry — we pass the host's
// lua_State + (already-open) driver session so kernel-lua plugins can be
// shipped without re-opening the device.

static void LoadPlugins(lua_State* L) {
    winternal::plugins::PluginLoadContext ctx{};
    ctx.lua_state      = L;
    ctx.driver_session = GetDriverNoThrow();
    winternal::plugins::LoadEnabledPlugins(ctx);
}

void Report(lua_State* L, int rc) {
    if (rc != LUA_OK) {
        const char* m = lua_tostring(L, -1);
        fprintf(stderr, "lua: %s\n", m ? m : "(unknown error)");
        lua_pop(L, 1);
    }
}

int Repl(lua_State* L) {
    char line[4096];
    fprintf(stderr, "Winternal Lua %s.  globals: wn  (q to quit)\n", LUA_VERSION);
    for (;;) {
        fputs("> ", stderr);
        fflush(stderr);
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        if (n == 1 && (line[0] == 'q' || line[0] == 'Q')) break;
        if (n == 0) continue;

        // Try as an expression first ("=expr" or bare): wrap in `return ...`.
        std::string wrapped = std::string("return ") + line;
        int rc = luaL_loadbuffer(L, wrapped.data(), wrapped.size(), "=stdin");
        if (rc != LUA_OK) {
            lua_pop(L, 1);
            rc = luaL_loadbuffer(L, line, n, "=stdin");
        }
        if (rc != LUA_OK) { Report(L, rc); continue; }
        rc = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (rc != LUA_OK) { Report(L, rc); continue; }
        int top = lua_gettop(L);
        for (int i = 1; i <= top; ++i) {
            const char* s = luaL_tolstring(L, i, nullptr);
            fputs(s, stdout); fputc('\t', stdout);
            lua_pop(L, 1);
        }
        if (top) fputc('\n', stdout);
        lua_settop(L, 0);
    }
    return 0;
}

} // namespace

int LuaMain(int argc, wchar_t** argv) {
    lua_State* L = luaL_newstate();
    if (!L) { fprintf(stderr, "luaL_newstate failed\n"); return 1; }
    luaL_openlibs(L);
    Register(L);
    LoadPlugins(L);

    if (argc == 0) return Repl(L);

    // `-e "code"` form.
    if (wcscmp(argv[0], L"-e") == 0 && argc >= 2) {
        int u = ::WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, nullptr, 0, nullptr, nullptr);
        std::string s(u, 0);
        ::WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, s.data(), u, nullptr, nullptr);
        if (!s.empty() && s.back() == 0) s.pop_back();
        int rc = luaL_loadbuffer(L, s.data(), s.size(), "=(-e)");
        if (rc == LUA_OK) rc = lua_pcall(L, 0, 0, 0);
        if (rc != LUA_OK) { Report(L, rc); winternal::hook::UninstallAll(); lua_close(L); return 1; }
        lua_close(L);
        winternal::hook::UninstallAll();
        return 0;
    }

    // Run a script file. Remaining args become `arg`.
    int u = ::WideCharToMultiByte(CP_UTF8, 0, argv[0], -1, nullptr, 0, nullptr, nullptr);
    std::string path(u, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, argv[0], -1, path.data(), u, nullptr, nullptr);
    if (!path.empty() && path.back() == 0) path.pop_back();

    lua_createtable(L, argc - 1, 0);
    for (int i = 1; i < argc; ++i) {
        int wu = ::WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string a(wu, 0);
        ::WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, a.data(), wu, nullptr, nullptr);
        if (!a.empty() && a.back() == 0) a.pop_back();
        lua_pushlstring(L, a.data(), a.size());
        lua_rawseti(L, -2, i);
    }
    lua_setglobal(L, "arg");

    int rc = luaL_loadfile(L, path.c_str());
    if (rc == LUA_OK) rc = lua_pcall(L, 0, 0, 0);
    if (rc != LUA_OK) { Report(L, rc); winternal::hook::UninstallAll(); lua_close(L); return 1; }
    lua_close(L);
    winternal::hook::UninstallAll();
    return 0;
}
