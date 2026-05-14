// Kernel-side overlay header for embedded Lua.
//
// Force-included before every Lua source compiles via /FI in
// Winternal.vcxproj. The strategy is:
//
//   * Replace Lua's three IO macros (writestring / writeline /
//     writestringerror) with capture-buffer writes so anything Lua wants
//     to print ends up in the per-call output buffer the IOCTL returns.
//   * No-op lua_assert.
//   * Stub localeconv() to give Lua a "." decimal point.
//
// We do NOT modify the Lua sources themselves so a future version bump is
// a drop-in copy from WinternalCLI/lua/src/.
#pragma once

#ifdef _KERNEL_MODE

// lua_assert -> no-op. Lua's internal sanity checks are a runtime cost we
// don't want in the kernel hot path.
#define lua_assert(x)            ((void)0)

// Lua's default I/O macros want stdout/stderr + fwrite/fprintf, neither of
// which we expose in kernel mode. Override to route through our buffer.
// lauxlib.h defines these as a fallback if not already defined — but it also
// defines them unconditionally a few lines later, so we must #undef first
// after each include. Easier: define before lauxlib.h sees them. The forced
// include here happens before lauxlib.h's own definitions.
#undef lua_writestring
#undef lua_writeline
#undef lua_writestringerror
#define lua_writestring(s,l)     klua_print_n((s), (l))
#define lua_writeline()          klua_print_n("\n", 1)
#define lua_writestringerror(fmt, p) klua_printf((fmt), (p))

// The kernel CRT's <locale.h> declares its own struct lconv + localeconv();
// we used to override here but it collided with C2011. Trust the CRT stub
// instead — Lua only reads the decimal_point field and a kernel locale
// returning "C" is fine.

#ifdef __cplusplus
extern "C" {
#endif

// Capture-buffer API used by the kernel-side print/error path.
void klua_print_n(const char* s, size_t n);
void klua_printf(const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // _KERNEL_MODE
