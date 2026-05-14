// Winternal native plugin ABI.
//
// Native plugins are loaded by `winternal lua` from <exe-dir>/plugins/*.dll
// (and %USERPROFILE%/.winternal/plugins/*.dll). The plugin must export:
//
//     int WinternalPluginInit(WinternalHost* host);
//
// returning 0 on success or a non-zero error code on failure. Plugins can:
//   * register additional Lua functions in the global `wn` table via
//     host->register_function(host, "name", fn)
//   * read driver state via host->driver_session (opaque pointer to
//     winternal::DriverSession*)
//   * write log lines via host->log(host, "msg")
//
// The host pointer remains valid until process exit. Plugins should NOT
// FreeLibrary themselves — the host owns the DLL lifetime.
//
// ABI is C-style and stable within a single major version. Bump
// WINTERNAL_HOST_VERSION_MAJOR if the layout changes.

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WINTERNAL_HOST_VERSION_MAJOR 1
#define WINTERNAL_HOST_VERSION_MINOR 0

struct lua_State;
typedef int (*WinternalLuaCFunction)(struct lua_State*);

typedef struct WinternalHost {
    uint32_t versionMajor;
    uint32_t versionMinor;
    struct lua_State* L;
    void* driver_session;        // opaque -> winternal::DriverSession*

    // Register a C function as wn.<name>. The function uses the standard
    // Lua C API (lua.h must be included by the plugin to match).
    void (*register_function)(struct WinternalHost* host, const char* name, WinternalLuaCFunction fn);

    // Emit a host-side log line. Prefixed with the plugin file name.
    void (*log)(struct WinternalHost* host, const char* msg);
} WinternalHost;

// Required entry point. Returns 0 on success.
typedef int (*WinternalPluginInit_t)(WinternalHost* host);

#ifdef __cplusplus
}
#endif
