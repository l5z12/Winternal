// Plugin discovery + lifecycle for Winternal.
//
// Layout (per plugin, in <exe-dir>/plugins/ and %USERPROFILE%/.winternal/plugins/):
//
//   plugins/
//     <name>/
//       plugin.lua          manifest: `return { name=..., version=..., type=..., entry=..., ... }`
//       main.lua            (or main.dll, etc.) — actual plugin body
//
// Manifest fields:
//
//   name           string (required)         — used for dependencies + state
//   version        string (required)         — semver-style "0.1.0"
//   description    string                    — single-line description
//   type           string (required)         — "lua-kernel" | "lua-user" | "dll"
//   entry          string (required)         — relative path to body file
//   depends        { string, ... }          — other plugin names that must load first
//   commands       { { name=, description= }, ... }
//                                            — subcommands the plugin registers
//
// Persistent enable/disable state lives in:
//   %APPDATA%/Winternal/plugins.lua          — returns a table { [name] = { enabled = bool } }
//
// API the rest of the CLI uses is `PluginRegistry`. It owns the lua_State
// used to parse manifests (independent of the user's `wn` Lua state).
//
#pragma once
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace winternal::plugins {

enum class PluginType { LuaKernel, LuaUser, Dll };

struct Command {
    std::string name;
    std::string description;
};

struct Manifest {
    std::string name;
    std::string version;
    std::string description;
    PluginType  type;
    std::string entry;                 // relative to plugin directory
    std::vector<std::string> depends;
    std::vector<Command>     commands;

    std::filesystem::path    directory;     // absolute
    std::filesystem::path    manifestPath;  // absolute
    bool                     enabled;       // from persistent state
};

class Registry {
public:
    Registry();
    ~Registry();

    // Walk all search paths and parse plugin.lua manifests. Skips plugins
    // with manifest errors but reports them. Resolves enable/disable state
    // from %APPDATA%/Winternal/plugins.lua.
    void discover();

    const std::vector<Manifest>& plugins() const { return plugins_; }
    const Manifest* find(std::string_view name) const;

    // Mutate persistent enable state. Writes back %APPDATA%/Winternal/plugins.lua.
    bool setEnabled(std::string_view name, bool enabled);

    // Search paths (created on first use if missing).
    static std::vector<std::filesystem::path> SearchDirs();

private:
    void* L_;  // lua_State*, hidden so the public header doesn't pull in lua.h
    std::vector<Manifest> plugins_;
    std::unordered_map<std::string, bool> enableState_;

    bool parseManifest_(const std::filesystem::path& manifestPath, Manifest& out);
    void loadEnableState_();
    void saveEnableState_();
    static std::filesystem::path StateFile_();
};

// CLI sub-dispatcher: handles `winternal plugin <subcmd> [args]`.
int RunPluginCommand(int argc, wchar_t** argv);

// Host-marker protocol — kernel-side Lua plugins emit lines like
//
//     [winternal-host] write_file <path-hex> <data-hex>
//     [winternal-host] delete_file <path-hex>
//
// (hex-encoded so paths/bytes round-trip without escape issues). The
// runner consumes those lines, performs the file operation, and replaces
// them with a short status. Other output passes through unchanged.
//
// This is how kernel-Lua plugins persist state across runs: they have
// fopen/fread (Zw*-backed) but no write side, so they print what they
// want saved and the user-mode runner does the write.
//
// ProcessPluginOutput writes filtered output to `out`; `actions` reports
// each performed host action (one line per success/failure) — usually
// printed after the plugin's own output for clarity.
void ProcessPluginOutput(std::string_view output, FILE* out, std::string& actionsLog);

// Load enabled plugins at process startup. Called from LuaMain. The
// argument is the user's Lua state (so dll plugins can register into it);
// kernel-lua plugins are shipped through the driver if it's reachable.
struct PluginLoadContext {
    void* lua_state;                     // lua_State*
    void* driver_session;                // DriverSession*
};
int LoadEnabledPlugins(const PluginLoadContext& ctx);

} // namespace winternal::plugins
