// Plugin loader implementation.
//
// Manifest parsing uses a dedicated Lua state. The plugin.lua file must
// return a single table; we read its fields back through the Lua C API.
// This keeps the manifest format expressive (Lua expressions, comments)
// without dragging in another parser.

#include "WinternalPlugins.h"
#include "WinternalCore.h"
#include "PluginAPI.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <cstdio>
#include <fstream>
#include <sstream>

using namespace winternal;
namespace fs = std::filesystem;

namespace winternal::plugins {

namespace {

const char* PluginTypeName(PluginType t) {
    switch (t) {
    case PluginType::LuaKernel: return "lua-kernel";
    case PluginType::LuaUser:   return "lua-user";
    case PluginType::Dll:       return "dll";
    }
    return "?";
}

std::optional<PluginType> ParsePluginType(std::string_view s) {
    if (s == "lua-kernel") return PluginType::LuaKernel;
    if (s == "lua-user")   return PluginType::LuaUser;
    if (s == "dll")        return PluginType::Dll;
    return std::nullopt;
}

std::string GetField(lua_State* L, const char* name, std::string def = {}) {
    lua_getfield(L, -1, name);
    std::string r = lua_isstring(L, -1) ? lua_tostring(L, -1) : def;
    lua_pop(L, 1);
    return r;
}

std::vector<std::string> GetStringArray(lua_State* L, const char* name) {
    std::vector<std::string> out;
    lua_getfield(L, -1, name);
    if (lua_istable(L, -1)) {
        size_t n = lua_rawlen(L, -1);
        for (size_t i = 1; i <= n; ++i) {
            lua_rawgeti(L, -1, (lua_Integer)i);
            if (lua_isstring(L, -1)) out.emplace_back(lua_tostring(L, -1));
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
    return out;
}

std::vector<Command> GetCommandArray(lua_State* L) {
    std::vector<Command> out;
    lua_getfield(L, -1, "commands");
    if (lua_istable(L, -1)) {
        size_t n = lua_rawlen(L, -1);
        for (size_t i = 1; i <= n; ++i) {
            lua_rawgeti(L, -1, (lua_Integer)i);
            if (lua_istable(L, -1)) {
                Command c;
                c.name        = GetField(L, "name");
                c.description = GetField(L, "description");
                if (!c.name.empty()) out.push_back(std::move(c));
            }
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
    return out;
}

bool LoadAndRunTable(lua_State* L, const fs::path& path) {
    std::string p = path.string();
    if (luaL_loadfile(L, p.c_str()) != LUA_OK) return false;
    if (lua_pcall(L, 0, 1, 0) != LUA_OK) return false;
    return lua_istable(L, -1);
}

} // namespace

Registry::Registry() {
    L_ = luaL_newstate();
    if (L_) luaL_openlibs((lua_State*)L_);
}

Registry::~Registry() {
    if (L_) lua_close((lua_State*)L_);
}

std::vector<fs::path> Registry::SearchDirs() {
    std::vector<fs::path> dirs;
    wchar_t exe[MAX_PATH];
    if (::GetModuleFileNameW(nullptr, exe, MAX_PATH)) {
        dirs.push_back(fs::path(exe).parent_path() / "plugins");
    }
    wchar_t* home = nullptr;
    size_t homeLen = 0;
    if (_wdupenv_s(&home, &homeLen, L"USERPROFILE") == 0 && home) {
        dirs.push_back(fs::path(home) / ".winternal" / "plugins");
        free(home);
    }
    return dirs;
}

fs::path Registry::StateFile_() {
    wchar_t* appData = nullptr;
    size_t n = 0;
    fs::path base;
    if (_wdupenv_s(&appData, &n, L"APPDATA") == 0 && appData) {
        base = fs::path(appData) / "Winternal";
        free(appData);
    } else {
        base = fs::current_path();
    }
    std::error_code ec;
    fs::create_directories(base, ec);
    return base / "plugins.lua";
}

bool Registry::parseManifest_(const fs::path& path, Manifest& out) {
    lua_State* L = (lua_State*)L_;
    lua_settop(L, 0);
    if (!LoadAndRunTable(L, path)) {
        const char* err = lua_tostring(L, -1);
        fprintf(stderr, "[plugin] %s: manifest error — %s\n", path.string().c_str(),
                err ? err : "no table returned");
        lua_settop(L, 0);
        return false;
    }

    out.directory    = path.parent_path();
    out.manifestPath = path;
    out.name         = GetField(L, "name");
    out.version      = GetField(L, "version", "0.0.0");
    out.description  = GetField(L, "description");
    out.entry        = GetField(L, "entry");
    auto typeStr     = GetField(L, "type");
    auto t           = ParsePluginType(typeStr);
    out.depends      = GetStringArray(L, "depends");
    out.commands     = GetCommandArray(L);
    out.enabled      = true;  // default; overridden by enableState

    lua_settop(L, 0);

    if (out.name.empty() || out.entry.empty() || !t) {
        fprintf(stderr, "[plugin] %s: missing required field (name=%s, entry=%s, type=%s)\n",
                path.string().c_str(),
                out.name.c_str(), out.entry.c_str(), typeStr.c_str());
        return false;
    }
    out.type = *t;
    return true;
}

void Registry::loadEnableState_() {
    fs::path p = StateFile_();
    std::error_code ec;
    if (!fs::exists(p, ec)) return;
    lua_State* L = (lua_State*)L_;
    lua_settop(L, 0);
    if (!LoadAndRunTable(L, p)) { lua_settop(L, 0); return; }
    lua_pushnil(L);
    while (lua_next(L, -2)) {
        if (lua_isstring(L, -2) && lua_istable(L, -1)) {
            std::string name = lua_tostring(L, -2);
            lua_getfield(L, -1, "enabled");
            enableState_[name] = (lua_toboolean(L, -1) != 0);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    lua_settop(L, 0);
}

void Registry::saveEnableState_() {
    std::ofstream o(StateFile_());
    if (!o) return;
    o << "-- Winternal plugin state. Auto-generated by `winternal plugin enable|disable`.\n";
    o << "return {\n";
    for (auto& kv : enableState_) {
        o << "    [\"" << kv.first << "\"] = { enabled = "
          << (kv.second ? "true" : "false") << " },\n";
    }
    o << "}\n";
}

void Registry::discover() {
    plugins_.clear();
    loadEnableState_();
    for (auto& dir : SearchDirs()) {
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) continue;
        for (auto& entry : fs::directory_iterator(dir, ec)) {
            if (!entry.is_directory()) continue;
            fs::path mf = entry.path() / "plugin.lua";
            if (!fs::is_regular_file(mf, ec)) continue;
            Manifest m;
            if (!parseManifest_(mf, m)) continue;
            auto it = enableState_.find(m.name);
            if (it != enableState_.end()) m.enabled = it->second;
            plugins_.push_back(std::move(m));
        }
    }
    // Stable order by name.
    std::sort(plugins_.begin(), plugins_.end(),
              [](auto& a, auto& b) { return a.name < b.name; });
}

const Manifest* Registry::find(std::string_view name) const {
    for (auto& m : plugins_) if (m.name == name) return &m;
    return nullptr;
}

bool Registry::setEnabled(std::string_view name, bool enabled) {
    auto* m = find(name);
    if (!m) return false;
    enableState_[std::string(name)] = enabled;
    saveEnableState_();
    return true;
}

// ---- Host-marker protocol ----

namespace {

const char kHostMarker[] = "[winternal-host]";

bool DecodeHex(std::string_view hex, std::string& out) {
    if (hex.size() % 2) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nyb(hex[i]), lo = nyb(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((char)((hi << 4) | lo));
    }
    return true;
}

// Returns true if line was a recognized directive; appends a status line
// to `actionsLog` describing what happened.
bool HandleHostDirective(std::string_view line, std::string& actionsLog) {
    // Strip leading whitespace and the marker prefix.
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    if (line.size() < sizeof(kHostMarker) - 1) return false;
    if (line.substr(0, sizeof(kHostMarker) - 1) != kHostMarker) return false;
    line.remove_prefix(sizeof(kHostMarker) - 1);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);

    auto next_token = [&]() -> std::string_view {
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
        size_t e = 0;
        while (e < line.size() && line[e] != ' ' && line[e] != '\t' && line[e] != '\r') ++e;
        std::string_view t = line.substr(0, e);
        line.remove_prefix(e);
        return t;
    };

    std::string_view verb = next_token();
    if (verb == "write_file") {
        std::string_view ph = next_token(), dh = next_token();
        std::string path, data;
        if (!DecodeHex(ph, path) || !DecodeHex(dh, data)) {
            actionsLog += "[host] write_file: bad hex encoding\n";
            return true;
        }
        std::error_code ec;
        fs::create_directories(fs::path(path).parent_path(), ec);
        FILE* f = nullptr;
        if (fopen_s(&f, path.c_str(), "wb") == 0 && f) {
            fwrite(data.data(), 1, data.size(), f);
            fclose(f);
            actionsLog += "[host] wrote " + std::to_string(data.size()) + " bytes to " + path + "\n";
        } else {
            actionsLog += "[host] write_file: could not open " + path + "\n";
        }
        return true;
    }
    if (verb == "delete_file") {
        std::string_view ph = next_token();
        std::string path;
        if (!DecodeHex(ph, path)) {
            actionsLog += "[host] delete_file: bad hex encoding\n";
            return true;
        }
        std::error_code ec;
        if (fs::remove(path, ec)) actionsLog += "[host] deleted " + path + "\n";
        else                      actionsLog += "[host] delete_file: " + path + " (not found / failed)\n";
        return true;
    }
    actionsLog += "[host] unknown directive: ";
    actionsLog.append(verb.data(), verb.size());
    actionsLog += "\n";
    return true;
}

} // namespace

void ProcessPluginOutput(std::string_view output, FILE* out, std::string& actionsLog) {
    size_t pos = 0;
    while (pos < output.size()) {
        size_t nl = output.find('\n', pos);
        size_t end = (nl == std::string_view::npos) ? output.size() : nl;
        std::string_view line = output.substr(pos, end - pos);
        if (!HandleHostDirective(line, actionsLog)) {
            fwrite(line.data(), 1, line.size(), out);
            if (nl != std::string_view::npos) fputc('\n', out);
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
}

// ---- CLI dispatcher ----

namespace {

int CmdPluginList(Registry& r) {
    if (r.plugins().empty()) {
        wprintf(L"No plugins found. Drop a folder into plugins/<name>/ with plugin.lua.\n");
        return 0;
    }
    wprintf(L"%-24s %-8s %-12s %-7s  %s\n", L"NAME", L"VER", L"TYPE", L"STATE", L"DESCRIPTION");
    for (auto& m : r.plugins()) {
        wchar_t buf[512];
        ::MultiByteToWideChar(CP_UTF8, 0, m.description.c_str(), -1, buf, 512);
        wprintf(L"%-24S %-8S %-12S %-7s  %s\n",
                m.name.c_str(), m.version.c_str(),
                PluginTypeName(m.type),
                m.enabled ? L"enabled" : L"disabled",
                buf);
    }
    return 0;
}

int CmdPluginInfo(Registry& r, const wchar_t* name) {
    char nameU8[256];
    ::WideCharToMultiByte(CP_UTF8, 0, name, -1, nameU8, sizeof(nameU8), nullptr, nullptr);
    const Manifest* m = r.find(nameU8);
    if (!m) { fwprintf(stderr, L"plugin: not found: %s\n", name); return 1; }
    wprintf(L"name:        %S\n", m->name.c_str());
    wprintf(L"version:     %S\n", m->version.c_str());
    wprintf(L"description: %S\n", m->description.c_str());
    wprintf(L"type:        %S\n", PluginTypeName(m->type));
    wprintf(L"directory:   %s\n", m->directory.wstring().c_str());
    wprintf(L"entry:       %S\n", m->entry.c_str());
    wprintf(L"state:       %s\n", m->enabled ? L"enabled" : L"disabled");
    if (!m->depends.empty()) {
        wprintf(L"depends:\n");
        for (auto& d : m->depends) wprintf(L"  - %S\n", d.c_str());
    }
    if (!m->commands.empty()) {
        wprintf(L"commands:\n");
        for (auto& c : m->commands) wprintf(L"  - %S: %S\n", c.name.c_str(), c.description.c_str());
    }
    return 0;
}

int CmdPluginEnable(Registry& r, const wchar_t* name, bool on) {
    char nameU8[256];
    ::WideCharToMultiByte(CP_UTF8, 0, name, -1, nameU8, sizeof(nameU8), nullptr, nullptr);
    if (!r.setEnabled(nameU8, on)) {
        fwprintf(stderr, L"plugin: not found: %s\n", name); return 1;
    }
    wprintf(L"plugin %s %s\n", name, on ? L"enabled" : L"disabled");
    return 0;
}

int CmdPluginRun(Registry& r, const wchar_t* name) {
    char nameU8[256];
    ::WideCharToMultiByte(CP_UTF8, 0, name, -1, nameU8, sizeof(nameU8), nullptr, nullptr);
    const Manifest* m = r.find(nameU8);
    if (!m) { fwprintf(stderr, L"plugin: not found: %s\n", name); return 1; }

    fs::path entryPath = m->directory / m->entry;
    if (m->type == PluginType::LuaKernel) {
        std::ifstream in(entryPath, std::ios::binary);
        if (!in) { fwprintf(stderr, L"plugin: cannot read %s\n", entryPath.wstring().c_str()); return 1; }
        std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        DriverSession ds;
        if (!ds.open()) {
            fwprintf(stderr, L"plugin: Winternal.sys not loaded (open failed: %lu)\n", ::GetLastError());
            return 1;
        }
        auto res = ds.luaExec(body);
        if (!res) {
            fwprintf(stderr, L"plugin: IOCTL_LUA_EXEC failed: %lu\n", ::GetLastError()); return 1;
        }
        std::string actions;
        if (!res->output.empty()) ProcessPluginOutput(res->output, stdout, actions);
        if (!actions.empty()) fwrite(actions.data(), 1, actions.size(), stdout);
        if (res->luaStatus != 0) {
            fwprintf(stderr, L"plugin: kernel lua status %d\n", res->luaStatus); return 1;
        }
        return 0;
    }
    fwprintf(stderr, L"plugin: type '%S' not yet runnable via `plugin run` (use winternal lua for user-mode plugins)\n",
             PluginTypeName(m->type));
    return 1;
}

} // namespace

int RunPluginCommand(int argc, wchar_t** argv) {
    Registry r;
    r.discover();

    if (argc < 1) {
        fwprintf(stderr, L"usage: winternal plugin <list|info|enable|disable|run> [name]\n");
        return 1;
    }
    std::wstring_view sub = argv[0];
    if (sub == L"list") return CmdPluginList(r);
    if (argc < 2) { fwprintf(stderr, L"plugin %s: missing name\n", argv[0]); return 1; }
    if (sub == L"info")     return CmdPluginInfo(r, argv[1]);
    if (sub == L"enable")   return CmdPluginEnable(r, argv[1], true);
    if (sub == L"disable")  return CmdPluginEnable(r, argv[1], false);
    if (sub == L"run")      return CmdPluginRun(r, argv[1]);
    fwprintf(stderr, L"plugin: unknown subcommand: %s\n", argv[0]);
    return 1;
}

// Called at `winternal lua` startup. Walks the registry, loads each enabled
// plugin per its type. Kernel-lua plugins go via the driver session; user-lua
// plugins dofile into the host lua_State; dll plugins LoadLibrary + Init.
int LoadEnabledPlugins(const PluginLoadContext& ctx) {
    Registry r;
    r.discover();
    int loaded = 0;
    for (auto& m : r.plugins()) {
        if (!m.enabled) continue;
        fs::path entryPath = m.directory / m.entry;

        if (m.type == PluginType::LuaUser) {
            lua_State* L = (lua_State*)ctx.lua_state;
            if (luaL_dofile(L, entryPath.string().c_str()) != LUA_OK) {
                fprintf(stderr, "[plugin:%s] %s\n", m.name.c_str(), lua_tostring(L, -1));
                lua_pop(L, 1);
                continue;
            }
            ++loaded;
        } else if (m.type == PluginType::LuaKernel) {
            DriverSession* ds = (DriverSession*)ctx.driver_session;
            if (!ds || !ds->isOpen()) {
                fprintf(stderr, "[plugin:%s] needs Winternal.sys loaded; skipped.\n", m.name.c_str());
                continue;
            }
            std::ifstream in(entryPath, std::ios::binary);
            if (!in) {
                fprintf(stderr, "[plugin:%s] cannot read %s\n", m.name.c_str(), entryPath.string().c_str());
                continue;
            }
            std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto res = ds->luaExec(body);
            if (!res) {
                fprintf(stderr, "[plugin:%s] IOCTL_LUA_EXEC failed (%lu)\n", m.name.c_str(), (unsigned long)::GetLastError());
                continue;
            }
            std::string actions;
            if (!res->output.empty()) ProcessPluginOutput(res->output, stderr, actions);
            if (!actions.empty()) fwrite(actions.data(), 1, actions.size(), stderr);
            if (res->luaStatus != 0) {
                fprintf(stderr, "[plugin:%s] kernel-Lua returned status %d\n", m.name.c_str(), res->luaStatus);
                continue;
            }
            ++loaded;
        } else if (m.type == PluginType::Dll) {
            HMODULE h = ::LoadLibraryW(entryPath.wstring().c_str());
            if (!h) {
                fprintf(stderr, "[plugin:%s] LoadLibrary failed (%lu)\n", m.name.c_str(), (unsigned long)::GetLastError());
                continue;
            }
            auto init = (WinternalPluginInit_t)::GetProcAddress(h, "WinternalPluginInit");
            if (!init) {
                fprintf(stderr, "[plugin:%s] missing WinternalPluginInit export\n", m.name.c_str());
                ::FreeLibrary(h); continue;
            }
            WinternalHost host{};
            host.versionMajor = WINTERNAL_HOST_VERSION_MAJOR;
            host.versionMinor = WINTERNAL_HOST_VERSION_MINOR;
            host.L = (lua_State*)ctx.lua_state;
            host.driver_session = ctx.driver_session;
            host.register_function = [](WinternalHost* h, const char* name, WinternalLuaCFunction fn) {
                lua_getglobal(h->L, "wn");
                lua_pushcfunction(h->L, (lua_CFunction)fn);
                lua_setfield(h->L, -2, name);
                lua_pop(h->L, 1);
            };
            host.log = [](WinternalHost*, const char* msg) {
                fprintf(stderr, "[plugin] %s\n", msg ? msg : "");
            };
            int rc = init(&host);
            if (rc != 0) {
                fprintf(stderr, "[plugin:%s] init returned %d\n", m.name.c_str(), rc);
                continue;
            }
            ++loaded;
        }
    }
    return loaded;
}

} // namespace winternal::plugins
