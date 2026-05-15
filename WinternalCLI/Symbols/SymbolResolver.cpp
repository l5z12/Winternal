#include "SymbolResolver.h"

#include <DbgHelp.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <ShellAPI.h>  // SHFileOperationW (excluded by WIN32_LEAN_AND_MEAN)

#include <sstream>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace winternal {

namespace {

std::wstring GetLocalAppDataDir() {
    PWSTR p = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p))) {
        std::wstring r = p;
        CoTaskMemFree(p);
        return r;
    }
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf, n) : std::wstring();
}

// CreateDirectoryW only makes the final leaf; build parents manually.
bool EnsureDir(const std::wstring& dir) {
    if (dir.empty()) return false;
    std::wstring p;
    for (size_t i = 0; i < dir.size(); ++i) {
        wchar_t c = dir[i];
        p += c;
        if ((c == L'\\' || c == L'/') && p.size() > 3) {
            CreateDirectoryW(p.c_str(), nullptr);
        }
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    DWORD attr = GetFileAttributesW(dir.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring W(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

}  // namespace

SymbolResolver::SymbolResolver() {
    // SymInitialize uses this handle purely as a key. Picking something
    // distinct keeps us from stomping on dbghelp state if another
    // component in the same process is also using it against
    // GetCurrentProcess().
    fakeProc_ = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xD86F00));
}

SymbolResolver::~SymbolResolver() {
    if (initialized_) SymCleanup(fakeProc_);
}

std::wstring SymbolResolver::CacheDirectory() const {
    auto base = GetLocalAppDataDir();
    return base.empty() ? std::wstring() : (base + L"\\Winternal\\Symbols");
}

bool SymbolResolver::Initialize(const std::wstring& symPath) {
    if (initialized_) return true;

    std::wstring path = symPath;
    if (path.empty()) {
        // Honor caller env first; this is the same convention windbg uses.
        wchar_t env[8192];
        DWORD n = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", env, _countof(env));
        if (n > 0 && n < _countof(env)) {
            path.assign(env, n);
        } else {
            auto cache = CacheDirectory();
            if (cache.empty()) {
                lastError_ = L"failed to locate %LOCALAPPDATA% for symbol cache";
                return false;
            }
            EnsureDir(cache);
            path = L"srv*" + cache + L"*https://msdl.microsoft.com/download/symbols";
        }
    }
    symPath_ = path;

    SymSetOptions(SYMOPT_AUTO_PUBLICS | SYMOPT_UNDNAME |
                  SYMOPT_DEFERRED_LOADS | SYMOPT_CASE_INSENSITIVE);

    if (!SymInitializeW(fakeProc_, path.c_str(), FALSE)) {
        std::wstringstream ss;
        ss << L"SymInitializeW failed: GetLastError=" << GetLastError();
        lastError_ = ss.str();
        return false;
    }
    initialized_ = true;
    return true;
}

bool SymbolResolver::ResolveImagePath(const std::wstring& in, std::wstring& out) const {
    if (PathIsRelativeW(in.c_str())) {
        wchar_t sys[MAX_PATH];
        UINT n = GetSystemDirectoryW(sys, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return false;
        out = std::wstring(sys, n) + L"\\" + in;
    } else {
        out = in;
    }
    return GetFileAttributesW(out.c_str()) != INVALID_FILE_ATTRIBUTES;
}

uint64_t SymbolResolver::LoadModuleForSymbols(const std::wstring& fullPath) {
    // Fake but recognizable base. We compute RVA = symAddr - base, so the
    // actual value doesn't matter as long as it's nonzero and consistent.
    constexpr DWORD64 kFakeBase = 0x10000000ULL;
    DWORD64 actual = SymLoadModuleExW(
        fakeProc_, nullptr, fullPath.c_str(), nullptr,
        kFakeBase, 0, nullptr, 0);
    if (!actual) {
        std::wstringstream ss;
        ss << L"SymLoadModuleExW failed for " << fullPath
           << L": GetLastError=" << GetLastError();
        lastError_ = ss.str();
    }
    return static_cast<uint64_t>(actual);
}

uint64_t SymbolResolver::Resolve(const std::wstring& imagePath, const std::string& symbolName) {
    if (!initialized_) { lastError_ = L"SymbolResolver not initialized"; return 0; }

    std::wstring full;
    if (!ResolveImagePath(imagePath, full)) {
        lastError_ = L"image file not found: " + imagePath;
        return 0;
    }
    uint64_t base = LoadModuleForSymbols(full);
    if (!base) return 0;

    union {
        SYMBOL_INFO info;
        char        pad[sizeof(SYMBOL_INFO) + MAX_SYM_NAME + 1];
    } sym;
    ZeroMemory(&sym, sizeof(sym));
    sym.info.SizeOfStruct = sizeof(SYMBOL_INFO);
    sym.info.MaxNameLen   = MAX_SYM_NAME;

    uint64_t rva = 0;
    if (SymFromName(fakeProc_, symbolName.c_str(), &sym.info)) {
        rva = static_cast<uint64_t>(sym.info.Address) - base;
        lastError_.clear();
    } else {
        std::wstringstream ss;
        ss << L"SymFromName(" << W(symbolName) << L") failed: GetLastError="
           << GetLastError();
        lastError_ = ss.str();
    }
    SymUnloadModule64(fakeProc_, base);
    return rva;
}

void SymbolResolver::ResolveBulk(const std::wstring& imagePath,
                                  std::vector<SymbolRequest>& reqs) {
    if (!initialized_) {
        for (auto& r : reqs) r.error = L"SymbolResolver not initialized";
        return;
    }
    std::wstring full;
    if (!ResolveImagePath(imagePath, full)) {
        std::wstring e = L"image file not found: " + imagePath;
        for (auto& r : reqs) r.error = e;
        return;
    }
    uint64_t base = LoadModuleForSymbols(full);
    if (!base) {
        for (auto& r : reqs) r.error = lastError_;
        return;
    }

    union {
        SYMBOL_INFO info;
        char        pad[sizeof(SYMBOL_INFO) + MAX_SYM_NAME + 1];
    } sym;
    for (auto& r : reqs) {
        ZeroMemory(&sym, sizeof(sym));
        sym.info.SizeOfStruct = sizeof(SYMBOL_INFO);
        sym.info.MaxNameLen   = MAX_SYM_NAME;
        if (SymFromName(fakeProc_, r.symbolName.c_str(), &sym.info)) {
            r.rva = static_cast<uint64_t>(sym.info.Address) - base;
        } else {
            std::wstringstream ss;
            ss << L"SymFromName(" << W(r.symbolName) << L") failed: GetLastError="
               << GetLastError();
            r.error = ss.str();
        }
    }
    SymUnloadModule64(fakeProc_, base);
}

bool SymbolResolver::ClearCache() {
    auto dir = CacheDirectory();
    if (dir.empty()) return false;
    // SHFileOperation needs a double-NUL-terminated source string.
    std::wstring buf = dir + L'\0';
    SHFILEOPSTRUCTW op = {};
    op.wFunc  = FO_DELETE;
    op.pFrom  = buf.c_str();
    op.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    return SHFileOperationW(&op) == 0;
}

}  // namespace winternal
