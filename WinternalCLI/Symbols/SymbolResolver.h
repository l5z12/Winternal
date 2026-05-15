// SymbolResolver — DbgHelp wrapper used to find function offsets in any
// Win32 PE module by symbol name. The whole point is "patch-by-RVA on
// whatever build the target machine actually has", so we resolve at
// install time against the live system binary, not against hardcoded
// offsets from our build host.
//
// DbgHelp + symsrv handle the download and caching of the matching PDB
// from https://msdl.microsoft.com/download/symbols, keyed by the PE's
// CodeView GUID+age. That key is build-specific: a different Win11 24H2
// patch level produces a different PDB, and we automatically pick up
// the right one. Hence "the VM is different from our host" stops
// mattering for the locate step.
//
// Failures fall back to the existing export-table walk in the driver
// (which is build-agnostic but limited to exported symbols).

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace winternal {

struct SymbolRequest {
    std::string  symbolName;   // input: undecorated C name (e.g. "NtUserDestroyWindow")
    uint64_t     rva = 0;      // output: 0 means "not found, see error"
    std::wstring error;        // output: human-readable on failure
};

class SymbolResolver {
public:
    SymbolResolver();
    ~SymbolResolver();

    SymbolResolver(const SymbolResolver&)            = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;

    // Initialize DbgHelp. Empty symPath -> default
    //   srv*%LOCALAPPDATA%\Winternal\Symbols*https://msdl.microsoft.com/download/symbols
    // Honors %_NT_SYMBOL_PATH% if set (and symPath is empty).
    bool Initialize(const std::wstring& symPath = L"");

    // Resolve one symbol. Returns RVA, or 0 on failure (check LastError()).
    uint64_t Resolve(const std::wstring& imagePath, const std::string& symbolName);

    // Resolve many symbols in the same image. Loads the PDB once.
    void ResolveBulk(const std::wstring& imagePath, std::vector<SymbolRequest>& requests);

    std::wstring SymbolPath()     const { return symPath_; }
    std::wstring CacheDirectory() const;
    std::wstring LastError()      const { return lastError_; }

    // Recursive delete of the local PDB cache. Doesn't touch symsrv-on-disk
    // caches outside our CacheDirectory().
    bool ClearCache();

private:
    HANDLE        fakeProc_   = nullptr;  // opaque cookie for SymInitialize
    bool          initialized_ = false;
    std::wstring  symPath_;
    std::wstring  lastError_;

    bool ResolveImagePath(const std::wstring& in, std::wstring& out) const;
    uint64_t LoadModuleForSymbols(const std::wstring& fullPath);
};

}  // namespace winternal
