#include "Hook.h"
#include "Module.h"
#include "Util.h"
#include <Windows.h>
#define PSAPI_VERSION 1
#include <psapi.h>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "psapi.lib")

namespace winternal {

namespace {

struct ModRange {
    uintptr_t base = 0;
    uintptr_t end = 0;
    std::wstring name;
    std::wstring path;
};

// Load a PE file from disk into memory and return a span. We map the raw bytes
// (not the loaded image), since we only need parsing of headers / export tables.
struct FileImage {
    std::vector<BYTE> bytes;
    bool valid = false;
    PIMAGE_NT_HEADERS nt = nullptr;
};

static FileImage LoadFileImage(const std::wstring& path) {
    FileImage fi{};
    std::ifstream f(path, std::ios::binary);
    if (!f) return fi;
    f.seekg(0, std::ios::end);
    auto sz = f.tellg();
    if (sz <= 0) return fi;
    f.seekg(0, std::ios::beg);
    fi.bytes.resize((size_t)sz);
    if (!f.read(reinterpret_cast<char*>(fi.bytes.data()), sz)) return fi;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(fi.bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return fi;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fi.bytes.size()) return fi;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(fi.bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return fi;
    fi.nt = nt;
    fi.valid = true;
    return fi;
}

// Convert a relative virtual address to a file offset using section table.
static uint32_t RvaToFileOffset(const IMAGE_NT_HEADERS* nt, uint32_t rva) {
    auto* sec = IMAGE_FIRST_SECTION(const_cast<PIMAGE_NT_HEADERS>(nt));
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            return rva - sec->VirtualAddress + sec->PointerToRawData;
        }
    }
    return 0;
}

struct ExportEntry {
    std::string name;
    uint32_t rva = 0;
    bool isForwarder = false;
};

static std::vector<ExportEntry> ParseExports(const FileImage& fi) {
    std::vector<ExportEntry> out;
    if (!fi.valid) return out;
    const auto& dir = fi.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) return out;
    const BYTE* base = fi.bytes.data();
    uint32_t off = RvaToFileOffset(fi.nt, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_EXPORT_DIRECTORY) > fi.bytes.size()) return out;
    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + off);
    uint32_t namesOff = RvaToFileOffset(fi.nt, exp->AddressOfNames);
    uint32_t funcsOff = RvaToFileOffset(fi.nt, exp->AddressOfFunctions);
    uint32_t ordOff = RvaToFileOffset(fi.nt, exp->AddressOfNameOrdinals);
    if (!namesOff || !funcsOff || !ordOff) return out;
    auto* names = reinterpret_cast<const DWORD*>(base + namesOff);
    auto* funcs = reinterpret_cast<const DWORD*>(base + funcsOff);
    auto* ords  = reinterpret_cast<const WORD*>(base + ordOff);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        uint32_t noff = RvaToFileOffset(fi.nt, names[i]);
        if (!noff) continue;
        ExportEntry ee;
        ee.name = std::string(reinterpret_cast<const char*>(base + noff));
        WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions) continue;
        ee.rva = funcs[ord];
        ee.isForwarder = (ee.rva >= dir.VirtualAddress && ee.rva < dir.VirtualAddress + dir.Size);
        out.push_back(std::move(ee));
    }
    return out;
}

static std::vector<ModRange> SnapshotModules(uint32_t pid, HANDLE phandle, std::unordered_map<std::wstring, ModRange>& byName) {
    std::vector<ModRange> ranges;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(phandle, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return ranges;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    for (DWORD i = 0; i < count; ++i) {
        ModRange r{};
        r.base = (uintptr_t)mods[i];
        MODULEINFO mi{};
        if (::GetModuleInformation(phandle, mods[i], &mi, sizeof(mi))) {
            r.end = r.base + mi.SizeOfImage;
        }
        wchar_t buf[1024];
        if (::GetModuleFileNameExW(phandle, mods[i], buf, 1024)) {
            r.path = buf;
            auto pos = r.path.find_last_of(L'\\');
            r.name = (pos == std::wstring::npos) ? r.path : r.path.substr(pos + 1);
            std::wstring lower = r.name;
            for (auto& c : lower) c = (wchar_t)::towlower(c);
            byName[lower] = r;
        }
        ranges.push_back(std::move(r));
    }
    return ranges;
}

const ModRange* FindRange(const std::vector<ModRange>& ranges, uintptr_t addr) {
    for (auto& r : ranges) {
        if (addr >= r.base && addr < r.end) return &r;
    }
    return nullptr;
}

} // namespace

std::vector<HookInfo> ScanIatHooks(uint32_t pid) {
    std::vector<HookInfo> out;
    HandleGuard ph(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!ph.valid()) return out;

    std::unordered_map<std::wstring, ModRange> byName;
    auto ranges = SnapshotModules(pid, ph.get(), byName);

    for (auto& r : ranges) {
        FileImage fi = LoadFileImage(r.path);
        if (!fi.valid) continue;
        auto& imp = fi.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp.Size == 0) continue;
        uint32_t off = RvaToFileOffset(fi.nt, imp.VirtualAddress);
        if (!off) continue;
        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(fi.bytes.data() + off);
        for (; desc->Name; ++desc) {
            uint32_t nameOff = RvaToFileOffset(fi.nt, desc->Name);
            if (!nameOff) continue;
            std::string dllName(reinterpret_cast<const char*>(fi.bytes.data() + nameOff));
            std::wstring dllNameW = ToUtf16(dllName);
            for (auto& c : dllNameW) c = (wchar_t)::towlower(c);

            auto srcIt = byName.find(dllNameW);
            if (srcIt == byName.end()) continue;
            const ModRange& src = srcIt->second;
            FileImage srcFi = LoadFileImage(src.path);
            if (!srcFi.valid) continue;
            auto exports = ParseExports(srcFi);

            // Build a quick name -> resolved-address-in-target map. The remote
            // image base will be src.base; expected address = src.base + rva.
            std::unordered_map<std::string, uintptr_t> expected;
            for (auto& e : exports) {
                if (e.isForwarder) continue;
                expected[e.name] = src.base + e.rva;
            }

            // Walk INT (names) + IAT (current values).
            uint32_t intOff = RvaToFileOffset(fi.nt, desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk);
            uint32_t iatRva = desc->FirstThunk;
            if (!intOff) continue;

            auto* intP = reinterpret_cast<ULONGLONG*>(fi.bytes.data() + intOff);
            for (size_t i = 0; intP[i]; ++i) {
                if (intP[i] & IMAGE_ORDINAL_FLAG64) continue;  // skip ordinals
                uint32_t hOff = RvaToFileOffset(fi.nt, (uint32_t)intP[i]);
                if (!hOff || hOff + 2 > fi.bytes.size()) continue;
                std::string fn(reinterpret_cast<const char*>(fi.bytes.data() + hOff + 2));
                auto eit = expected.find(fn);
                if (eit == expected.end()) continue;

                // Read the corresponding IAT slot from the target process.
                uintptr_t slotAddr = r.base + iatRva + i * sizeof(ULONGLONG);
                ULONGLONG actual = 0;
                SIZE_T got = 0;
                if (!::ReadProcessMemory(ph.get(), (LPCVOID)slotAddr, &actual, sizeof(actual), &got)) continue;
                const ModRange* hostMod = FindRange(ranges, (uintptr_t)actual);
                if ((uintptr_t)actual != eit->second &&
                    (!hostMod || hostMod->base != src.base)) {
                    HookInfo h{};
                    h.kind = HookKind::Iat;
                    h.pid = pid;
                    h.victimModule = r.name;
                    h.victimFunction = ToUtf16(fn);
                    h.expectedAddress = eit->second;
                    h.actualAddress = (uintptr_t)actual;
                    if (hostMod) h.resolvedModule = hostMod->name;
                    out.push_back(std::move(h));
                }
            }
        }
    }
    return out;
}

std::vector<HookInfo> ScanInlineHooks(uint32_t pid, size_t maxPerModule) {
    std::vector<HookInfo> out;
    HandleGuard ph(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!ph.valid()) return out;
    std::unordered_map<std::wstring, ModRange> byName;
    auto ranges = SnapshotModules(pid, ph.get(), byName);

    for (auto& r : ranges) {
        FileImage fi = LoadFileImage(r.path);
        if (!fi.valid) continue;
        auto exports = ParseExports(fi);
        size_t scanned = 0;
        for (auto& e : exports) {
            if (e.isForwarder) continue;
            if (scanned++ >= maxPerModule) break;
            uint32_t fileOff = RvaToFileOffset(fi.nt, e.rva);
            if (!fileOff || fileOff + 16 > fi.bytes.size()) continue;
            BYTE diskBytes[16];
            memcpy(diskBytes, fi.bytes.data() + fileOff, 16);

            BYTE memBytes[16] = {};
            SIZE_T got = 0;
            if (!::ReadProcessMemory(ph.get(), (LPCVOID)(r.base + e.rva), memBytes, 16, &got) || got < 16) continue;

            if (memcmp(memBytes, diskBytes, 16) != 0) {
                HookInfo h{};
                h.kind = HookKind::Inline;
                h.pid = pid;
                h.victimModule = r.name;
                h.victimFunction = ToUtf16(e.name);
                h.expectedAddress = r.base + e.rva;
                h.actualAddress = r.base + e.rva;
                out.push_back(std::move(h));
            }
        }
    }
    return out;
}

} // namespace winternal
