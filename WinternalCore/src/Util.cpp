#include "Util.h"
#include "NtApi.h"
#include <wincrypt.h>
#include <sddl.h>
#include <array>
#include <cstdio>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")

namespace winternal {

std::string ToUtf8(std::wstring_view w) {
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring ToUtf16(std::string_view u) {
    if (u.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), nullptr, 0);
    std::wstring s(n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), s.data(), n);
    return s;
}

std::string FormatStatus(LONG s) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(s));
    return buf;
}

std::string FormatError(DWORD e) {
    LPSTR msg = nullptr;
    DWORD n = ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, e, 0, (LPSTR)&msg, 0, nullptr);
    std::string out;
    char prefix[32];
    std::snprintf(prefix, sizeof(prefix), "%lu: ", e);
    out = prefix;
    if (n && msg) {
        out.append(msg, n);
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) out.pop_back();
        ::LocalFree(msg);
    }
    return out;
}

std::string FormatBytes(uint64_t b) {
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double v = (double)b;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %s", v, units[i]);
    return buf;
}

std::wstring DosPathFromNtPath(std::wstring_view nt) {
    // Map common prefixes \??\ (alias for \GLOBAL??\) and \Device\HarddiskVolumeN\... -> drive letter.
    if (nt.starts_with(L"\\??\\")) return std::wstring(nt.substr(4));
    if (nt.starts_with(L"\\\\?\\")) return std::wstring(nt.substr(4));

    // For \Device\HarddiskVolume*, walk drives.
    if (nt.starts_with(L"\\Device\\")) {
        wchar_t drive[4] = L"A:";
        for (wchar_t c = L'A'; c <= L'Z'; ++c) {
            drive[0] = c;
            wchar_t target[1024];
            DWORD rc = ::QueryDosDeviceW(drive, target, 1024);
            if (rc == 0) continue;
            std::wstring_view t(target);
            if (nt.starts_with(t) && nt.size() > t.size() && nt[t.size()] == L'\\') {
                std::wstring out;
                out += c; out += L':';
                out.append(nt.substr(t.size()));
                return out;
            }
        }
    }
    return std::wstring(nt);
}

std::wstring NtPathFromDosPath(std::wstring_view dos) {
    if (dos.size() >= 2 && dos[1] == L':') {
        wchar_t drive[4] = L"A:";
        drive[0] = dos[0];
        wchar_t target[1024];
        DWORD rc = ::QueryDosDeviceW(drive, target, 1024);
        if (rc != 0) {
            std::wstring out = target;
            out.append(dos.substr(2));
            return out;
        }
    }
    return std::wstring(dos);
}

std::optional<std::wstring> ImagePathFromHandle(HANDLE p) {
    wchar_t buf[1024];
    DWORD n = (DWORD)std::size(buf);
    if (::QueryFullProcessImageNameW(p, 0, buf, &n)) return std::wstring(buf, n);
    return std::nullopt;
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION e = {};
    DWORD cb = 0;
    bool ok = ::GetTokenInformation(token, TokenElevation, &e, sizeof(e), &cb) && e.TokenIsElevated;
    ::CloseHandle(token);
    return ok;
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    LUID luid;
    bool ok = false;
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
        ok = (::GetLastError() == ERROR_SUCCESS);
    }
    ::CloseHandle(token);
    return ok;
}

std::string Sha256Hex(const void* data, size_t len) {
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0;
    std::string out;
    if (!::CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return out;
    if (::CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (::CryptHashData(hash, (const BYTE*)data, (DWORD)len, 0)) {
            BYTE digest[32];
            DWORD dlen = sizeof(digest);
            if (::CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0)) {
                char buf[3] = {};
                for (DWORD i = 0; i < dlen; ++i) {
                    std::snprintf(buf, 3, "%02X", digest[i]);
                    out.append(buf);
                }
            }
        }
        ::CryptDestroyHash(hash);
    }
    ::CryptReleaseContext(prov, 0);
    return out;
}

} // namespace winternal
