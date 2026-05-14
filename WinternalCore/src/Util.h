#pragma once
#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cstdint>

namespace winternal {

std::string ToUtf8(std::wstring_view w);
std::wstring ToUtf16(std::string_view u);
std::string FormatStatus(LONG ntStatus);
std::string FormatError(DWORD winError);
std::string FormatBytes(uint64_t bytes);
std::wstring DosPathFromNtPath(std::wstring_view nt);
std::wstring NtPathFromDosPath(std::wstring_view dos);
std::optional<std::wstring> ImagePathFromHandle(HANDLE process);
bool IsElevated();
bool EnableDebugPrivilege();
std::string Sha256Hex(const void* data, size_t len);

class HandleGuard {
public:
    HandleGuard() = default;
    explicit HandleGuard(HANDLE h) : h_(h) {}
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    HandleGuard& operator=(HandleGuard&& o) noexcept {
        if (this != &o) { reset(); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }
    ~HandleGuard() { reset(); }
    HANDLE get() const { return h_; }
    bool valid() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
    void reset(HANDLE n = nullptr) {
        if (valid() && h_ != INVALID_HANDLE_VALUE) ::CloseHandle(h_);
        h_ = n;
    }
    HANDLE release() { HANDLE t = h_; h_ = nullptr; return t; }
private:
    HANDLE h_ = nullptr;
};

} // namespace winternal
