#include "Handle.h"
#include "NtApi.h"
#include "Util.h"
#include <vector>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <chrono>
#include <future>

#pragma comment(lib, "ntdll.lib")

using namespace winternal::nt;

namespace winternal {

// Resolve type names from index by querying ObjectAllTypesInformation.
// Layout returned by ntdll: ULONG NumberOfTypes; followed by per-type records:
// OBJECT_TYPE_INFORMATION (UNICODE_STRING TypeName + 22 ULONG/UCHAR fields +
// GENERIC_MAPPING). Each record is followed by the wchar buffer for TypeName,
// rounded up to sizeof(void*).
static std::unordered_map<uint16_t, std::wstring> BuildTypeIndexMap() {
    std::unordered_map<uint16_t, std::wstring> map;
    std::vector<BYTE> buf(64 * 1024);
    ULONG ret = 0;
    NTSTATUS s;
    while (true) {
        s = NtQueryObject(nullptr, ObjectAllTypesInformationClass, buf.data(), (ULONG)buf.size(), &ret);
        if (s == 0) break;
        if (ret > buf.size()) { buf.resize(ret + 4096); continue; }
        return map;
    }
    BYTE* p = buf.data();
    ULONG count = *reinterpret_cast<ULONG*>(p);
    // Records start aligned to sizeof(void*) past the count header.
    p += sizeof(ULONG_PTR);
    constexpr size_t kRecordSize = sizeof(OBJECT_TYPE_INFORMATION_MIN);
    for (ULONG i = 0; i < count && p + kRecordSize <= buf.data() + buf.size(); ++i) {
        auto* t = reinterpret_cast<OBJECT_TYPE_INFORMATION_MIN*>(p);
        std::wstring name;
        if (t->TypeName.Buffer && t->TypeName.Length) {
            name.assign(t->TypeName.Buffer, t->TypeName.Length / 2);
        }
        // ObjectTypeIndex assigned by the kernel typically starts at 2.
        map[(uint16_t)(i + 2)] = std::move(name);
        BYTE* next = p + kRecordSize + t->TypeName.MaximumLength;
        next = reinterpret_cast<BYTE*>(((ULONG_PTR)next + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
        if (next <= p) break;
        p = next;
    }
    return map;
}

// Query an object name with a timeout. Some handle types (named pipes,
// synchronous file handles to devices) can hang inside NtQueryObject.
static std::wstring QueryObjectNameSafe(HANDLE h) {
    std::promise<std::wstring> prom;
    auto fut = prom.get_future();
    std::thread t([h, p = std::move(prom)]() mutable {
        std::vector<BYTE> buf(2048);
        ULONG ret = 0;
        NTSTATUS s = NtQueryObject(h, ObjectNameInformationClass, buf.data(), (ULONG)buf.size(), &ret);
        if (s == 0) {
            auto* n = reinterpret_cast<UNICODE_STRING*>(buf.data());
            if (n->Length && n->Buffer) {
                p.set_value(std::wstring(n->Buffer, n->Length / 2));
                return;
            }
        }
        p.set_value(L"");
    });
    if (fut.wait_for(std::chrono::milliseconds(80)) == std::future_status::ready) {
        t.join();
        return fut.get();
    }
    // Hung. Detach + give up. (Worst case: a worker thread leaks for the lifetime
    // of the handle. NtQueryObject on the offending handle can be aborted by closing
    // the handle, but we don't own it.)
    t.detach();
    return L"";
}

std::vector<HandleInfo> EnumHandles(bool resolveNames) {
    std::vector<HandleInfo> out;
    std::vector<BYTE> buf(1024 * 1024);
    ULONG ret = 0;
    NTSTATUS s;
    while (true) {
        s = NtQuerySystemInformation(SystemExtendedHandleInformationClass, buf.data(), (ULONG)buf.size(), &ret);
        if (s == 0) break;
        if (s == kStatusInfoLengthMismatch || ret > buf.size()) {
            buf.resize(ret ? ret + 4096 : buf.size() * 2);
            continue;
        }
        return out;
    }

    auto types = BuildTypeIndexMap();

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX_X*>(buf.data());
    std::unordered_map<uint32_t, HANDLE> dupSrcCache;

    DWORD me = ::GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        HandleInfo h{};
        h.pid = (uint32_t)e.UniqueProcessId;
        h.handleValue = (uint32_t)e.HandleValue;
        h.typeIndex = e.ObjectTypeIndex;
        h.grantedAccess = e.GrantedAccess;
        h.object = (uint64_t)e.Object;

        auto it = types.find(e.ObjectTypeIndex);
        if (it != types.end()) h.typeName = it->second;

        if (resolveNames) {
            HANDLE dup = nullptr;
            HANDLE src = nullptr;
            if (h.pid == me) {
                src = (HANDLE)(ULONG_PTR)h.handleValue;
                dup = src;
            } else {
                auto cached = dupSrcCache.find(h.pid);
                if (cached == dupSrcCache.end()) {
                    HANDLE p = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.pid);
                    dupSrcCache[h.pid] = p;
                    src = p;
                } else {
                    src = cached->second;
                }
                if (src) {
                    if (!::DuplicateHandle(src, (HANDLE)(ULONG_PTR)h.handleValue,
                                           ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                        dup = nullptr;
                    }
                }
            }
            if (dup) {
                // Skip name query for known-hangy types when name not strictly needed.
                bool risky = (h.typeName == L"File" || h.typeName == L"EtwRegistration" || h.typeName == L"EtwConsumer");
                std::wstring name = risky ? QueryObjectNameSafe(dup) : QueryObjectNameSafe(dup);
                h.name = std::move(name);
                if (h.pid != me) ::CloseHandle(dup);
            }
        }
        out.push_back(std::move(h));
    }

    for (auto& [pid, p] : dupSrcCache) if (p) ::CloseHandle(p);
    return out;
}

bool CloseHandleInProcess(uint32_t pid, uint32_t handleValue) {
    HandleGuard p(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid));
    if (!p.valid()) return false;
    HANDLE dummy = nullptr;
    BOOL ok = ::DuplicateHandle(p.get(), (HANDLE)(ULONG_PTR)handleValue,
                                ::GetCurrentProcess(), &dummy,
                                0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (ok && dummy) ::CloseHandle(dummy);
    return ok != 0;
}

} // namespace winternal
