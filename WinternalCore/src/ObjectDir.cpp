#include "ObjectDir.h"
#include "NtApi.h"
#include "Util.h"
#include <vector>

#pragma comment(lib, "ntdll.lib")

using namespace winternal::nt;

namespace winternal {

std::vector<ObjectEntry> ListObjectDir(const std::wstring& path) {
    std::vector<ObjectEntry> out;
    UNICODE_STRING us{};
    us.Buffer = const_cast<wchar_t*>(path.c_str());
    us.Length = (USHORT)(path.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributesX(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE dir = nullptr;
    NTSTATUS s = NtOpenDirectoryObject(&dir, kDirQuery | kDirTraverse, &oa);
    if (!NT_SUCCESS(s)) return out;

    std::vector<BYTE> buf(64 * 1024);
    ULONG ctx = 0, ret = 0;
    BOOLEAN restart = TRUE;
    while (true) {
        NTSTATUS qs = NtQueryDirectoryObject(dir, buf.data(), (ULONG)buf.size(), FALSE, restart, &ctx, &ret);
        if (!NT_SUCCESS(qs)) break;
        restart = FALSE;
        auto* p = reinterpret_cast<OBJECT_DIRECTORY_INFORMATION_X*>(buf.data());
        for (; p->Name.Buffer; ++p) {
            ObjectEntry e{};
            e.name.assign(p->Name.Buffer, p->Name.Length / 2);
            if (p->TypeName.Buffer) e.type.assign(p->TypeName.Buffer, p->TypeName.Length / 2);
            e.fullPath = path;
            if (!e.fullPath.empty() && e.fullPath.back() != L'\\') e.fullPath += L'\\';
            e.fullPath += e.name;
            out.push_back(std::move(e));
        }
        // STATUS_MORE_ENTRIES is positive (0x105). NtQueryDirectoryObject returns
        // STATUS_NO_MORE_ENTRIES (0x8000001a) when done.
        if (qs != 0x00000105L) break;
    }

    NtClose(dir);
    return out;
}

} // namespace winternal
