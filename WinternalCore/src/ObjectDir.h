#pragma once
#include <string>
#include <vector>

namespace winternal {

struct ObjectEntry {
    std::wstring name;
    std::wstring type;
    std::wstring fullPath;        // joined parent + name
};

// List entries inside a NT object directory (e.g. "\\", "\\Device", "\\BaseNamedObjects").
std::vector<ObjectEntry> ListObjectDir(const std::wstring& path);

} // namespace winternal
