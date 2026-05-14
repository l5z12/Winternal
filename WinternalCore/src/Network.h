#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace winternal {

enum class L4Proto { Tcp4, Tcp6, Udp4, Udp6 };

struct ConnectionInfo {
    L4Proto proto = L4Proto::Tcp4;
    std::wstring local;          // "ip:port"
    std::wstring remote;         // "ip:port" or empty
    uint32_t state = 0;          // TCP MIB_TCP_STATE_* (0 for UDP)
    uint32_t pid = 0;
    std::wstring stateName;      // friendly
    std::wstring processName;    // best-effort, filled by enricher
};

std::vector<ConnectionInfo> EnumConnections();

} // namespace winternal
