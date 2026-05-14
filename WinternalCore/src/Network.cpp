#include "Network.h"
#include "Util.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace winternal {

static std::wstring TcpStateName(MIB_TCP_STATE s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED:      return L"CLOSED";
        case MIB_TCP_STATE_LISTEN:      return L"LISTEN";
        case MIB_TCP_STATE_SYN_SENT:    return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:    return L"SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:       return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:   return L"FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:   return L"FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:  return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:     return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK:    return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:   return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:  return L"DELETE_TCB";
        default:                        return L"?";
    }
}

static std::wstring V4ToString(DWORD addr, USHORT port) {
    in_addr a{}; a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    wchar_t out[64];
    swprintf_s(out, L"%S:%u", buf, ntohs(port));
    return out;
}

static std::wstring V6ToString(const UCHAR addr[16], USHORT port) {
    in6_addr a{};
    memcpy(&a, addr, 16);
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    wchar_t out[80];
    swprintf_s(out, L"[%S]:%u", buf, ntohs(port));
    return out;
}

std::vector<ConnectionInfo> EnumConnections() {
    std::vector<ConnectionInfo> out;

    // TCPv4
    {
        ULONG sz = 0;
        ::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz);
        if (sz && ::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                ConnectionInfo c{};
                c.proto = L4Proto::Tcp4;
                c.local = V4ToString(r.dwLocalAddr, (USHORT)r.dwLocalPort);
                c.remote = V4ToString(r.dwRemoteAddr, (USHORT)r.dwRemotePort);
                c.state = r.dwState;
                c.pid = r.dwOwningPid;
                c.stateName = TcpStateName((MIB_TCP_STATE)r.dwState);
                out.push_back(std::move(c));
            }
        }
    }
    // TCPv6
    {
        ULONG sz = 0;
        ::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz);
        if (sz && ::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                ConnectionInfo c{};
                c.proto = L4Proto::Tcp6;
                c.local = V6ToString(r.ucLocalAddr, (USHORT)r.dwLocalPort);
                c.remote = V6ToString(r.ucRemoteAddr, (USHORT)r.dwRemotePort);
                c.state = r.dwState;
                c.pid = r.dwOwningPid;
                c.stateName = TcpStateName((MIB_TCP_STATE)r.dwState);
                out.push_back(std::move(c));
            }
        }
    }
    // UDPv4
    {
        ULONG sz = 0;
        ::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> buf(sz);
        if (sz && ::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                ConnectionInfo c{};
                c.proto = L4Proto::Udp4;
                c.local = V4ToString(r.dwLocalAddr, (USHORT)r.dwLocalPort);
                c.pid = r.dwOwningPid;
                c.stateName = L"";
                out.push_back(std::move(c));
            }
        }
    }
    // UDPv6
    {
        ULONG sz = 0;
        ::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> buf(sz);
        if (sz && ::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                ConnectionInfo c{};
                c.proto = L4Proto::Udp6;
                c.local = V6ToString(r.ucLocalAddr, (USHORT)r.dwLocalPort);
                c.pid = r.dwOwningPid;
                out.push_back(std::move(c));
            }
        }
    }
    return out;
}

} // namespace winternal
