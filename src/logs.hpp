#pragma once
#include "packet.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>

#define TODO(x) throw std::runtime_error(std::format("TODO: {}", x))


std::vector<std::string> show_interfaces();

class Logger;
enum class LogLevel {
    V = 0, // default, // log format: [protocol]: [stuff...]; ...next protocol
    VV, // log format: [protocol]: [stuff...];\nNext protocol...
    VVV // log format: [protocol]: [
        //                          stnuff...
        //                          ];\nNext protocol
};

// static void print_entry(Entry& en) {
//     std::println("=====");
//     std::println("Ts: {}", en.ts);
//     std::println("Shaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", en.shaddr[0], en.shaddr[1], en.shaddr[2], en.shaddr[3], en.shaddr[4], en.shaddr[5]);
//     std::println("Thaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", en.thaddr[0], en.thaddr[1], en.thaddr[2], en.thaddr[3], en.thaddr[4], en.thaddr[5]);
//     std::println("Eth proto: {:#04x}", ntohs(en.eth_proto));
//     if (en.eth_proto == ntohs(ETH_P_IP)) {
//         char buf[INET_ADDRSTRLEN];
//         const char* r = inet_ntop(AF_INET, en.saddr.data(), buf, sizeof(buf));
//         assert(r);
//         std::println("Source addr: {}", buf);
//         r = inet_ntop(AF_INET, en.taddr.data(), buf, sizeof(buf));
//         assert(r);
//         std::println("Dest addr: {}", buf);
//     }
//     std::println("IP proto: {}", en.ip_proto);
//     std::println("Sport: {}", ntohs(en.sport));
//     std::println("Dport: {}", ntohs(en.dport));

//     std::println("=====");
// }


std::unique_ptr<Logger> make_logger(Protocols proto, LogLevel lvl);
std::string log_packet(Packet& pkt, LogLevel lvl);


class Logger {
protected:
    LogLevel m_log_lvl;
public:
    virtual ~Logger() = default;
    Logger(LogLevel lvl) : m_log_lvl(lvl) {}
    virtual std::string process(std::shared_ptr<void> p) = 0;
};

class EthLogger final : public Logger {
public:
    EthLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class ArpLogger final : public Logger {
public:
    ArpLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class IpLogger final : public Logger {
public:
    IpLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class TcpLogger final : public Logger {
public:
    TcpLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class UdpLogger final : public Logger {
public:
    UdpLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class IcmpLogger final : public Logger {
public:
    IcmpLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};

class TlsLogger final : public Logger {
public:
    TlsLogger(LogLevel lvl) : Logger(lvl) {}
    std::string process(std::shared_ptr<void> p) override;
};
