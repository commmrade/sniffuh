#pragma once
#include "packet.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>

#define TODO(x) throw std::runtime_error(std::format("TODO: {}", x))


std::vector<std::string> show_interfaces();

class Logger;
enum class LogLevel {
    V, // default, // log format: [protocol]: [stuff...]; ...next protocol
    VV, // log format: [protocol]: [stuff...];\nNext protocol...
    VVV // log format: [protocol]: [
        //                          stnuff...
        //                          ];\nNext protocol
};



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
