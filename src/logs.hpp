#pragma once
#include "packet.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>

#define TODO(x) throw std::runtime_error(std::format("TODO: {}", x))

template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};
std::vector<std::string> show_interfaces();


class Logger {
public:
    virtual ~Logger() = default;
    virtual std::string process(std::shared_ptr<void> p) = 0;
};

std::unique_ptr<Logger> make_logger(Protocols proto);
std::string log_packet(Packet& pkt);

class EthLogger final : public Logger {
public:
    std::string process(std::shared_ptr<void> p) override;
};

class ArpLogger final : public Logger {
    std::string process(std::shared_ptr<void> p) override;
};

class IpLogger final : public Logger {
public:
    std::string process(std::shared_ptr<void> p) override;
};

class TcpLogger final : public Logger {
public:
    std::string process(std::shared_ptr<void> p) override;
};

class UdpLogger final : public Logger {
public:
    std::string process(std::shared_ptr<void> p) override;
};

class IcmpLogger final : public Logger {
    std::string process(std::shared_ptr<void> p) override;
};
