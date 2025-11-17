#pragma once
#include <span>
#include <memory>
#include "packet.hpp"

class Parser {
public:
    virtual std::shared_ptr<void> parse(std::span<char> bytes) = 0;
    virtual ~Parser() = default;
};

class IcmpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};
class TcpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};
class UdpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};
class ArpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};
class IpParser final : public Parser {
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};
class EthParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes) override;
};

std::unique_ptr<Parser> make_parser(Protocols proto);
Packet parse_packet(std::span<char> bytes);
