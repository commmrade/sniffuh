#pragma once
#include <span>
#include <memory>
#include "file.hpp"
#include "packet.hpp"

class Parser {
public:
    virtual std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) = 0;
    virtual ~Parser() = default;
};

class TlsParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class IcmpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class Icmp6Parser final : public Parser {
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class TcpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class UdpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class ArpParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class Ip4Parser final : public Parser {
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class Ip6Parser final : public Parser {
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};
class EthParser final : public Parser {
public:
    std::shared_ptr<void> parse(std::span<char> bytes, Entry& entry) override;
};

std::unique_ptr<Parser> make_parser(Protocols proto);
std::pair<Packet, Entry> parse_packet(std::span<char> bytes);
