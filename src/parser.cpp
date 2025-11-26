#include "parser.hpp"
#include "packet.hpp"
#include <chrono>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <print>
#include <stdexcept>

std::unique_ptr<Parser> make_parser(Protocols proto) {
    switch (proto) {
        case Protocols::ETH: {
            return std::make_unique<EthParser>();
            break;
        }
        case Protocols::ARP: {
            return std::make_unique<ArpParser>();
            break;
        }
        case Protocols::IP: {
            return std::make_unique<IpParser>();
            break;
        }
        case Protocols::TCP: {
            return std::make_unique<TcpParser>();
            break;
        }
        case Protocols::UDP: {
            return std::make_unique<UdpParser>();
            break;
        }
        case Protocols::ICMP: {
            return std::make_unique<IcmpParser>();
            break;
        }
        case Protocols::TLS: {
            return std::make_unique<TlsParser>();
            break;
        }
        default: {
            throw std::runtime_error("Parser type is not supported");
            break;
        }
    }
}

std::pair<Packet, Entry> parse_packet(std::span<char> bytes) {
    Packet result;
    Entry entry;
    auto parser = make_parser(Protocols::ETH);
    result.timestamp = std::chrono::system_clock::now();
    entry.ts = std::chrono::system_clock::now();
    result.plod = parser->parse(bytes, entry);
    return {result, entry};
}

std::shared_ptr<void> TlsParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<tlsrecords>();
    constexpr size_t hdr_size = sizeof(tlsrecordhdr);
    while (!bytes.empty()) {
        if (bytes.size() < hdr_size)
            break;

        tlsrecordhdr hdr;
        std::memcpy(&hdr, bytes.data(), hdr_size);

        uint16_t payload_size = ntohs(hdr.length);

        if (bytes.size() < hdr_size + payload_size)
            break;

        result->records.emplace_back(hdr);

        bytes = bytes.subspan(hdr_size + payload_size);
    }

    return result;
}


std::shared_ptr<void> IcmpParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<icmphdr_f>();
    constexpr auto icmphdr_size = sizeof(icmphdr);
    if (bytes.size() < icmphdr_size) {
        throw std::runtime_error("Can't parse ICMP");
    }
    std::memcpy(&result->hdr, bytes.data(), icmphdr_size);
    return result;
}

std::shared_ptr<void> TcpParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<tcphdr_f>();
    constexpr auto tcphdr_size = sizeof(tcphdr);
    if (bytes.size() < tcphdr_size) {
        throw std::runtime_error("Can't parse TCP");
    }
    std::memcpy(&result->hdr, bytes.data(), tcphdr_size);

    std::memcpy(&entry.sport, &result->hdr.source, sizeof(result->hdr.source));
    std::memcpy(&entry.tport, &result->hdr.dest, sizeof(result->hdr.dest));

    bytes = bytes.subspan(tcphdr_size);

    auto options_size = result->hdr.doff * 4 - tcphdr_size;
    if (bytes.size() < options_size) {
        throw std::runtime_error("Can't parse TCP Options");
    }
    result->options.resize(options_size);
    std::memcpy(result->options.data(), bytes.data(), options_size);
    bytes = bytes.subspan(options_size);

    // std::println("TLS first byte: {:#02x}", *bytes.begin());
    if (bytes.size()) {
        auto first_byte = *bytes.begin();
        if ((first_byte >= 0x14 && first_byte <= 0x18) || (ntohs(result->hdr.source) == 443 || ntohs(result->hdr.dest) == 443)) {
            auto tls_parser = make_parser(Protocols::TLS);
            auto plod = tls_parser->parse(bytes, entry);

            result->plod = std::move(plod);
            result->plod_proto = Protocols::TLS;
        } else {
            // Ignore for now (or forever)
        }
    }
    return result;
}

std::shared_ptr<void> UdpParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<udphdr_f>();
    auto a = IPPROTO_IP;
    constexpr auto udphdr_size = sizeof(udphdr);
    if (bytes.size() < udphdr_size) {
        throw std::runtime_error("Can't parse UDP");
    }
    std::memcpy(&result->hdr, bytes.data(), udphdr_size);

    std::memcpy(&entry.sport, &result->hdr.source, sizeof(result->hdr.source));
    std::memcpy(&entry.tport, &result->hdr.dest, sizeof(result->hdr.dest));

    bytes = bytes.subspan(udphdr_size);
    return result;
}

std::shared_ptr<void> ArpParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<arphdr_f>();
    constexpr auto arphdr_size = sizeof(arphdr);
    if (bytes.size() < arphdr_size) {
        throw std::runtime_error("Can't parse arp");
    }
    std::memcpy(&result->hdr, bytes.data(), arphdr_size);
    bytes = bytes.subspan(arphdr_size);

    if (ntohs(result->hdr.ar_hrd) == 1 && ntohs(result->hdr.ar_pro) == 0x0800) {
        constexpr auto size = sizeof(arphdr_ipv4);
        result->plod.resize(size);
        std::memcpy(result->plod.data(), bytes.data(), size);
    } else {
        // ignore
    }
    // No payload
    return result;
}

std::shared_ptr<void> IpParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<iphdr_f>();
    constexpr auto iphdr_size = sizeof(iphdr);
    if (bytes.size() < iphdr_size) {
        throw std::runtime_error("Can't parse IP");
    }

    std::memcpy(&result->hdr, bytes.data(), iphdr_size);

    std::memcpy(entry.saddr.data(), &result->hdr.saddr, sizeof(result->hdr.saddr));
    std::memcpy(entry.taddr.data(), &result->hdr.daddr, sizeof(result->hdr.daddr));
    entry.ip_proto = result->hdr.protocol;

    if (result->hdr.version == 6) {
        throw std::runtime_error("IPV6 is not supported yet");
    }
    bytes = bytes.subspan(iphdr_size);

    auto options_size = (result->hdr.ihl * 4) - iphdr_size;
    if (bytes.size_bytes() < options_size) {
        throw std::runtime_error("Can't parse IP options");
    }
    result->options.resize(options_size);
    std::memcpy(result->options.data(), bytes.data(), options_size);

    bytes = bytes.subspan(options_size);

    // Call the next parser
    // auto proto = result->hdr.protocol == 6 ? Protocols::TCP : Protocols::UDP; // TODO: Improve
    Protocols proto{};
    switch (result->hdr.protocol) {
        case IPPROTO_ICMP: {
            proto = Protocols::ICMP;
            break;
        }
        case IPPROTO_TCP: {
            proto = Protocols::TCP;
            break;
        }
        case IPPROTO_UDP: {
            proto = Protocols::UDP;
            break;
        }
        default: {
            std::println("IP Protocol is not supported: {:02x}", result->hdr.protocol);
            break;
        }
    }
    auto next_parser = make_parser(proto);
    result->plod = next_parser->parse(bytes, entry);
    return result;
}

std::shared_ptr<void> EthParser::parse(std::span<char> bytes, Entry& entry) {
    auto result = std::make_shared<ethhdr_f>();
    // TODO: Implement parsing logic for Ethernet different header types
    constexpr auto ethhdr_size = sizeof(ethhdr);
    if (bytes.size() < ethhdr_size) {
        return {};
        throw std::runtime_error("Can't parse eth");
    }
    std::memcpy(&result->hdr, bytes.data(), ethhdr_size);
    // std::println("If length?: {}", ntohs(result->hdr.h_proto));
    if (ntohs(result->hdr.h_proto) == ETH_P_8021Q) {
        bytes = bytes.subspan(sizeof(result->hdr.h_source) + sizeof(result->hdr.h_dest) + 2); // 2 for vlan tag part
        std::memcpy(&result->hdr.h_proto, bytes.data(), sizeof(result->hdr.h_proto));
        bytes = bytes.subspan(sizeof(result->hdr.h_proto));
    } else {
        bytes = bytes.subspan(ethhdr_size);
    }

    std::memcpy(entry.shaddr.data(), &result->hdr.h_source, sizeof(result->hdr.h_source));
    std::memcpy(entry.thaddr.data(), &result->hdr.h_dest, sizeof(result->hdr.h_dest));
    entry.eth_proto = result->hdr.h_proto;

    // Call next parser
    Protocols proto{};
    switch (ntohs(result->hdr.h_proto)) {
        case ETH_P_IP: {
            proto = Protocols::IP;
            break;
        }
        case ETH_P_ARP: {
            proto = Protocols::ARP;
            break;
        }
        default: {
            return {};
            break;
        }
    }
    auto next_parser = make_parser(proto);
    result->plod = next_parser->parse(bytes, entry);
    return result;
}
