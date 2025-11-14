#include "utils.hpp"

std::vector<std::string> show_interfaces() {
    int ret;
    ifaddrs *ifap, *p;

    ret = getifaddrs(&ifap);
    if (ret < 0) {
        std::perror("getifaddrs");
        throw std::runtime_error("getifaddrs failed");
    }
    defer ifaddrsfree{[ifap] { freeifaddrs(ifap); }};

    std::vector<std::string> ifs;
    for (p = ifap; p != NULL; p = p->ifa_next) {
        ifs.emplace_back(p->ifa_name);
    }
    return ifs;
}

ethhdr parse_eth(std::span<char> bytes) {
    ethhdr result; // TODO: FIx vlan
    if (bytes.size() < sizeof(ethhdr)) {
        throw std::runtime_error("Buf is too short to parse eth header");
    }
    std::memcpy(&result, bytes.data(), sizeof(ethhdr));
    return result;
}

arphdr_f parse_arp(std::span<char> bytes) {
    arphdr_f result;
    if (bytes.size() < sizeof(result.hdr)) {
        throw std::runtime_error("Buf is too short to parse arp");
    }
    std::memcpy(&result.hdr, bytes.data(), sizeof(result.hdr));
    bytes = bytes.subspan(sizeof(result.hdr));

    if (ntohs(result.hdr.ar_hrd) == 1 && ntohs(result.hdr.ar_pro) == 0x0800) {
        auto body_size = sizeof(arphdr_ipv4); // TODO Handle error
        result.plod.resize(body_size);
        std::memcpy(result.plod.data(), bytes.data(), body_size);
    } else {
        throw std::runtime_error("Parsing other types of arp is not supported");
    }

    return result;
}
void print_arp(arphdr_f& arp) {
    std::println("==========\nHardware type: {}\nProtocol type: {:#06x}\nHardware length: {}\nProtocol length: {}\nOperation: {}", ntohs(arp.hdr.ar_hrd), ntohs(arp.hdr.ar_pro), arp.hdr.ar_hln, arp.hdr.ar_pln, ntohs(arp.hdr.ar_op));

    if (ntohs(arp.hdr.ar_hrd) == 1 && ntohs(arp.hdr.ar_pro) == 0x0800) { // mac and ipv4
        if (arp.plod.size() < sizeof(arphdr_ipv4)) {
            throw std::runtime_error("ARP payload isn't big enough");
        }
        arphdr_ipv4 body{};
        std::memcpy(&body, arp.plod.data(), sizeof(body));

        char addr_buf[INET_ADDRSTRLEN]{};

        const char* r = inet_ntop(AF_INET, body.ar_sip, addr_buf, sizeof(addr_buf));
        assert(r);
        std::println("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Source", body.ar_sha[0], body.ar_sha[1], body.ar_sha[2], body.ar_sha[3], body.ar_sha[4], body.ar_sha[5]);
        std::println("Sender IP: {}", addr_buf);

        r = inet_ntop(AF_INET, body.ar_tip, addr_buf, sizeof(addr_buf));
        assert(r);
        std::println("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Target", body.ar_tha[0], body.ar_tha[1], body.ar_tha[2], body.ar_tha[3], body.ar_tha[4], body.ar_tha[5]);
        std::println("Target IP: {}\n==========", addr_buf);
    } else {
        std::println("***This ARP hardware address and protocol address are not supported***");
    }
}

iphdr_f parse_ip(std::span<char> bytes) {
    iphdr_f result;
    if (bytes.size() < sizeof(result.hdr)) {
        throw std::runtime_error("Buffer is too short for iphdr");
    }

    std::memcpy(&result.hdr, bytes.data(), sizeof(result.hdr));
    if (result.hdr.version == 6) {
        throw std::runtime_error("IPv6 not supported yet");
    }
    bytes = bytes.subspan(sizeof(result.hdr));

    auto options_size = (result.hdr.ihl * 4) - sizeof(iphdr);
    if (bytes.size() < options_size) {
        throw std::runtime_error("Options requested, size is smaller");
    }
    result.options.resize(options_size);
    std::memcpy(result.options.data(), bytes.data(), options_size);
    // Options are almost never used in Ipv4 so idc
    return result;
}
void print_ip(iphdr_f& ip) {
    std::println("======== IP");

    int ver = ip.hdr.version;
    int ihl = ip.hdr.ihl;
    std::println("Version: {}\nIHL: {}\nTotal length: {}\nId: {}\nFrag off: {}\nTtl: {}\nProtocol: {}\nCheck: {}",
        ver, ihl, ntohs(ip.hdr.tot_len), ntohs(ip.hdr.id), ntohs(ip.hdr.frag_off), ip.hdr.ttl, ip.hdr.protocol, ntohs(ip.hdr.check));

    char addr_buf[INET_ADDRSTRLEN];
    const char* r = inet_ntop(AF_INET, &ip.hdr.saddr, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Source IP: {}", addr_buf);
    r = inet_ntop(AF_INET, &ip.hdr.daddr, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Destination IP: {}", addr_buf);

    std::println("========");
}

tcphdr_f parse_tcp(std::span<char> bytes) {
    tcphdr_f result{};
    if (bytes.size() < sizeof(tcphdr)) {
        throw std::runtime_error("Buf is not big enough to parse TCP");
    }
    std::memcpy(&result.hdr, bytes.data(), sizeof(tcphdr));
    bytes = bytes.subspan(sizeof(tcphdr));

    auto options_size = result.hdr.doff * 4 - sizeof(tcphdr);
    if (bytes.size() < options_size) {
        throw std::runtime_error("not enough bytes in buf to read tcp options");
    }
    result.options.resize(options_size);
    std::memcpy(result.options.data(), bytes.data(), options_size);
    return result;
}
void print_tcp(tcphdr_f& tcp) {
    std::println("======== TCP****");
    std::println("Source port: {}", ntohs(tcp.hdr.source));
    std::println("Dest port: {}", ntohs(tcp.hdr.dest));
    std::println("Seq Num: {}", ntohl(tcp.hdr.seq));
    std::println("Ack Num: {}", ntohl(tcp.hdr.ack_seq));
    auto doff = tcp.hdr.doff;
    std::println("Data offset (in bytes): {}", (doff - 5) * 4);
    std::println("Window: {}", ntohs(tcp.hdr.window));
    std::println("Urg: {}", ntohs(tcp.hdr.urg_ptr));

    auto options_size = (tcp.hdr.doff * 4) - sizeof(tcphdr);
    if (options_size) {
        std::println("Options:");
        auto* obytes = tcp.options.data();
        auto size = tcp.options.size();

        while (size) {
            uint8_t kind;
            std::memcpy(&kind, obytes, sizeof(kind));
            obytes += sizeof(kind);
            size -= sizeof(kind);
            switch (kind) {
                case 0: {
                    size = 0;
                    break;
                }
                case 1: { // no-op
                    std::println("    Kind: {}", kind);
                    continue; // skip to next iteration
                    break;
                }
                case 8: {
                    uint8_t olen;
                    std::memcpy(&olen, obytes, sizeof(olen));
                    obytes += sizeof(olen);
                    size -= sizeof(olen);
                    olen -= sizeof(olen) + sizeof(kind); // how many bytes in payload

                    std::println("    Kind: {}\n    Olen: {}", kind, olen);
                    if (olen < 8) {
                        throw std::runtime_error("Kind 8 option field is broken");
                    }

                    uint32_t ststmp;
                    std::memcpy(&ststmp, obytes, sizeof(ststmp));
                    obytes += sizeof(ststmp);
                    size -= sizeof(ststmp);
                    ststmp = ntohl(ststmp);

                    uint32_t ttstmp;
                    std::memcpy(&ttstmp, obytes, sizeof(ttstmp));
                    obytes += sizeof(ttstmp);
                    size -= sizeof(ttstmp);
                    ttstmp = ntohl(ttstmp);
                    std::println("    Sender timestamp: {}\n    Reply timestamp: {}", ststmp, ttstmp);

                    olen -= sizeof(ststmp) + sizeof(ttstmp);
                    if (olen < 0) {
                        throw std::runtime_error("Packet is corrupted");
                    }
                    obytes += olen;
                    size -= olen;
                    break;
                }
                case 5: {
                    std::println("    Selective Acknowledgement permitted option");
                    break;
                }
                default: {
                    std::println("UNSUPPORTED OPTION {}", kind);
                    break;
                }
            }
        }
    }
    std::println("========");
}

udphdr parse_udp(std::span<char> bytes) {
    udphdr result{};
    if (bytes.size() < sizeof(result)) {
        throw std::runtime_error("Buf is not big enough to parse UDP");
    }
    std::memcpy(&result, bytes.data(), sizeof(result));
    return result;
}
void print_udp(udphdr& udp) {
    std::println("======= UDP******");
    std::println("Source port: {}", ntohs(udp.source));
    std::println("Dest port: {}", ntohs(udp.dest));
    std::println("Length: {}", ntohs(udp.len));
    std::println("=======");
}
