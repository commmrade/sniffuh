#include "logs.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <format>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <print>
#include "packet.hpp"


std::string log_packet(Packet& pkt, LogLevel lvl) {
    if (!pkt.plod)
        return "";
    auto log = make_logger(Protocols::ETH, lvl);

    std::string r;
    switch (lvl) {
    case LogLevel::V: {
        r += std::format("{}: ", pkt.timestamp);
        break;
    }
    case LogLevel::VV: {
        r += std::format("{}:\n", pkt.timestamp);
        break;
    }
    case LogLevel::VVV: {
        r += std::format("{}:\n", pkt.timestamp);
    }
    }
    r += log->process(pkt.plod);
    return r;
}

std::unique_ptr<Logger> make_logger(Protocols proto, LogLevel lvl) {
    switch (proto) {
        case Protocols::ETH: {
            return std::make_unique<EthLogger>(lvl);
            break;
        }
        case Protocols::ARP: {
            return std::make_unique<ArpLogger>(lvl);
            break;
        }
        case Protocols::IPv4: {
            return std::make_unique<Ip4Logger>(lvl);
            break;
        }
        case Protocols::IPv6: {
            return std::make_unique<Ip6Logger>(lvl);
        }
        case Protocols::TCP: {
            return std::make_unique<TcpLogger>(lvl);
            break;;
        }
        case Protocols::UDP: {
            return std::make_unique<UdpLogger>(lvl);
            break;
        }
        case Protocols::ICMP: {
            return std::make_unique<IcmpLogger>(lvl);
            break;
        }
        case Protocols::ICMPv6: {
            return std::make_unique<Icmp6Logger>(lvl);
            break;
        }
        case Protocols::TLS: {
            return std::make_unique<TlsLogger>(lvl);
            break;
        }
        default: {
            throw std::runtime_error("Logger type is not supported");
            break;
        }
    }
}

std::string EthLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const ethhdr_f* eth = static_cast<const ethhdr_f*>(p.get());

    res += "ETH: ";

    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; ",
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5],
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5]
        );
        break;
    }
    case LogLevel::VV: {
        res += std::format("Src: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> Target: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; EthType: {:#04x}\n",
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5],
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5],
            ntohs(eth->hdr.h_proto)
        );
        break;
    }
    case LogLevel::VVV: {
        res += std::format("\n    Source: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, Target: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x};\n    EthType: {:#04x}\n",
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5],
            eth->hdr.h_source[0], eth->hdr.h_source[1], eth->hdr.h_source[2], eth->hdr.h_source[3], eth->hdr.h_source[4], eth->hdr.h_source[5],
            ntohs(eth->hdr.h_proto)
        );
        break;
    }
    }

    Protocols proto{};
    switch (ntohs(eth->hdr.h_proto)) {
        case ETH_P_IP: {
            proto = Protocols::IPv4;
            break;
        }
        case ETH_P_ARP: {
            proto = Protocols::ARP;
            break;
        }
        case ETH_P_IPV6: {
            proto = Protocols::IPv6;
            break;
        }
        default: {
            return res;
            break;
        }
    }
    auto next_log = make_logger(proto, m_log_lvl);
    res += next_log->process(eth->plod);
    return res;
}

std::string ArpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const arphdr_f* arp = static_cast<const arphdr_f*>(p.get());

    auto op = ntohs(arp->hdr.ar_op);
    res += std::format("ARP: {}", op == 1 ? "Request " : "Reply ");

    if (ntohs(arp->hdr.ar_hrd) == 1 && ntohs(arp->hdr.ar_pro) == 0x0800) {
        arphdr_ipv4 body{};
        std::memcpy(&body, arp->plod.data(), sizeof(body));

        switch (m_log_lvl) {
        case LogLevel::V: {
            if (op == 1) { // request
                std::array<char, INET_ADDRSTRLEN> addr_buf{};
                const char* r = inet_ntop(AF_INET, body.ar_tip, addr_buf.data(), addr_buf.size());
                assert(r);
                res += std::format("who is {}; ", addr_buf.data());
            } else if (op == 2) {
                std::array<char, INET_ADDRSTRLEN> addr_buf{};
                const char* r = inet_ntop(AF_INET, body.ar_sip, addr_buf.data(), addr_buf.size());
                assert(r);
                res += std::format("{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; ", addr_buf.data(),
                    body.ar_sha[0], body.ar_sha[1], body.ar_sha[2], body.ar_sha[3], body.ar_sha[4], body.ar_sha[5]);
            }
            break;
        }
        case LogLevel::VV: {
            res += std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x};\n",
                body.ar_sha[0], body.ar_sha[1], body.ar_sha[2], body.ar_sha[3], body.ar_sha[4], body.ar_sha[5],
                body.ar_tha[0], body.ar_tha[1], body.ar_tha[2], body.ar_tha[3], body.ar_tha[4], body.ar_tha[5]
            );
            break;
        }
        case LogLevel::VVV: {
            std::array<char, INET_ADDRSTRLEN> sip_buf{};
            std::array<char, INET_ADDRSTRLEN> tip_buf{};
            const char* r = inet_ntop(AF_INET, body.ar_sip, sip_buf.data(), sip_buf.size());
            assert(r);
            r = inet_ntop(AF_INET, body.ar_tip, tip_buf.data(), tip_buf.size());
            assert(r);

            res += std::format("\n    SIP: {}, SHA: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n    TIP: {}, THA: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x};\n",
                sip_buf.data(), body.ar_sha[0], body.ar_sha[1], body.ar_sha[2], body.ar_sha[3], body.ar_sha[4], body.ar_sha[5],
                tip_buf.data(), body.ar_tha[0], body.ar_tha[1], body.ar_tha[2], body.ar_tha[3], body.ar_tha[4], body.ar_tha[5]);
        }
        }
    }

    return res;
}

std::string Ip4Logger::process(std::shared_ptr<void> p) {
    std::string res;
    const ip4hdr_f* ip = static_cast<const ip4hdr_f*>(p.get());

    std::array<char, INET_ADDRSTRLEN> sip_buf{};
    std::array<char, INET_ADDRSTRLEN> tip_buf{};
    const char* r = inet_ntop(AF_INET, &ip->hdr.saddr, sip_buf.data(), sip_buf.size());
    assert(r);
    r = inet_ntop(AF_INET, &ip->hdr.daddr, tip_buf.data(), tip_buf.size());
    assert(r);

    res += "IP: ";
    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("{} -> {}; ", sip_buf.data(), tip_buf.data());
        break;
    }
    case LogLevel::VV: {
        res += std::format("Src: {} -> Dest: {}, TTL: {}, Proto: {};\n", sip_buf.data(), tip_buf.data(), ip->hdr.ttl, ip->hdr.protocol);
        break;
    }
    case LogLevel::VVV: {
        std::uint16_t flags = ntohs(ip->hdr.frag_off);
        bool reserved_flag = flags & 0b1000000000000000;
        bool df_flag = flags & 0b0100000000000000;
        bool mf_flag = flags & 0b0010000000000000;

        std::string proto_str{"Unknown"};
        switch (ip->hdr.protocol) {
            case IPPROTO_TCP: {
                proto_str = "TCP";
                break;
            }
            case IPPROTO_UDP: {
                proto_str = "UDP";
                break;
            }
            case IPPROTO_ICMP: {
                proto_str = "ICMP";
                break;
            }
            default: {
                break;
            }
        }

        res += std::format("\n    Src: {} -> Dest: {}\n    Total Len: {}, Flags: {}{}{}, TTL: {}\n    Protocol: {}({});\n",
            sip_buf.data(), tip_buf.data(), ntohs(ip->hdr.tot_len), reserved_flag ? "R" : ".", df_flag ? "D" : ".", mf_flag ? "M" : ".", ip->hdr.ttl,
            ip->hdr.protocol, proto_str);
        break;
    }
    }

    Protocols proto{};
    switch (ip->hdr.protocol) {
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
            return res;
            break;
        }
    }
    auto next_log = make_logger(proto, m_log_lvl);
    res += next_log->process(ip->plod);

    return res;
}

std::string Ip6Logger::process(std::shared_ptr<void> p) {
    std::string res;
    const ip6hdr_f* ip = static_cast<const ip6hdr_f*>(p.get());

    std::array<char, INET6_ADDRSTRLEN> saddr{};
    std::array<char, INET6_ADDRSTRLEN> taddr{};
    const char* r = inet_ntop(AF_INET6, &ip->hdr.saddr, saddr.data(), saddr.size());
    assert(r);
    r = inet_ntop(AF_INET6, &ip->hdr.daddr, taddr.data(), taddr.size());
    assert(r);

    res += "IPv6: ";
    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("{} -> {}; ", saddr.data(), taddr.data());
        break;
    }
    case LogLevel::VV: {
        res += std::format("Src: {} -> Dest: {}, TTL: {}, Protocol: {};\n", saddr.data(), taddr.data(), ip->hdr.hop_limit, ip->hdr.nexthdr);
        break;
    }
    case LogLevel::VVV: {
        std::string proto_str{"Unknown"};
        switch (ip->hdr.nexthdr) {
            case IPPROTO_TCP: {
                proto_str = "TCP";
                break;
            }
            case IPPROTO_UDP: {
                proto_str = "UDP";
                break;
            }
            case IPPROTO_ICMP: {
                proto_str = "ICMP";
                break;
            }
            default: {
                break;
            }
        }

        res += std::format("\n    Src: {} -> Dest: {}\n    Plod len: {}, TTL: {}\n    Protocol: {}({});\n",
            saddr.data(), taddr.data(), ntohs(ip->hdr.payload_len),
            ip->hdr.hop_limit, ip->hdr.nexthdr, proto_str);
        break;
    }
    }

    Protocols proto{};
    switch (ip->hdr.nexthdr) {
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
        case IPPROTO_ICMPV6: {
            proto = Protocols::ICMPv6;
            break;
        }
        default: {
            return res;
            break;
        }
    }
    auto next_logger = make_logger(proto, m_log_lvl);
    res += next_logger->process(ip->plod);
    return res;
}


std::string TcpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const tcphdr_f* tcp = static_cast<const tcphdr_f*>(p.get());

    res += "TCP: ";

    bool is_ack_set = tcp->hdr.ack;

    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("SPort: {}, TPort: {}, Seq: {}, Ack: {}; ", ntohs(tcp->hdr.source), ntohs(tcp->hdr.dest), ntohl(tcp->hdr.seq), is_ack_set ? ntohl(tcp->hdr.ack_seq) : 0);
        break;
    }
    case LogLevel::VV: {
        res += std::format("SPort: {}, TPort: {}, Seq: {}, Ack: {}, Win: {};\n",
            ntohs(tcp->hdr.source), ntohs(tcp->hdr.dest), ntohl(tcp->hdr.seq), is_ack_set ? ntohl(tcp->hdr.ack_seq) : 0,
            ntohs(tcp->hdr.window));
        break;
    }
    case LogLevel::VVV: {
        res += std::format("\n    SPort: {}, TPort: {}\n    Seq: {}, Ack: {}, Win: {}\n    Options: ",
            ntohs(tcp->hdr.source), ntohs(tcp->hdr.dest), ntohl(tcp->hdr.seq), is_ack_set ? ntohl(tcp->hdr.ack_seq) : 0, ntohs(tcp->hdr.window));

        if (tcp->options.size()) {
            res += "[";
            // auto* obytes = tcp->options.data();
            std::span<const char> obytes{tcp->options};
            // auto size = tcp->options.size();

            while (obytes.size()) {
                uint8_t kind;
                std::memcpy(&kind, obytes.data(), sizeof(kind));
                obytes = obytes.subspan(sizeof(kind));
                switch (kind) {
                    case 0: {
                        obytes = {};
                        break;
                    }
                    case 1: { // no-op
                        res += "no-op, ";
                        continue; // skip to next iteration
                        break;
                    }
                    case 8: {
                        constexpr auto ts_option_size = sizeof(tcpoption_ts);
                        tcpoption_ts ts;
                        if (obytes.size() < ts_option_size) {
                            break;
                        }
                        // It works only if option length takes option payoad into account, without kind and length itself
                        std::memcpy(&ts, obytes.data(), ts_option_size);
                        obytes = obytes.subspan(ts_option_size);

                        res += std::format("Ts [{}][{}], ", ts.ststmp, ts.ttstmp);

                        int pad_len = ts.olen - (sizeof(tcpoption_ts::ststmp) + sizeof(tcpoption_ts::ttstmp) + sizeof(kind) + sizeof(ts.olen));
                        if (pad_len <= 0) {
                            break;
                        }
                        obytes = obytes.subspan(pad_len); // Offset when there is padding

                        break;
                    }
                    default: {
                        break;
                    }
                }
            }
        }
        res.erase(res.end() - 2, res.end());
        res += "];\n";
        break;
    }
    }

    if (tcp->plod_proto == Protocols::TLS) {
        if (tcp->plod) {
            auto logger = make_logger(Protocols::TLS, m_log_lvl);
            res += logger->process(tcp->plod);
        }
    }
    return res;
}


std::string UdpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const udphdr_f* udp = static_cast<const udphdr_f*>(p.get());

    res += "UDP: ";
    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("SPort: {}, TPort: {}, Len: {}; ", ntohs(udp->hdr.source), ntohs(udp->hdr.dest), ntohs(udp->hdr.len));
    }
    case LogLevel::VV: {
        res += std::format("SPort: {}, TPort: {}, Len: {}; \n", ntohs(udp->hdr.source), ntohs(udp->hdr.dest), ntohs(udp->hdr.len));
        break;
    }
    case LogLevel::VVV: {
        res += std::format("\n    SPort: {}, TPort: {}\n    Len: {}; \n", ntohs(udp->hdr.source), ntohs(udp->hdr.dest), ntohs(udp->hdr.len));
        break;
    }
    }
    return res;
}

std::string IcmpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const icmphdr_f* icmp = static_cast<const icmphdr_f*>(p.get());

    res += "ICMP: ";
    std::string type;
    switch (icmp->hdr.type) {
        case 8: {
            type = "echo request";
            break;
        }
        case 0: {
            type = "echo reply";
            break;
        }
        default: {
            type = "Unknown";
            break;
        }
    }
    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("{}, code: {}; ", type, icmp->hdr.code);
        break;
    }
    case LogLevel::VV: {
        res += std::format("{}, code: {};\n", type, icmp->hdr.code);
        break;
    }
    case LogLevel::VVV: {
        res += std::format("\n    {}, code: {}; ", type, icmp->hdr.code);
        break;
    }
    }
    return res;
}

std::string Icmp6Logger::process(std::shared_ptr<void> p) {
    std::string res;
    const icmphdr_f* icmp = static_cast<const icmphdr_f*>(p.get());

    res += "ICMPv6: ";
    std::string type;
    switch (icmp->hdr.type) {
        case 128: {
            type = "echo request";
            break;
        }
        case 129: {
            type = "echo reply";
            break;
        }
        default: {
            type = "Unknown";
            break;
        }
    }
    switch (m_log_lvl) {
    case LogLevel::V: {
        res += std::format("type: {}, code: {}; ", type, icmp->hdr.code);
        break;
    }
    case LogLevel::VV: {
        res += std::format("type: {}, code: {};\n", type, icmp->hdr.code);
        break;
    }
    case LogLevel::VVV: {
        res += std::format("\n    type: {}, code: {}; ", type, icmp->hdr.code);
        break;
    }
    }
    return res;
}

 std::string TlsLogger::process(std::shared_ptr<void> p) {
     std::string res;


     const tlsrecords* tls_rec = static_cast<const tlsrecords*>(p.get());
     if (tls_rec->records.empty()) {
         return res;
     }
     res += "TLS: ";
     for (const auto& rec : tls_rec->records) {
        switch (m_log_lvl) {
        case LogLevel::V: {
            res += std::format("Content type: {:#02x}; ", rec.content_type);
            break;
        }
        case LogLevel::VV: {
            res += std::format("Content type: {:#02x}, Version: {:#04x}, Length: {};\n", rec.content_type, ntohs(rec.version), ntohs(rec.length));
            break;
        }
        case LogLevel::VVV: {
            std::string ctype;
            switch (rec.content_type) {
                case 0x14: {
                    ctype = "ChangeCipherSpec";
                    break;
                }
                case 0x15: {
                    ctype = "Alert";
                    break;
                }
                case 0x16: {
                    ctype = "Handshake";
                    break;
                }
                case 0x17: {
                    ctype = "Application";
                    break;
                }
                case 0x18: {
                    ctype = "Heartbeat";
                    break;
                }
            }
            res += std::format("    Content type: {:#02x}({}), Version: {:#04x}, Length: {};\n", rec.content_type, ctype, ntohs(rec.version), ntohs(rec.length));
            break;
        }
        }
     }
     return res;
 }

 void print_entry(const Entry& en) {
    std::array<char, INET6_ADDRSTRLEN> sbuf{};
    std::array<char, INET6_ADDRSTRLEN> tbuf{};
    if (en.eth_proto == htons(ETH_P_IP)) {
        const char* r = inet_ntop(AF_INET, en.saddr.data(), sbuf.data(), sbuf.size());
        assert(r);
        r = inet_ntop(AF_INET, en.taddr.data(), tbuf.data(), tbuf.size());
        assert(r);
    } else if (en.eth_proto == htons(ETH_P_IPV6)) {
        const char* r = inet_ntop(AF_INET6, en.saddr.data(), sbuf.data(), tbuf.size());
        assert(r);
        r = inet_ntop(AF_INET6, en.taddr.data(), tbuf.data(), tbuf.size());
        assert(r);
    }


    std::println("{}:\n    SHAddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, THAddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, EtherType: {:#04x}\n    SAddr: {}, TAddr: {}, IP Proto: {}\n    SPort: {}, TPort: {}",
        std::chrono::system_clock::from_time_t(be64toh(en.ts)),
        en.shaddr[0], en.shaddr[1], en.shaddr[2], en.shaddr[3], en.shaddr[4], en.shaddr[5],
        en.thaddr[0], en.thaddr[1], en.thaddr[2], en.thaddr[3], en.thaddr[4], en.thaddr[5],
        ntohs(en.eth_proto),
        (en.eth_proto == htons(ETH_P_IP) || en.eth_proto == htons(ETH_P_IPV6)) ? sbuf.data() : "-", (en.eth_proto == htons(ETH_P_IP) || en.eth_proto == htons(ETH_P_IPV6)) ? tbuf.data() : "-",
        en.ip_proto,
        ntohs(en.sport), ntohs(en.tport)
    );
 }
