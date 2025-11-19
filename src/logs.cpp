#include "logs.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <format>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <print>

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

std::string log_packet(Packet& pkt) {
    auto log = make_logger(Protocols::ETH);
    std::string r{std::format("Timestamp: {}\n", pkt.timestamp)};
    r += log->process(pkt.plod);
    return r;
}

std::unique_ptr<Logger> make_logger(Protocols proto) {
    switch (proto) {
        case Protocols::ETH: {
            return std::make_unique<EthLogger>();
            break;
        }
        case Protocols::ARP: {
            return std::make_unique<ArpLogger>();
            break;
        }
        case Protocols::IP: {
            return std::make_unique<IpLogger>();
            break;
        }
        case Protocols::TCP: {
            return std::make_unique<TcpLogger>();
            break;;
        }
        case Protocols::UDP: {
            return std::make_unique<UdpLogger>();
            break;
        }
        case Protocols::ICMP: {
            return std::make_unique<IcmpLogger>();
            break;
        }
        case Protocols::TLS: {
            return std::make_unique<TlsLogger>();
            break;
        }
        default: {
            throw std::runtime_error("Parser type is not supported");
            break;
        }
    }
}

std::string EthLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const ethhdr_f* eth = static_cast<const ethhdr_f*>(p.get());
    auto proto = ntohs(eth->hdr.h_proto) == 0x0800 ? Protocols::IP : Protocols::ARP;
    auto next_log = make_logger(proto);
    res += next_log->process(eth->plod);
    return res;
}

std::string ArpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const arphdr_f* arp = static_cast<const arphdr_f*>(p.get());

    res += std::format("==========\nHardware type: {}\nProtocol type: {:#06x}\nHardware length: {}\nProtocol length: {}\nOperation: {}\n", ntohs(arp->hdr.ar_hrd), ntohs(arp->hdr.ar_pro), arp->hdr.ar_hln, arp->hdr.ar_pln, ntohs(arp->hdr.ar_op));
    if (ntohs(arp->hdr.ar_hrd) == 1 && ntohs(arp->hdr.ar_pro) == 0x0800) { // mac and ipv4
        if (arp->plod.size() < sizeof(arphdr_ipv4)) {
            throw std::runtime_error("ARP payload isn't big enough");
        }
        arphdr_ipv4 body{};
        std::memcpy(&body, arp->plod.data(), sizeof(body));

        char addr_buf[INET_ADDRSTRLEN]{};

        const char* r = inet_ntop(AF_INET, body.ar_sip, addr_buf, sizeof(addr_buf));
        res += std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Source, ", body.ar_sha[0], body.ar_sha[1], body.ar_sha[2], body.ar_sha[3], body.ar_sha[4], body.ar_sha[5]);
        res += std::format("Sender IP: {}\n", addr_buf);

        r = inet_ntop(AF_INET, body.ar_tip, addr_buf, sizeof(addr_buf));
        res += std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Target, ", body.ar_tha[0], body.ar_tha[1], body.ar_tha[2], body.ar_tha[3], body.ar_tha[4], body.ar_tha[5]);
        res += std::format("Target IP: {}\n==========", addr_buf);
    } else {
        res += std::format("***This ARP hardware address and protocol address are not supported***");
    }
    return res;
}

std::string IpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const iphdr_f* ip = static_cast<const iphdr_f*>(p.get());

    res += std::format("======== IP\n");

    int ver = ip->hdr.version;
    int ihl = ip->hdr.ihl;
    res += std::format("Version: {}\nIHL: {}\nTotal length: {}\nId: {}\nFrag off: {}\nTtl: {}\nProtocol: {}\nCheck: {}\n",
        ver, ihl, ntohs(ip->hdr.tot_len), ntohs(ip->hdr.id), ntohs(ip->hdr.frag_off), ip->hdr.ttl, ip->hdr.protocol, ntohs(ip->hdr.check));

    char addr_buf[INET_ADDRSTRLEN];
    const char* r = inet_ntop(AF_INET, &ip->hdr.saddr, addr_buf, sizeof(addr_buf));
    res += std::format("Source IP: {}, ", addr_buf);
    r = inet_ntop(AF_INET, &ip->hdr.daddr, addr_buf, sizeof(addr_buf));
    res += std::format("Destination IP: {}\n", addr_buf);

    res += std::format("========\n");

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
            break;
        }
    }
    auto next_log = make_logger(proto);
    res += next_log->process(ip->plod);

    return res;
}


std::string TcpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const tcphdr_f* tcp = static_cast<const tcphdr_f*>(p.get());

    res += std::format("======== TCP****\n");
    res += std::format("Source port: {}, ", ntohs(tcp->hdr.source));
    res += std::format("Dest port: {}\n", ntohs(tcp->hdr.dest));
    res += std::format("Seq Num: {}, ", ntohl(tcp->hdr.seq));
    res += std::format("Ack Num: {}\n", ntohl(tcp->hdr.ack_seq));
    auto doff = tcp->hdr.doff;
    res += std::format("Data offset (in bytes): {}, ", (doff - 5) * 4);
    res += std::format("Window: {}, ", ntohs(tcp->hdr.window));
    res += std::format("Urg: {}\n", ntohs(tcp->hdr.urg_ptr));

    auto options_size = (tcp->hdr.doff * 4) - sizeof(tcphdr);
    if (options_size) {
        res += std::format("Options:\n");
        auto* obytes = tcp->options.data();
        auto size = tcp->options.size();

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
                    res += std::format("    Kind: {}\n", kind);
                    continue; // skip to next iteration
                    break;
                }
                case 8: {
                    uint8_t olen;
                    std::memcpy(&olen, obytes, sizeof(olen));
                    obytes += sizeof(olen);
                    size -= sizeof(olen);
                    olen -= sizeof(olen) + sizeof(kind); // how many bytes in payload

                    res += std::format("    Kind: {}, Olen: {}\n", kind, olen);
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
                    res += std::format("    Sender timestamp: {}, Reply timestamp: {}\n", ststmp, ttstmp);

                    olen -= sizeof(ststmp) + sizeof(ttstmp);
                    if (olen < 0) {
                        throw std::runtime_error("Packet is corrupted");
                    }
                    obytes += olen;
                    size -= olen;
                    break;
                }
                default: {
                    break;
                }
            }
        }
    }
    res += std::format("========\n");

    if (tcp->plod_proto == Protocols::TLS) {
        if (tcp->plod) {
            auto logger = make_logger(Protocols::TLS);
            res += logger->process(tcp->plod);
        }
    }
    return res;
}


std::string UdpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const udphdr_f* udp = static_cast<udphdr_f*>(p.get());

    res += std::format("======= UDP******\n");
    res += std::format("Source port: {}, ", ntohs(udp->hdr.source));
    res += std::format("Dest port: {}\n", ntohs(udp->hdr.dest));
    res += std::format("Length: {}\n", ntohs(udp->hdr.len));
    res += std::format("=======\n");

    return res;
}

std::string IcmpLogger::process(std::shared_ptr<void> p) {
    std::string res;
    const icmphdr_f* icmp = static_cast<const icmphdr_f*>(p.get());

    res += std::format("===== ICMP*****\n");
    res += std::format("Type: {}\nCode: {}\nChecksum: {:#04x}\n", icmp->hdr.type, icmp->hdr.code, ntohs(icmp->hdr.checksum));
    res += std::format("=====");

    return res;
}

 std::string TlsLogger::process(std::shared_ptr<void> p) {
     std::string res;
     const tlsrecords* tls_rec = static_cast<const tlsrecords*>(p.get());
     for (const auto& rec : tls_rec->records) {
         res += std::format("===== TLS RECORD\n    Content type: {:#02x}, Legacy version: {:#04x}, Length: {}\n=====", rec.content_type, ntohs(rec.version), ntohs(rec.length));
     }
     return res;
 }
