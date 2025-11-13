#include <cassert>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <print>
#include <stdexcept>
#include <sys/socket.h>
#include <vector>
#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/ioctl.h>

#define TODO(x) throw std::runtime_error(std::format("TODO: {}", x))

template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};

void show_interfaces() {
    int ret;
    ifaddrs *ifap, *p;

    ret = getifaddrs(&ifap);
    if (ret < 0) {
        std::perror("getifaddrs");
        throw std::runtime_error("getifaddrs failed");
    }
    defer ifaddrsfree{[ifap] {
        freeifaddrs(ifap);
    }};

    for (p = ifap; p != NULL; p = p->ifa_next) {
        std::println("Interface name: {}", p->ifa_name);
    }
}


ethhdr parse_eth(char* bytes, size_t bytes_size) {
    ethhdr result; // TODO: FIx vlan
    if (bytes_size < sizeof(ethhdr)) {
        throw std::runtime_error("Buf is too short to parse eth header");
    }
    std::memcpy(&result, bytes, sizeof(ethhdr));
    return result;
}

struct arphdr_f { // ONLY FOR IPv4
	uint16_t		ar_hrd;		/* format of hardware address	*/
	uint16_t		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	uint16_t		ar_op;		/* ARP opcode (command)		*/
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
};

arphdr_f parse_arp(char* bytes, size_t bytes_size) {
    arphdr_f result;
    if (bytes_size < sizeof(result)) {
        throw std::runtime_error("Buf is too short to parse arp");
    }

    std::memcpy(&result, bytes, sizeof(arphdr_f));
    return result;
}

void print_arp(arphdr_f& arp) {
    std::println("==========\nHardware type: {}\nProtocol type: {:#06x}\nHardware length: {}\nProtocol length: {}\nOperation: {}", ntohs(arp.ar_hrd), ntohs(arp.ar_pro), arp.ar_hln, arp.ar_pln, ntohs(arp.ar_op));
    std::println("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Source", arp.ar_sha[0], arp.ar_sha[1], arp.ar_sha[2], arp.ar_sha[3], arp.ar_sha[4], arp.ar_sha[5]);
    std::println("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - Target", arp.ar_tha[0], arp.ar_tha[1], arp.ar_tha[2], arp.ar_tha[3], arp.ar_tha[4], arp.ar_tha[5]);

    char addr_buf[INET_ADDRSTRLEN]{};
    void* saddr = nullptr;

    const char* r = inet_ntop(AF_INET, arp.ar_sip, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Sender IP: {}", addr_buf);

    r = inet_ntop(AF_INET, arp.ar_tip, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Target IP: {}\n==========", addr_buf);
}

iphdr parse_ip(char* bytes, size_t bytes_size) {
    iphdr result{};
    if (bytes_size < sizeof(result)) {
        throw std::runtime_error("Buffer is too short for iphdr");
    }

    std::memcpy(&result, bytes, sizeof(result));
    if (result.version == 6) {
        throw std::runtime_error("IPv6 not supported yet");
    }
    // TODO: Options if any
    return result;
}

void print_ip(iphdr& ip) {
    std::println("========");

    int ver = ip.version;
    int ihl = ip.ihl;
    std::println("Version: {}\nIHL: {}\nTotal length: {}\nId: {}\nFrag off: {}\nTtl: {}\nProtocol: {}\nCheck: {}",
        ver, ihl, ntohs(ip.tot_len), ntohs(ip.id), ntohs(ip.frag_off), ip.ttl, ip.protocol, ntohs(ip.check));

    char addr_buf[INET_ADDRSTRLEN];
    const char* r = inet_ntop(AF_INET, &ip.saddr, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Source IP: {}", addr_buf);
    r = inet_ntop(AF_INET, &ip.daddr, addr_buf, sizeof(addr_buf));
    assert(r);
    std::println("Destination IP: {}", addr_buf);
    std::println("========");
}

tcphdr parse_tcp(char* bytes, size_t bytes_size) {
    tcphdr result{};
    if (bytes_size < sizeof(result)) {
        throw std::runtime_error("Buf is not big enough to parse TCP");
    }
    std::memcpy(&result, bytes, sizeof(result));
    if (result.doff > 5) {
        auto doff = result.doff;
        // throw std::runtime_error(std::format("Options is not supported in tcp: {}", doff));
    }
    // TODO: Options
    return result;
}

void print_tcp(tcphdr& tcp) {
    std::println("======== TCP****");
    std::println("Source port: {}", ntohs(tcp.source));
    std::println("Dest port: {}", ntohs(tcp.dest));
    std::println("Seq Num: {}", ntohl(tcp.seq));
    std::println("Ack Num: {}", ntohl(tcp.ack_seq));
    auto doff = tcp.doff;
    std::println("Data offset (in bytes): {}", (doff - 5) * 4);
    std::println("Window: {}", ntohs(tcp.window));
    std::println("Urg: {}", ntohs(tcp.urg_ptr));
    // TODO: OPTIONS
    std::println("========");
}

udphdr parse_udp(char* bytes, size_t bytes_size) {
    udphdr result{};
    if (bytes_size < sizeof(result)) {
        throw std::runtime_error("Buf is not big enough to parse UDP");
    }
    std::memcpy(&result, bytes, sizeof(result));
    return result;
}

void print_udp(udphdr& udp) {
    std::println("======= UDP******");
    std::println("Source port: {}", ntohs(udp.source));
    std::println("Dest port: {}", ntohs(udp.dest));
    std::println("Length: {}", ntohs(udp.len));
    std::println("=======");
}

int main(int argc, char** argv) {
    iphdr s;
    int ret;

    show_interfaces();
    if (geteuid() != 0) {
        throw std::runtime_error("Should be ran as root");
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        throw std::runtime_error("Socket creation failed");
    }
    defer sock_close{[sock] {
        close(sock);
    }};

    const char* interface_name = "enp8s0";

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = if_nametoindex(interface_name);
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        throw std::runtime_error("setsockopt failed");
    } // enable promisicsdsdj mode

    sockaddr_ll addr{};
    socklen_t addr_len = sizeof(addr);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(interface_name);
    if (!addr.sll_ifindex) {
        perror("if_nametoindex");
        throw std::runtime_error("nametoindex failed");
    }

    ret = bind(sock, (sockaddr*)&addr, addr_len);
    if (ret < 0) {
        perror("bind");
        throw std::runtime_error("Could not bind");
    }




    while (true) {
        char buf[(1 << 16)];
        char* p = buf;
        ssize_t rd_bytes = recv(sock, buf, sizeof(buf), 0);
        if (rd_bytes <= 0) {
            perror("recv");
            throw std::runtime_error("Recv failed");
        }
        size_t buf_size = rd_bytes;

        auto eth = parse_eth(p, buf_size);
        p += sizeof(eth);
        buf_size -= sizeof(eth);


        if (ntohs(eth.h_proto) == 0x0800) {
            // std::println("IP");
            auto ip = parse_ip(p, buf_size);
            // p += sizeof(ip);
            // buf_size -= sizeof(ip);
            p += ip.ihl * 4;
            buf_size = ip.ihl * 4;
            // TODO: move ptr by options bytes
            print_ip(ip);

            // std::println("Protocol: {}", ip.protocol);
            if (ip.protocol == 6) { // tcp
                auto tcp = parse_tcp(p, buf_size);
                // p += sizeof(tcp);
                // buf_size -= sizeof(tcp);
                p += tcp.doff * 4;
                buf_size -= tcp.doff * 4;
                // TOOD: Move ptr by options bytes
                print_tcp(tcp);
            } else if (ip.protocol == 17) { // udp
                auto udp = parse_udp(p, buf_size);
                p += sizeof(udp);
                buf_size -= sizeof(udp);
                print_udp(udp);
            }
        } else if (ntohs(eth.h_proto) == 0x0806) {
            auto arp = parse_arp(p, buf_size);
            p += sizeof(arp);
            buf_size -= sizeof(arp);
            // print_arp(arp);
        }
    }

    return 0;
}
