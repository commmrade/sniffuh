#include <net/if.h>
#include "sniffer.hpp"
#include <chrono>
#include <linux/in6.h>
#include "packet.hpp"
#include "parser.hpp"
#include "logs.hpp"
#include "utils.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <print>
#include <span>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/ioctl.h>

Sniffer::Sniffer(std::string_view if_name) {
    setup(if_name);
}
Sniffer::~Sniffer() {
    close(m_sock);
}

void Sniffer::setup(std::string_view if_name) {
    int ret;
    m_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_sock < 0) {
        perror("socket");
        throw std::runtime_error("Socket creation failed");
    }

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = if_nametoindex(if_name.data());
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(m_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("setsockopt");
        throw std::runtime_error("Could not set sock opt promisc mode");
    } // enable promisicsdsdj mode

    sockaddr_ll addr{};
    socklen_t addr_len = sizeof(addr);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(if_name.data());
    if (!addr.sll_ifindex) {
        perror("if_nametoindex");
        throw std::runtime_error("nametoindex failed");
    }

    ret = bind(m_sock, (sockaddr*)&addr, addr_len);
    if (ret < 0) {
        perror("bind");
        throw std::runtime_error("Could not bind");
    }
}

static void print_entry(Entry& en) {
    std::println("=====");
    std::println("Ts: {}", en.ts);
    std::println("Shaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", en.shaddr[0], en.shaddr[1], en.shaddr[2], en.shaddr[3], en.shaddr[4], en.shaddr[5]);
    std::println("Thaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", en.thaddr[0], en.thaddr[1], en.thaddr[2], en.thaddr[3], en.thaddr[4], en.thaddr[5]);
    std::println("Eth proto: {:#04x}", ntohs(en.eth_proto));
    if (en.eth_proto == ntohs(ETH_P_IP)) {
        char buf[INET_ADDRSTRLEN];
        const char* r = inet_ntop(AF_INET, en.saddr.data(), buf, sizeof(buf));
        assert(r);
        std::println("Source addr: {}", buf);
        r = inet_ntop(AF_INET, en.taddr.data(), buf, sizeof(buf));
        assert(r);
        std::println("Dest addr: {}", buf);
    }
    std::println("IP proto: {}", en.ip_proto);
    std::println("Sport: {}", ntohs(en.sport));
    std::println("Dport: {}", ntohs(en.dport));

    std::println("=====");
}

void Sniffer::process_packet(std::span<char> p) {
    auto packet = parse_packet(p);
    if (packet.first.plod) {
        auto output = log_packet(packet.first, LogLevel::VVV);
        std::println("{}", output);
        m_writer.add(packet.second);
    }
}

void Sniffer::sniff_loop() {
    while (true) {
        std::array<char, (1 << 16)> buf;
        ssize_t rd_bytes = recv(m_sock, buf.data(), sizeof(buf), 0);
        if (rd_bytes <= 0) {
            perror("recv");
            throw std::runtime_error("Recv failed");
        }
        std::span<char> p{buf.data(), static_cast<size_t>(rd_bytes)};
        process_packet(p);
    }
}
