#include "server.hpp"
#include "utils.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <span>
#include <stdexcept>
#include <sys/socket.h>
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

Server::Server(std::string_view if_name) {
    setup(if_name);
}
Server::~Server() {
    close(m_sock);
}

void Server::setup(std::string_view if_name) {
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

void Server::process_packet(std::span<char> p) {
    auto eth = parse_eth(p);
    p = p.subspan(sizeof(eth));
    if (ntohs(eth.h_proto) == 0x0800) {
        auto ip = parse_ip(p);
        auto ip_size = ip.hdr.ihl * 4;
        p = p.subspan(ip_size);
        print_ip(ip);
        if (ip.hdr.protocol == 6) { // tcp
            auto tcp = parse_tcp(p);
            p = p.subspan(tcp.hdr.doff * 4);
            print_tcp(tcp);
        } else if (ip.hdr.protocol == 17) { // udp
            auto udp = parse_udp(p);
            p = p.subspan(sizeof(udp));
            print_udp(udp);
        }
    } else if (ntohs(eth.h_proto) == 0x0806) {
        auto arp = parse_arp(p);
        p = p.subspan(sizeof(arp));
        print_arp(arp);
    }
}

void Server::sniff_loop() {
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
