#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
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

std::vector<std::string> show_interfaces();

ethhdr parse_eth(std::span<char> bytes);

struct arphdr_f { // ONLY FOR IPv4
    arphdr hdr;
    std::vector<char> plod;
};
#pragma pack(push, 1)
struct arphdr_ipv4 {
    unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
};
#pragma pack(pop)

arphdr_f parse_arp(std::span<char> bytes);
void print_arp(arphdr_f& arp);

struct iphdr_f {
	iphdr hdr;
	std::vector<char> options;
};

iphdr_f parse_ip(std::span<char> bytes);
void print_ip(iphdr_f& ip);


struct tcphdr_f {
    tcphdr hdr;
    std::vector<char> options;
};
tcphdr_f parse_tcp(std::span<char> bytes);
void print_tcp(tcphdr_f& tcp);

udphdr parse_udp(std::span<char> bytes);
void print_udp(udphdr& udp);
