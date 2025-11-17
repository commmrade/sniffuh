#pragma once
#include <chrono>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <memory>
#include <linux/if_arp.h>
#include <vector>

struct Packet {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::shared_ptr<void> plod;
};

struct ethhdr_f {
    ethhdr hdr;
    std::shared_ptr<void> plod;
};
enum class Protocols {
    ETH,
    ARP,
    IP,
    TCP,
    UDP,
    ICMP,
    HTTP,
    DNS
};

struct arphdr_f {
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


struct iphdr_f {
	iphdr hdr;
	std::vector<char> options;
	std::shared_ptr<void> plod;
};

struct tcphdr_f {
    tcphdr hdr;
    std::vector<char> options;
    std::shared_ptr<void> plod;
};

struct icmphdr_f {
    icmphdr hdr;
};

struct udphdr_f {
    udphdr hdr;
    std::shared_ptr<void> plod;
};
