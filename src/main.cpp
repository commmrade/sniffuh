#include <cstdio>
#include <cstring>
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
    ethhdr result;
    if (bytes_size < sizeof(ethhdr)) {
        throw std::runtime_error("Buf is too short to parse eth header");
    }

    memcpy(result.h_dest, bytes, sizeof(result.h_dest));
    bytes += sizeof(result.h_dest);
    memcpy(result.h_source, bytes, sizeof(result.h_dest));
    bytes += sizeof(result.h_source);

    uint16_t proto_net;
    memcpy(&proto_net, bytes, sizeof(proto_net));
    proto_net = ntohs(proto_net);
    result.h_proto = proto_net;

    return result;
}

struct arphdr_f { // ONLY FOR IPv4
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
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

    uint16_t htype; // 1 for ethernet
    std::memcpy(&htype, bytes, sizeof(htype));
    htype = ntohs(htype);
    bytes += sizeof(htype);

    uint16_t hproto;
    std::memcpy(&hproto, bytes, sizeof(hproto));
    hproto = ntohs(hproto);
    bytes += sizeof(hproto);

    TODO("To be continued");
    return result;
}


int main(int argc, char** argv) {
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

    sockaddr_ll addr{};
    socklen_t addr_len = sizeof(addr);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex("enp8s0");
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


        if (eth.h_proto == 0x0800) {
            // std::println("IP");
        } else if (eth.h_proto == 0x0806) {
            parse_arp(p, buf_size);
            std::println("ARP");
        }
    }

    return 0;
}
