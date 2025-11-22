#include "logs.hpp"
#include "parser.hpp"
#include "sniffer.hpp"
#include <print>
#include <stdexcept>


static void print_entry(const Entry& en) {
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

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    if (argc < 2) {
        std::println("Usage: {} <log || store>", argv[0]);
        return -1;
    }

    if (!strcmp(argv[1], "log")) {
        // TODO: Connect signal handler
        auto vec = show_interfaces();
        if (geteuid() != 0) {
            throw std::runtime_error("Should be ran as root");
        }

        Sniffer s{vec[1]};
        s.sniff_loop();
    } else if (!strcmp(argv[1], "read")) {
        auto entries = read_file("test.json");
        for (const auto& en : entries) {
            print_entry(en);
        }
    } else {
        throw std::runtime_error("Invalid mode");
    }

    return 0;
}
