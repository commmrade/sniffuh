#include "utils.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdexcept>
#include <ranges>

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
    ifs.emplace_back(ANY_INTERFACE);
    return ifs;
}

std::expected<in_addr_t, std::string> convert_to_addr(const std::string& addr_str) {
    in_addr_t addr{};
    int r = inet_pton(AF_INET, addr_str.c_str(), &addr);
    switch (r) {
        case 1: { // all good
            return {addr};
            break;
        }
        case 0: {
            return std::unexpected("Address string does not represent a valid network address");
            break;
        }
        case -1: {
            return std::unexpected("Error when converting address");
            break;
        }
        default: {
            return std::unexpected("Unexpected error");
            break;
        }
    }
}

std::expected<std::array<char, 6>, std::string> convert_to_mac(const std::string& mac_str) {
    std::array<char, 6> raddr{};
    auto mac = std::views::split(mac_str, ':') | std::ranges::to<std::vector<std::string>>();
    if (mac.size() != 6) {
        return std::unexpected("Hardware address is invalid");
    }
    for (std::size_t i = 0; i < raddr.size(); ++i) {
        raddr[i] = std::stoi(mac[i], nullptr, 16);
    }
    return {raddr};
}
