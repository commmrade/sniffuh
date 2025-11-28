#include "utils.hpp"
#ifdef __linux__
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#elif _WIN32
#include <winsock2.h>      // Must include before windows.h
#include <ws2tcpip.h>
#include <iphlpapi.h>      // For GetAdaptersAddresses
#include <Windows.h>
#include <format>
#endif
#include <stdexcept>
#include <ranges>

std::vector<std::string> show_interfaces() {
    int ret;
    std::vector<std::string> ifs;
#ifdef __linux__
    ifaddrs *ifap, *p;

    ret = getifaddrs(&ifap);
    if (ret < 0) {
        std::perror("getifaddrs");
        throw std::runtime_error("getifaddrs failed");
    }
    defer ifaddrsfree{[ifap] { freeifaddrs(ifap); }};

    for (p = ifap; p != NULL; p = p->ifa_next) {
        ifs.emplace_back(p->ifa_name);
    }
#elif _WIN32
    IP_ADAPTER_ADDRESSES* head, * cur;
    int len{};
    head = new IP_ADAPTER_ADDRESSES[100];
    defer headfree{ [head] { delete[] head; } };

    ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, head, (PULONG)&len);
    if (ret != ERROR_SUCCESS) {
        throw std::runtime_error(std::format("GetAdapterAddrs failed: {}", ret));
    }
    for (cur = head; cur != NULL; cur = cur->Next) {
        ifs.emplace_back(cur->AdapterName);
    }
#endif
    ifs.emplace_back(ANY_INTERFACE);
    return ifs;
}

std::expected<std::array<char, 16>, std::string> convert_to_addr(const std::string& addr_str) {
    std::array<char, 16> addr{};
    int r;
    r = inet_pton(addr_str.contains(":") ? AF_INET6 : AF_INET, addr_str.c_str(), addr.data());
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
