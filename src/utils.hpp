#pragma once
#include <expected>
#ifdef __linux
#include <netinet/in.h>

#elif _WIN32
#endif
#include <string>
#include <vector>
#include <array>

#endif


template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};

constexpr std::string_view ANY_INTERFACE = "any";
std::vector<std::string> show_interfaces();

std::expected<std::array<char, 16>, std::string> convert_to_addr(const std::string& addr_str);
std::expected<std::array<char, 6>, std::string> convert_to_mac(const std::string& mac_str);
