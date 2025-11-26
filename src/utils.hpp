#pragma once
#include <expected>
#include <netinet/in.h>
#include <string>
#include <vector>
#include <array>

template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};

constexpr std::string_view ANY_INTERFACE = "any";
std::vector<std::string> show_interfaces();

std::expected<in_addr_t, std::string> convert_to_addr(const std::string& addr_str);
std::expected<std::array<char, 6>, std::string> convert_to_mac(const std::string& mac_str);
