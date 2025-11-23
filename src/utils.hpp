#pragma once
#include <string>
#include <vector>

template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};

constexpr std::string_view ANY_INTERFACE = "any";
std::vector<std::string> show_interfaces();
