#pragma once

template <typename Action>
struct defer {
    Action f_;
    ~defer() {
        f_();
    }
};

enum class ethProto {
    IPv4 = 0x0800,
    ARP = 0x0806
};
