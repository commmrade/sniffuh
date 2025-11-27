#pragma once
#include <chrono>

namespace pdor {
/// Everything is in big endian
struct Entry {
    std::uint64_t ts;
    std::array<char, 6> shaddr;
    std::array<char, 6> thaddr;
    std::uint16_t eth_proto;

    // IPv4 || IPv6
    std::array<char, 16> saddr;
    std::array<char, 16> taddr;
    std::uint8_t ip_proto;

    std::uint16_t sport;
    std::uint16_t tport;
};

namespace detail {
#pragma pack(push, 1)
struct Entry__ {
    std::uint64_t ts;
    std::array<char, 6> shaddr;
    std::array<char, 6> thaddr;
    std::uint16_t eth_proto;

    // IPv4 || IPv6
    std::array<char, 16> saddr;
    std::array<char, 16> taddr;
    std::uint8_t ip_proto;

    std::uint16_t sport;
    std::uint16_t tport;
};
#pragma pack(pop)
}
} // namespace pdor
