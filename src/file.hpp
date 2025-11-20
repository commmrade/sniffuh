#include <chrono>

struct Entry { // Big endian for cross platofr
    std::chrono::time_point<std::chrono::system_clock> ts;
    std::array<char, 6> shaddr;
    std::array<char, 6> thaddr;

    // IPv4 || IPv6
    std::uint8_t p_type;
    std::array<char, 16> saddr;
    std::array<char, 16> taddr;

    std::uint16_t sport;
    std::uint16_t dport;
};
