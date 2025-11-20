#include <chrono>

enum class IpType : std::uint8_t {
    V4,
    V6
};

struct Entry { // Big endian for cross platofr
    std::chrono::time_point<std::chrono::system_clock> ts;
    std::array<char, 6> shaddr;
    std::array<char, 6> thaddr;
    std::uint32_t eth_proto;

    // IPv4 || IPv6
    std::array<char, 16> saddr;
    std::array<char, 16> taddr;
    std::uint8_t ip_proto;

    std::uint16_t sport;
    std::uint16_t dport;
};

/*
TODO: Write to file as json array
*/
