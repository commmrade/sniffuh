#include <chrono>

enum class IpType : std::uint8_t {
    V4,
    V6
};

struct Entry { // Big endian for cross platofr
    std::chrono::time_point<std::chrono::system_clock> ts;
    std::array<char, 6> shaddr;
    std::array<char, 6> thaddr;

    // IPv4 || IPv6
    IpType p_type;
    std::array<char, 16> saddr;
    std::array<char, 16> taddr;

    std::uint16_t sport;
    std::uint16_t dport;
};

/*
1. Create a Entry entry;
2. Pass Entry& to Ethernet handler, it fills shaddr and thaddr
3. Pass Entry& from Ethernet handler to IP handler and fill saddr and taddr
4. Pass Entry& from IP Handler to TCP/UDP handler and fill port fields

// But it is kinda tideous, and follows the same chain of resp pattern, therefore it is better to find other ways of doing it, although there are not many
// Here are all the ways:
- Do it in a single function which peeks inside Eth, then IP, then TCP/UDP
- Chain of Responsibility shit
- Fill Entry in Logs chain of responsibility
*/