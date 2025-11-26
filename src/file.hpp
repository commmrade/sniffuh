#pragma once
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <nlohmann/json_fwd.hpp>
#include <vector>

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
    std::uint16_t tport;
};

void to_json(nlohmann::json& j, const Entry& en);
void from_json(const nlohmann::json& j, Entry& en);

std::vector<Entry> read_file(const std::string_view filename);

class Writer {
    std::vector<Entry> m_entries;
    std::mutex m_mutex;
    int m_cnter{};
    int m_interval{};

    std::string_view m_filename;

    void write_to_file();
public:
    Writer(int write_interval = 10, std::string_view filename = "test.json");
    void store(const Entry& en);
};
