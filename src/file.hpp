#include <chrono>
#include <exception>
#include <fstream>
#include <ios>
#include <mutex>
#include <netinet/in.h>
#include <nlohmann/json_fwd.hpp>
#include <print>
#include <ratio>
#include <thread>
#include <vector>
#include "nlohmann/json.hpp"
#include "endian.h"

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

inline void to_json(nlohmann::json& j, const Entry& en) {
    using a = std::milli;
    auto time_ms = std::chrono::duration_cast<std::chrono::seconds>(en.ts.time_since_epoch()).count();
    j = nlohmann::json{ // TODO: Not cross architecture
        {"ts", htobe64(time_ms)},
        {"shaddr", en.shaddr},
        {"thaddr", en.thaddr},
        {"eth_proto", en.eth_proto},
        {"saddr", en.saddr},
        {"taddr", en.taddr},
        {"ip_proto", en.ip_proto},
        {"sport", en.sport},
        {"dport", en.dport}
    };
}
inline void from_json(const nlohmann::json& j, Entry& en) {
    auto ts = std::chrono::system_clock::from_time_t(be64toh(j["ts"].get<std::time_t>()));
    en.ts = ts;

    auto shaddr = j["shaddr"].get<std::array<char, 6>>();
    auto thaddr = j["thaddr"].get<std::array<char, 6>>();
    std::memcpy(en.shaddr.data(), shaddr.data(), shaddr.size());
    std::memcpy(en.thaddr.data(), thaddr.data(), thaddr.size());

    en.eth_proto = j["eth_proto"].get<std::uint32_t>();

    auto saddr = j["saddr"].get<std::array<char, 16>>();
    auto taddr = j["taddr"].get<std::array<char, 16>>();
    std::memcpy(en.saddr.data(), saddr.data(), saddr.size());
    std::memcpy(en.taddr.data(), taddr.data(), taddr.size());

    en.ip_proto = j["ip_proto"].get<std::uint8_t>();

    en.sport = j["sport"].get<std::uint16_t>();
    en.dport = j["dport"].get<std::uint16_t>();
}

inline std::vector<Entry> read_file(const std::string_view filename) {
    std::ifstream r_file(filename.data());
    std::vector<Entry> result;
    if (!r_file.is_open()) {
        return result;
    }

    nlohmann::json data = nlohmann::json::parse(r_file);
    if (!data.is_array()) {
        return result;
    }

    for (const auto& val : data) {
        Entry en = val.get<Entry>();
        result.push_back(std::move(en));
    }
    return result;
}

inline void write_file(const std::string_view filename, std::vector<Entry> entries) {
    std::thread th{[filename, entries = std::move(entries)] {
        std::ifstream r_file{filename.data()};
        if (!r_file.is_open()) {
            return;
        }

        try {
            // nlohmann::json data = nlohmann::json::parse(r_file);
            nlohmann::json data = nlohmann::json::array();
            r_file.close();

            std::ofstream w_file{filename.data(), std::ios_base::trunc};
            if (!w_file.is_open()) {
                return;
            }

            if (!data.is_array()) {
                return; // TODO: handle
            }

            for (const auto& en : entries) {
                data.push_back(en);
            }

            w_file << data.dump(4);
            w_file.flush();
            w_file.close();
        } catch (const std::exception& ex) {
            // TODO: Handle
            return;
        }
    }};
    th.detach(); // async write to file to prevent the app from freezing for a moment
}

class Writer {
    std::vector<Entry> m_entries;
    std::mutex m_mutex;
    int m_cnter{};
    int m_interval{};

    constexpr static inline std::string_view m_filename = "test.json";
public:
    Writer(int write_interval = 10) : m_interval(write_interval) {

    }

    void add(const Entry& en) {
        std::unique_lock lock{m_mutex};
        m_entries.push_back(en);
        lock.unlock();

        ++m_cnter;
        if (m_cnter >= m_interval) {
            // write_file();
            write_file(m_filename, std::move(m_entries));
            assert(m_entries.size() == 0);
            m_cnter = 0;
        }
    }
};


/*
TODO: Write to file as json array
*/
