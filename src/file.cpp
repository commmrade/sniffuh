#include "file.hpp"
#include <filesystem>
#include <ios>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <cstring>
#include <nlohmann/json.hpp>
#include <fstream>
#include <print>

void to_json(nlohmann::json& j, const Entry& en) {
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
        {"tport", en.tport}
    };
}
void from_json(const nlohmann::json& j, Entry& en) {
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
    en.tport = j["tport"].get<std::uint16_t>();
}

std::vector<Entry> read_file(const std::string_view filename) {
    std::vector<Entry> result;
    std::ifstream r_file(filename.data());
    if (!r_file.is_open()) {
        throw std::runtime_error(std::format("Could not open {}", filename));
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

Writer::Writer(int write_interval, std::string_view filename) : m_interval(write_interval), m_filename(filename) {
    std::ofstream file{std::string{filename}, std::ios_base::app};
    file.close();
}

void Writer::write_to_file() {
    std::thread th{[this] {
        std::ifstream r_file{m_filename.data()};
        if (!r_file.is_open()) {
            return;
        }

        try {
            nlohmann::json data = nlohmann::json::parse(r_file, nullptr, false);
            if (!data.is_array()) { // TODO: There seems to be a data race because it always satisfies the cond
                std::println("FUCK UP\nFUCK UP\nFUCK UP");
                data = nlohmann::json::array();
            }
            r_file.close();

            std::ofstream w_file{m_filename.data(), std::ios_base::trunc};
            if (!w_file.is_open()) {
                return;
            }

            std::unique_lock lock{m_mutex};
            std::copy(m_entries.begin(), m_entries.end(), std::back_inserter(data));
            lock.unlock();

            w_file << data.dump(4);
            w_file.flush();
            w_file.close();
        } catch (const std::exception& ex) {
            // TODO: Handle
            std::println("Ex: {}", ex.what());
            return;
        }
    }};
    th.detach(); // async write to file to prevent the app from freezing for a moment
}

void Writer::store(const Entry& en) {
    std::unique_lock lock{m_mutex};
    m_entries.push_back(en);
    lock.unlock();

    ++m_cnter;
    if (m_cnter >= m_interval) {
        write_to_file();
        std::unique_lock lock{m_mutex};
        m_entries.clear();
        lock.unlock();
        m_cnter = 0;
    }
}
