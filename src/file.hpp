#pragma once
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <nlohmann/json_fwd.hpp>
#include <vector>
#include "entry.hpp"
#include "pdor.hpp"

using pdor::Entry;

enum class IpType : std::uint8_t {
    V4,
    V6
};
// namespace pdor {
// void to_json(nlohmann::json& j, const Entry& en);
// void from_json(const nlohmann::json& j, Entry& en);
// }

std::vector<Entry> read_file(const std::string_view filename);

class Writer {
    std::vector<Entry> m_entries;
    std::mutex m_mutex;
    int m_cnter{};
    int m_interval{};

    std::string_view m_filename;

    void write_to_file();

    pdor::File m_file;
public:
    Writer(int write_interval = 10, std::string_view filename = "test.json");
    void store(const Entry& en);
};
