#pragma once
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

std::vector<Entry> read_file(const std::string_view filename);

class Writer {
    std::string_view m_filename;
    pdor::Writer m_file;
public:
    Writer(std::string_view filename = "test.json");
    void store(const Entry& en);
};
