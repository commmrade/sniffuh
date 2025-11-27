#pragma once

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <optional>
#include <print>
#include <stdexcept>
#include "entry.hpp"

namespace pdor {

constexpr inline static std::uint32_t MAGIC_VALUE = 0xCAFE;
constexpr inline static std::uint16_t MAJOR = 1;
constexpr inline static std::uint16_t MINOR = 0;
constexpr inline static int HEADER_SIZE = 8;

class Reader {
    std::ifstream m_file;
    std::string m_filepath;
public:
    Reader(std::string filepath) : m_filepath{std::move(filepath)} {
    }

    bool open();
    bool open(const std::string &filepath);

    bool read(Entry &res);
    std::optional<Entry> read();
private:
    bool check_header();
};

class Writer {
    std::ofstream m_file;
    std::string m_filepath;
public:
    Writer(std::string filepath) : m_filepath{std::move(filepath)} {
    }
    bool open();
    bool open(const std::string &filepath);
    void write(const Entry &en);
private:
    bool check_header();
    void write_header();
};
} // namespace pdor
