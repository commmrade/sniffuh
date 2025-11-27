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

    bool check_header() {
        m_file.seekg(0, std::ios::end);
        auto file_size = m_file.tellg();
        m_file.seekg(0);
        if (file_size < HEADER_SIZE) {
            return false;
        }

        std::uint32_t magic;
        m_file.read((char*)&magic, sizeof(magic));
        m_file.seekg(0);
        if (ntohl(magic) != MAGIC_VALUE) {
            throw std::runtime_error("Not a .pdor file");
        }
        m_file.seekg(HEADER_SIZE); // Header size
        return true;
    }
public:
    Reader(std::string filepath) : m_filepath{std::move(filepath)} {
    }

    bool open() {
        m_file.open(m_filepath, std::ios::binary | std::ios::in);
        if (!m_file.is_open()) {
            return false;
        }
        return check_header();
    }
    bool open(const std::string& filepath) {
        m_filepath = filepath;
        return open();
    }

    bool read(Entry& res) {
        detail::Entry__ raw_pkt;
        m_file.read(reinterpret_cast<char*>(&raw_pkt), sizeof(raw_pkt));

        std::println("{} {}", (int)m_file.tellg(), m_file.gcount());
        if ((unsigned long)m_file.gcount() < sizeof(raw_pkt)) {
            return false; // EOS
        }

        res.ts = raw_pkt.ts;
        res.shaddr = raw_pkt.shaddr;
        res.thaddr = raw_pkt.thaddr;
        res.eth_proto = raw_pkt.eth_proto;
        res.saddr = raw_pkt.saddr;
        res.taddr = raw_pkt.taddr;
        res.ip_proto = raw_pkt.ip_proto;
        res.sport = raw_pkt.sport;
        res.tport = raw_pkt.tport;
        return true;
    }
    std::optional<Entry> read() {
        detail::Entry__ raw_pkt;
        m_file.read(reinterpret_cast<char*>(&raw_pkt), sizeof(raw_pkt));
        if ((unsigned long)m_file.gcount() < sizeof(raw_pkt)) {
            return std::nullopt; // EOS
        }

        Entry res;
        res.ts = raw_pkt.ts;
        res.shaddr = raw_pkt.shaddr;
        res.thaddr = raw_pkt.thaddr;
        res.eth_proto = raw_pkt.eth_proto;
        res.saddr = raw_pkt.saddr;
        res.taddr = raw_pkt.taddr;
        res.ip_proto = raw_pkt.ip_proto;
        res.sport = raw_pkt.sport;
        res.tport = raw_pkt.tport;
        return res;
    }
};

class Writer {
    std::ofstream m_file;
    std::string m_filepath;

    bool check_header() {
        std::ifstream file{m_filepath};

        file.seekg(0, std::ios::end);
        auto file_size = file.tellg();
        file.seekg(0);

        if (file_size > HEADER_SIZE) {
            std::uint32_t magic;
            file.read((char*)&magic, sizeof(magic));
            if (ntohl(magic) != MAGIC_VALUE) {
                throw std::runtime_error("Not a .pdor file");
            }
        } else {
            return false; // File is new
        }
        return true;
    }
    void write_header() {
        std::uint32_t magic = htonl(MAGIC_VALUE);
        std::uint16_t major = htons(MAJOR);
        std::uint16_t minor = htons(MINOR);
        m_file.write((char*)&magic,  sizeof(magic));
        m_file.write((char*)&major, sizeof(major));
        m_file.write((char*)&minor, sizeof(minor));
    }
public:
    Writer(std::string filepath) : m_filepath{std::move(filepath)} {
    }

    bool open() {
        bool r = check_header();
        m_file.open(m_filepath, std::ios::binary | std::ios::out);
        if (!m_file.is_open()) {
            return false;
        }
        if (!r) {
            write_header();
        }
        m_file.seekp(HEADER_SIZE);
        return true;
    }
    bool open(const std::string& filepath) {
        m_filepath = filepath;
        return open();
    }
    void write(const Entry& en) {
        m_file.write((char*)&en.ts, sizeof(en.ts));

        m_file.write(en.shaddr.data(), en.shaddr.size());
        m_file.write(en.thaddr.data(), en.thaddr.size());
        m_file.write((char*)&en.eth_proto, sizeof(en.eth_proto));

        m_file.write(en.saddr.data(), en.saddr.size());
        m_file.write(en.taddr.data(), en.taddr.size());
        m_file.write((char*)&en.ip_proto, sizeof(en.ip_proto));

        m_file.write((char*)&en.sport, sizeof(en.sport));
        m_file.write((char*)&en.tport, sizeof(en.tport));
    }
};
} // namespace pdor
