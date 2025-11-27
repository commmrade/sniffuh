#pragma once

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <optional>
#include <print>
#include "entry.hpp"

namespace pdor {

enum class Mode {
    Read,
    Write
};

class File { // TODO: Split into reader and writer
    std::fstream m_file;
    std::string m_filepath;

    bool process_header() {
        // TODO: Fix this shit
        m_file.seekg(0, std::ios::end);
        auto file_size = m_file.tellg();
        m_file.seekg(0);
        if (file_size > 8) {
            std::uint32_t magic;
            m_file.read((char*)&magic, sizeof(magic));
            m_file.seekg(0);
            if (ntohl(magic) != 0xCAFE) {
                std::println("{} is not a .pdor file", m_filepath);
                return false;
            }
            m_file.seekg(8); // Header size
        } else {
            std::uint32_t magic = htonl(0xCAFE);
            std::uint16_t major = htons(1);
            std::uint16_t minor = htons(0);
            m_file.write((char*)&magic, sizeof(magic));
            m_file.write((char*)&major, sizeof(major));
            m_file.write((char*)&minor, sizeof(minor));
            m_file.seekg(8);
        }

        std::println("here");
        return true;
    }
public:
    File(std::string filepath) : m_filepath{std::move(filepath)} {
    }

    bool open(Mode m) {
        if (m == Mode::Read) {
            m_file.open(m_filepath, std::ios::binary | std::ios::in);
        } else {
            m_file.open(m_filepath, std::ios::binary | std::ios::out);
        }
        if (!m_file.is_open()) {
            return false;
        }
        return process_header();
    }
    bool open(const std::string& filepath, Mode m) {
        m_filepath = filepath;
        if (m == Mode::Read) {
            m_file.open(m_filepath, std::ios::binary | std::ios::in);
        } else {
            m_file.open(m_filepath, std::ios::binary | std::ios::out);
        }
        if (!m_file.is_open()) {
            return false;
        }
        return process_header();
    }
    void close() {
        m_file.close();
    }

    bool read(Entry& res) {
        detail::Entry__ raw_pkt;
        m_file.read(reinterpret_cast<char*>(&raw_pkt), sizeof(raw_pkt));
        int pos = m_file.tellg();
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
