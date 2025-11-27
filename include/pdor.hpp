#pragma once

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <optional>
#include <print>
#include "entry.hpp"

namespace pdor {

class File {
    std::fstream m_file;
    std::string m_filepath;
public:
    File(std::string filepath) : m_filepath{std::move(filepath)} {
    }

    bool open() {
        m_file.open(m_filepath);
        if (!m_file.is_open()) {
            return false;
        }

        std::uint32_t magic;
        m_file >> magic;
        m_file.seekg(0);
        if (ntohl(magic) != 0xCAFE) {
            std::println("{} is not a .pdor file", m_filepath);
            return false;
        }

        return true;
    }
    bool open(const std::string& filepath) {
        // TODO: Check if it is a file of type .pdor by magic value
        m_filepath = filepath;
        m_file.open(m_filepath);
        if (!m_file.is_open()) {
            return false;
        }

        m_file.seekg(std::ios::end);
        auto file_size = m_file.tellg();
        m_file.seekg(0);
        if (file_size > 8) {
            std::uint32_t magic;
            m_file >> magic;
            m_file.seekg(0);
            if (ntohl(magic) != 0xCAFE) {
                std::println("{} is not a .pdor file", filepath);
                return false;
            }
            m_file.seekg(8); // Header size
        } else {
            std::uint32_t magic = htonl(0xCAFE);
            std::uint16_t major = 1;
            std::uint16_t minor = 0;
            m_file.write((char*)&magic, sizeof(magic));
            m_file.write((char*)&major, sizeof(major));
            m_file.write((char*)&minor, sizeof(minor));
        }

        return true;
    }
    void close() {
        m_file.close();
    }

    bool read(Entry& res) {
        detail::Entry__ raw_pkt;
        m_file.read(reinterpret_cast<char*>(&raw_pkt), sizeof(raw_pkt));
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
    void write(Entry& en) {
        // TODO: Make sure to write header
        m_file << en.ts;

        m_file.write(en.shaddr.data(), en.shaddr.size());
        m_file.write(en.thaddr.data(), en.thaddr.size());
        m_file << en.eth_proto;

        m_file.write(en.saddr.data(), en.saddr.size());
        m_file.write(en.taddr.data(), en.taddr.size());
        m_file << en.ip_proto;

        m_file << en.sport;
        m_file << en.tport;
    }
};
} // namespace pdor
