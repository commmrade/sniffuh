#include "pdor.hpp"
#include "entry.hpp"
#include <array>

namespace pdor {

bool Reader::check_header() {
    std::uint32_t magic;
    m_file.read((char *)&magic, sizeof(magic));
    if (ntohl(magic) != MAGIC_VALUE) {
        throw std::runtime_error("Not a .pdor file");
    }
    m_file.seekg(HEADER_SIZE); // Header size
    return true;
}
bool Reader::open() {
    m_file.open(m_filepath, std::ios::binary | std::ios::in);
    if (!m_file.is_open()) {
        return false;
    }
    return check_header();
}
bool Reader::open(const std::string &filepath) {
    m_filepath = filepath;
    return open();
}
bool Reader::read(Entry &res) {
    auto opt = read();
    if (!opt.has_value()) {
        return false;
    }
    res = opt.value();
    return true;
}
std::optional<Entry> Reader::read() {
    detail::Entry__ raw_pkt;
    m_file.read(reinterpret_cast<char *>(&raw_pkt), sizeof(raw_pkt));
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



bool Writer::check_header() {
    std::ifstream file{m_filepath, std::ios::binary | std::ios::in};

    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    file.seekg(0);

    if (file_size >= HEADER_SIZE) {
        std::uint32_t magic;
        file.read((char *)&magic, sizeof(magic));
        if (ntohl(magic) != MAGIC_VALUE) {
            return false;
        }
        return true;
    }
    return false;
}
void Writer::write_header() {
    std::uint32_t magic = htonl(MAGIC_VALUE);
    std::uint16_t major = htons(MAJOR);
    std::uint16_t minor = htons(MINOR);
    m_file.write((char *)&magic, sizeof(magic));
    m_file.write((char *)&major, sizeof(major));
    m_file.write((char *)&minor, sizeof(minor));
}
bool Writer::open() {
    bool r = check_header();
    if (!r) {
        m_file.open(m_filepath, std::ios::binary | std::ios::out | std::ios::trunc);
        write_header();
    } else {
        m_file.open(m_filepath, std::ios::binary | std::ios::out | std::ios::app);
    }
    if (!m_file.is_open()) {
        return false;
    }
    return true;
}
bool Writer::open(const std::string &filepath) {
    m_filepath = filepath;
    return open();
}
void Writer::write(const Entry &en) {
    detail::Entry__ buf;
    buf.ts = en.ts;
    buf.shaddr = en.shaddr;
    buf.thaddr = en.thaddr;
    buf.eth_proto = en.eth_proto;
    buf.saddr = en.saddr;
    buf.taddr = en.taddr;
    buf.ip_proto = en.ip_proto;
    buf.sport = en.sport;
    buf.tport = en.tport;

    m_file.write((const char*)&buf, sizeof(buf));
}

} // namespace pdor
