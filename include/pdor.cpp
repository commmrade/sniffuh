#include "pdor.hpp"


bool pdor::Reader::check_header() {
    std::uint32_t magic;
    m_file.read((char *)&magic, sizeof(magic));
    m_file.seekg(0);
    if (ntohl(magic) != MAGIC_VALUE) {
        throw std::runtime_error("Not a .pdor file");
    }
    m_file.seekg(HEADER_SIZE); // Header size
    return true;
}
bool pdor::Reader::open() {
    m_file.open(m_filepath, std::ios::binary | std::ios::in);
    if (!m_file.is_open()) {
        return false;
    }
    return check_header();
}
bool pdor::Reader::open(const std::string &filepath) {
    m_filepath = filepath;
    return open();
}
bool pdor::Reader::read(Entry &res) {
    detail::Entry__ raw_pkt;
    m_file.read(reinterpret_cast<char *>(&raw_pkt), sizeof(raw_pkt));

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
std::optional<pdor::Entry> pdor::Reader::read() {
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
bool pdor::Writer::check_header() {
    std::ifstream file{m_filepath};

    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    file.seekg(0);

    if (file_size > HEADER_SIZE) {
        std::uint32_t magic;
        file.read((char *)&magic, sizeof(magic));
        if (ntohl(magic) != MAGIC_VALUE) {
            throw std::runtime_error("Not a .pdor file");
        }
    } else {
        return false; // File is new
    }
    return true;
}
void pdor::Writer::write_header() {
    std::uint32_t magic = htonl(MAGIC_VALUE);
    std::uint16_t major = htons(MAJOR);
    std::uint16_t minor = htons(MINOR);
    m_file.write((char *)&magic, sizeof(magic));
    m_file.write((char *)&major, sizeof(major));
    m_file.write((char *)&minor, sizeof(minor));
}
bool pdor::Writer::open() {
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
bool pdor::Writer::open(const std::string &filepath) {
    m_filepath = filepath;
    return open();
}
void pdor::Writer::write(const Entry &en) {
    m_file.write((char *)&en.ts, sizeof(en.ts));

    m_file.write(en.shaddr.data(), en.shaddr.size());
    m_file.write(en.thaddr.data(), en.thaddr.size());
    m_file.write((char *)&en.eth_proto, sizeof(en.eth_proto));

    m_file.write(en.saddr.data(), en.saddr.size());
    m_file.write(en.taddr.data(), en.taddr.size());
    m_file.write((char *)&en.ip_proto, sizeof(en.ip_proto));

    m_file.write((char *)&en.sport, sizeof(en.sport));
    m_file.write((char *)&en.tport, sizeof(en.tport));
}
