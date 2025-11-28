#pragma once
#include <string_view>
#include "packet.hpp"
#include "entry.hpp"

using pdor::Entry;

class Sniffer {
    int m_sock;
    void setup(std::string_view if_name);
public:
    Sniffer(std::string_view if_name);
    ~Sniffer();
    std::pair<Packet, Entry> sniff();
};
