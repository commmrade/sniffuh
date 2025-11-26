#pragma once
#include "logs.hpp"
#include <string_view>

class Sniffer {
    int m_sock;
    void setup(std::string_view if_name);
public:
    Sniffer(std::string_view if_name);
    ~Sniffer();
    std::pair<Packet, Entry> sniff();
};
