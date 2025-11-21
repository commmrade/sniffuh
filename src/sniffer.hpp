#pragma once
#include "parser.hpp"
#include <string_view>
#include <span>


class Sniffer {
    Writer m_writer;
    int m_sock;
    void setup(std::string_view if_name);
    void process_packet(std::span<char> p);
public:
    Sniffer(std::string_view if_name);
    ~Sniffer();
    void sniff_loop();
};
