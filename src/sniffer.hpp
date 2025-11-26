#pragma once
#include "logs.hpp"
#include "parser.hpp"
#include <string_view>
#include <span>

class Sniffer {
    Writer m_writer;
    int m_sock;
    LogLevel m_log_lvl{LogLevel::V};
    void setup(std::string_view if_name);
    void process_packet(std::span<char> p);
public:
    Sniffer(std::string_view if_name);
    ~Sniffer();
    void set_log_lvl(LogLevel loglvl);
    void sniff_loop();
};
