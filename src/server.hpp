#pragma once
#include <string_view>
#include <span>

class Server {
    int m_sock;
    void setup(std::string_view if_name);

    void process_packet(std::span<char> p);
public:
    Server(std::string_view if_name);
    ~Server();
    void sniff_loop();
};
