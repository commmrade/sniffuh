#include "utils.hpp"
#include "server.hpp"
#include <print>

int main(int argc, char** argv) {
    // TODOS:
    // - process VLAN

    auto vec =  show_interfaces();
    if (geteuid() != 0) {
        throw std::runtime_error("Should be ran as root");
    }

    Server serv{vec[1]};
    serv.sniff_loop();
    return 0;
}
