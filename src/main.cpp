#include "logs.hpp"
#include "server.hpp"
#include <print>

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    // TODOS:
    // - process VLAN

    auto vec = show_interfaces();
    if (geteuid() != 0) {
        throw std::runtime_error("Should be ran as root");
    }

    Server serv{vec[1]};
    serv.sniff_loop();
    return 0;
}
