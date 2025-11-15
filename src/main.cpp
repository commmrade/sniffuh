#include "logs.hpp"
#include "sniffer.hpp"
#include <print>

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    // TODOS:
    // - process VLAN

    auto vec = show_interfaces();
    if (geteuid() != 0) {
        throw std::runtime_error("Should be ran as root");
    }

    Sniffer s{vec[1]};
    s.sniff_loop();
    return 0;
}
