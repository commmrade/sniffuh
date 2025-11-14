#include "utils.hpp"
#include "server.hpp"

int main(int argc, char** argv) {
    // TODOS:
    // - process VLAN

    show_interfaces();
    if (geteuid() != 0) {
        throw std::runtime_error("Should be ran as root");
    }

    Server serv{"wlan0"};
    serv.start_sniffing();
    return 0;
}
