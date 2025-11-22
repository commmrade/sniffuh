#include "logs.hpp"
#include "parser.hpp"
#include "sniffer.hpp"
#include <exception>
#include <print>
#include <stdexcept>
#include "argparse/argparse.hpp"

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    argparse::ArgumentParser parser;
    {
        auto& group = parser.add_mutually_exclusive_group(true);
        group.add_argument("--log")
            .flag()
            .help("Logging mode");
        group.add_argument("--read")
            .flag()
            .help("Reading log dumps mode");
        // TODO: Show interfaces option
    }
    {
        auto& w_group = parser.add_group("Write options");
        w_group.add_argument("--opt1")
            .default_value(std::string{"Def"})
            .help("Test option");
        w_group.add_argument("--opt2")
            .default_value(std::string{"Def"})
            .help("Test option");
        // Add option to specify interface

        auto& r_group = parser.add_group("Read options");
        r_group.add_argument("--opt1")
            .default_value(std::string{"def"})
            .help("Test option");
        r_group.add_argument("--opt2")
            .default_value(std::string{"def"})
            .help("Test option");
    }


    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& ex) {
        std::println("Exception: {}", ex.what());
    }

    if (parser.is_used("log")) {
        auto vec = show_interfaces();
        if (geteuid() != 0) {
            throw std::runtime_error("Should be ran as root");
        }

        Sniffer s{vec[1]};
        s.sniff_loop();
    } else if (parser.is_used("read")) {
        auto entries = read_file("test.json");
        for (const auto& en : entries) {
            std::println("{}", en.ts);
        }
    }

    return 0;
}
