#include "logs.hpp"
#include "sniffer.hpp"
#include <exception>
#include <print>
#include <stdexcept>
#include "argparse/argparse.hpp"
#include "utils.hpp"

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
        group.add_argument("--interfaces")
            .flag()
            .help("Specify which interface you want to 'sniff'");

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

        auto& debug_lvls = w_group.add_mutually_exclusive_group();
        debug_lvls.add_argument("--log-level")
            .default_value(static_cast<int>(0))
            .scan<'i', int>()
            .help("Log level for logging [0, 1, 2]");
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
        return -1;
    }

    if (parser.is_used("log")) {
        if (geteuid() != 0) {
            throw std::runtime_error("Should be ran as root");
        }

        LogLevel loglvl;
        int lvl = parser.get<int>("--log-level");
        if (lvl < 0) {
            std::println("Log level can't be set to {}, set to 0 (min)", lvl);
        } else if (lvl > 2) {
            std::println("Log level can't be set to {}, set to 2 (max)", lvl);
        }
        loglvl = static_cast<LogLevel>(lvl);

        auto ifcs = show_interfaces();
        std::string if_name = ifcs.empty() ? "" : ifcs[0];

        Sniffer s{if_name};
        s.set_log_lvl(loglvl);
        s.sniff_loop();
    } else if (parser.is_used("read")) {
        auto entries = read_file("test.json");
        for (const auto& en : entries) {
            std::println("{}", en.ts);
        }
    } else if (parser.is_used("interfaces")) {
        auto ifcs = show_interfaces();
        for (const auto& ifc : ifcs) {
            std::println("Interface: {}", ifc);
        }
    }

    return 0;
}
