#include "logs.hpp"
#include "sniffer.hpp"
#include <arpa/inet.h>
#include <exception>
#include <netinet/in.h>
#include <print>
#include <stdexcept>
#include <string>
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
        w_group.add_argument("--interface")
            .default_value(std::string{ANY_INTERFACE})
            .help("Specify an interface");

        parser.add_argument("--log-level")
            .default_value(static_cast<int>(0))
            .scan<'i', int>()
            .help("Log level for logging [0, 1, 2]");

        auto& r_group = parser.add_group("Read options");
        r_group.add_argument("--time-order") //
            .scan<'i', int>() //
            .help("Sort order by time. 0 - ascending, 1 - descending");
        r_group.add_argument("--shaddr")
            .default_value(std::string{})
            .help("Find records for specified source hardware address");
        r_group.add_argument("--thaddr")
            .default_value(std::string{})
            .help("Find records for specified target hardware address");
        r_group.add_argument("--eth-proto")
            .scan<'i', int>() // from ethernet rfc
            .help("Find records for the specified EtherType. From RFC in HEX format");
        r_group.add_argument("--saddr")
            .default_value(std::string{})
            .help("Find records for the specified source address (IpV4 for now). xxx.xxx.xxx.xxx format");
        r_group.add_argument("--taddr")
            .default_value(std::string{})
            .help("Find records for the specified target address (IpV4 for now). xxx.xxx.xxx.xxx format");
        r_group.add_argument("--ip-proto")
            .scan<'i', int>()
            .help("Find records for the specified ip protocol");
        r_group.add_argument("--sport")
            .scan<'i', std::uint16_t>()
            .help("Find records for the specified source port");
        r_group.add_argument("--tport")
            .scan<'i', std::uint16_t>()
            .help("Find records for the specified target port");
        // Setup filters and shit
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

        std::string ifc = parser.get<std::string>("--interface");

        Sniffer s{ifc};
        s.set_log_lvl(loglvl);
        s.sniff_loop();
    } else if (parser.is_used("read")) {
        auto entries = read_file("test.json");


        if (parser.is_used("time-order")) {
            int order_val = parser.get<int>("time-order");
            if (order_val < 0 || order_val > 1) {
                throw std::runtime_error("Invalid value for time order option");
            }
            std::ranges::sort(entries, [order_val](const Entry& lhs, const Entry& rhs) {
                return order_val == 0 ? lhs.ts < rhs.ts : lhs.ts > rhs.ts;
            });
        }
        if (parser.is_used("shaddr")) {
            std::string addr = parser.get<std::string>("shaddr"); // get addr like 25:12:4a:11:09:2f
            std::array<char, 6> raddr{};

            auto mac = std::views::split(addr, ':') | std::ranges::to<std::vector<std::string>>();
            if (mac.size() != 6) {
                throw std::runtime_error("Source hardware address is invalid");
            }

            for (std::size_t i = 0; i < raddr.size(); ++i) {
                raddr[i] = std::stoi(mac[i], nullptr, 16);
            }

            auto filtered = std::views::filter(entries, [raddr](const Entry& en) {
                return !std::memcmp(raddr.data(), en.shaddr.data(), raddr.size());
            }) | std::ranges::to<std::vector<Entry>>();
            entries = std::move(filtered);
        }
        if (parser.is_used("thaddr")) {
            std::string addr = parser.get<std::string>("thaddr"); // get addr like 25:12:4a:11:09:2f
            std::array<char, 6> raddr{};

            auto mac = std::views::split(addr, ':') | std::ranges::to<std::vector<std::string>>();
            if (mac.size() != 6) {
                throw std::runtime_error("Target hardware address is invalid");
            }

            for (std::size_t i = 0; i < raddr.size(); ++i) {
                raddr[i] = std::stoi(mac[i], nullptr, 16);
            }

            auto filtered = std::views::filter(entries, [raddr](const Entry& en) {
                return !std::memcmp(raddr.data(), en.thaddr.data(), raddr.size());
            }) | std::ranges::to<std::vector<Entry>>();
            entries = std::move(filtered);
        }
        if (parser.is_used("eth-proto")) {
            auto proto = parser.get<std::uint32_t>("eth-proto");
            auto filtered = std::views::filter(entries, [proto](const Entry& en) {
                return ntohl(en.eth_proto) == proto;
            }) | std::ranges::to<std::vector<Entry>>();
            entries = std::move(filtered);
        }
        if (parser.is_used("saddr")) {
            std::string addr_str = parser.get<std::string>("saddr");
            in_addr_t addr{};

            int r = inet_pton(AF_INET, addr_str.c_str(), &addr);
            if (r != 1) {
                throw std::runtime_error("Source address is invalid");
            }

            auto filtered = entries | std::views::filter([addr](const Entry& en){
                uint32_t ip;
                std::memcpy(&ip, en.saddr.data(), 4);
                return ip == addr;
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
        }
        if (parser.is_used("taddr")) {
            std::string addr_str = parser.get<std::string>("taddr");
            in_addr_t addr{};

            int r = inet_pton(AF_INET, addr_str.c_str(), &addr);
            if (r != 1) {
                throw std::runtime_error("Target address is invalid");
            }

            auto filtered = entries | std::views::filter([addr](const Entry& en){
                uint32_t ip;
                std::memcpy(&ip, en.taddr.data(), 4);
                return ip == addr;
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
        }
        if (parser.is_used("ip-proto")) {
            int proto = parser.get<int>("ip-proto");

            auto filtered = entries | std::views::filter([proto](const Entry& en){
                return en.ip_proto == proto;
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
        }
        if (parser.is_used("sport")) {
            std::uint16_t port = htons(parser.get<std::uint16_t>("sport")); // to be, since port is stored in be

            auto filtered = entries | std::views::filter([port](const Entry& en){
                return en.sport == port;
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
        }
        if (parser.is_used("tport")) {
            std::uint16_t port = htons(parser.get<std::uint16_t>("tport"));

            auto filtered = entries | std::views::filter([port](const Entry& en){
                return en.tport == port;
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
        }

        for (const auto& en : entries) {
            // std::println("{}", en.ts);
            print_entry(en);
        }



    } else if (parser.is_used("interfaces")) {
        auto ifcs = show_interfaces();
        for (const auto& ifc : ifcs) {
            std::println("Interface: {}", ifc);
        }
    }
    return 0;
}
