#include "logs.hpp"
#include "sniffer.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <exception>
#include <netinet/in.h>
#include <print>
#include <ranges>
#include <stdexcept>
#include <string>
#include "argparse/argparse.hpp"
#include "utils.hpp"

/*
#ifdef __linux__
    //linux code goes here
#elif _WIN32
    // windows code goes here
#else

#endif

*/


void setup_parser(argparse::ArgumentParser& parser) {
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
    }
    {
        auto& w_group = parser.add_group("Write options");
        w_group.add_argument("--interface")
            .default_value(std::string{ANY_INTERFACE})
            .help("Specify an interface");
        w_group.add_argument("-o")
            .default_value(std::string{"test.pdor"})
            .help("Specify path for an output log file");

        parser.add_argument("--log-level")
            .default_value(static_cast<int>(0))
            .scan<'i', int>()
            .help("Log level for logging [0, 1, 2]");

        auto& r_group = parser.add_group("Read options");
        r_group.add_argument("-i")
            .default_value(std::string{"test.pdor"})
            .help("Specify path for an input log file");
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
            .scan<'i', std::uint32_t>() // from ethernet rfc
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
}

void log_mode(argparse::ArgumentParser& parser) {
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
    Writer writer{parser.get<std::string>("-o")};
    while (true) {
        auto packentry = s.sniff();
        if (packentry.first.plod) {
            auto output = log_packet(packentry.first, loglvl);
            std::println("{}", output);
            writer.store(packentry.second);
        }
    }
}

void read_mode(argparse::ArgumentParser& parser) {
    auto entries = read_file(parser.get<std::string>("-i"));

    if (parser.is_used("time-order")) {
        int order_val = parser.get<int>("time-order");
        if (order_val < 0 || order_val > 1) {
            throw std::runtime_error("Invalid value for time order option");
        }
        std::ranges::sort(entries, [order_val](const Entry& lhs, const Entry& rhs) {
            return order_val == 0 ? be64toh(lhs.ts) < be64toh(rhs.ts) : be64toh(lhs.ts) > be64toh(rhs.ts);
        });
    }

    if (parser.is_used("shaddr")) {
        auto res = convert_to_mac(parser.get<std::string>("shaddr"));
        auto r = res.and_then([&entries](std::array<char, 6> raddr) -> std::expected<std::array<char, 6>, std::string> {
            auto filtered = std::views::filter(entries, [raddr](const Entry& en) {
                return !std::memcmp(raddr.data(), en.shaddr.data(), raddr.size());
            }) | std::ranges::to<std::vector<Entry>>();
            entries = std::move(filtered);
            return {};
        }).or_else([](const std::string& err) -> std::expected<std::array<char, 6>, std::string> {
            throw std::runtime_error(err);
            return {};
        });
    }
    if (parser.is_used("thaddr")) {
        auto res = convert_to_mac(parser.get<std::string>("thaddr"));
        auto r = res.and_then([&entries](std::array<char, 6> raddr) -> std::expected<std::array<char, 6>, std::string> {
            auto filtered = std::views::filter(entries, [raddr](const Entry& en) {
                return !std::memcmp(raddr.data(), en.thaddr.data(), raddr.size());
            }) | std::ranges::to<std::vector<Entry>>();
            entries = std::move(filtered);
            return {};
        }).or_else([](const std::string& err) -> std::expected<std::array<char, 6>, std::string> {
            throw std::runtime_error(err);
            return {};
        });
    }
    if (parser.is_used("eth-proto")) {
        auto proto = parser.get<std::uint32_t>("eth-proto");
        proto = htons(proto);
        auto filtered = std::views::filter(entries, [proto](const Entry& en) {
            return en.eth_proto == proto;
        }) | std::ranges::to<std::vector<Entry>>();
        entries = std::move(filtered);
    }
    if (parser.is_used("saddr")) {
        auto addr_str = parser.get<std::string>("saddr");
        auto addr = convert_to_addr(addr_str);
        auto r = addr.and_then([&entries, &addr_str](std::array<char, 16> addr) ->  std::expected<in_addr_t, std::string> {
            auto filtered = entries | std::views::filter([addr, &addr_str](const Entry& en){
                if (addr_str.contains(":")) {
                    return !std::memcmp(addr.data(), en.saddr.data(), addr.size());
                } else { // v4
                    uint32_t en_ip;
                    uint32_t ip;
                    std::memcpy(&en_ip, en.saddr.data(), 4);
                    std::memcpy(&ip, addr.data(), 4);

                    return en_ip == ip;
                }
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
            return {};
        }).or_else([](const std::string& err) -> std::expected<in_addr_t, std::string> {
            throw std::runtime_error(std::format("Failed to filter by saddr: {}", err));
            return {};
        });
    }
    if (parser.is_used("taddr")) {
        auto addr_str = parser.get<std::string>("taddr");
        auto addr = convert_to_addr(addr_str);
        auto r = addr.and_then([&entries, &addr_str](std::array<char, 16> addr) ->  std::expected<in_addr_t, std::string> {
            auto filtered = entries | std::views::filter([addr, &addr_str](const Entry& en){
                if (addr_str.contains(":")) {

                    return !std::memcmp(addr.data(), en.taddr.data(), addr.size());
                } else { // v4
                    uint32_t en_ip;
                    uint32_t ip;
                    std::memcpy(&en_ip, en.taddr.data(), 4);
                    std::memcpy(&ip, addr.data(), 4);

                    return en_ip == ip;
                }
            }) | std::ranges::to<std::vector>();
            entries = std::move(filtered);
            return {};
        }).or_else([](const std::string& err) -> std::expected<in_addr_t, std::string> {
            throw std::runtime_error(std::format("Failed to filter by taddr: {}", err));
            return {};
        });
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
        print_entry(en);
    }
}

void interfaces_mode() {
    auto ifcs = show_interfaces();
    for (const auto& ifc : ifcs) {
        std::println("Interface: {}", ifc);
    }
}


int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    argparse::ArgumentParser parser;
    setup_parser(parser);

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& ex) {
        std::println("Exception: {}", ex.what());
        return -1;
    }

    if (parser.is_used("log")) {
        log_mode(parser);
    } else if (parser.is_used("read")) {
        read_mode(parser);
    } else if (parser.is_used("interfaces")) {
        interfaces_mode();
    }
    return 0;
}
