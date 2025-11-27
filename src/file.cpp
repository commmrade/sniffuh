#include "file.hpp"
#include "pdor.hpp"
#include <filesystem>
#include <linux/if_ether.h>
#include <print>

std::vector<Entry> read_file(const std::string_view filename) {
    std::vector<Entry> result;
    pdor::Reader file{filename.data()};
    if (!file.open()) {
        return result;
    }

    Entry en;
    while (file.read(en)) {
        result.push_back(en);
    }
    return result;
}

Writer::Writer(std::string_view filename) : m_filename(filename), m_file(std::string{filename}) {
    bool r = m_file.open();
    std::filesystem::permissions(filename,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
}

void Writer::store(const Entry& en) {
    m_file.write(en);
}
