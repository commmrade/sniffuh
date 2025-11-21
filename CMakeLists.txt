cmake_minimum_required(VERSION 3.30)

project(sniffuh)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sniffuh
    src/main.cpp
    src/sniffer.cpp
    src/logs.cpp
    src/parser.cpp
)

target_compile_options(sniffuh PRIVATE -Wall -Wextra)

find_package(nlohmann_json REQUIRED)

target_link_libraries(sniffuh PRIVATE nlohmann_json::nlohmann_json)
