cmake_minimum_required(VERSION 3.30)

project(sniffuh)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Argument parser
FetchContent_Declare(
    argparse
    GIT_REPOSITORY https://github.com/p-ranav/argparse.git
)
FetchContent_MakeAvailable(argparse)

add_executable(sniffuh
    src/main.cpp
    src/sniffer.cpp
    src/logs.cpp
    src/parser.cpp
    src/file.cpp
)

target_compile_options(sniffuh PRIVATE -Wall -Wextra)

find_package(nlohmann_json REQUIRED)

target_link_libraries(sniffuh PRIVATE nlohmann_json::nlohmann_json argparse)
