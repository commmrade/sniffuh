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
    src/utils.cpp
    include/pdor.cpp
)

target_include_directories(sniffuh PRIVATE include)
if (UNIX) 
    target_compile_options(sniffuh PRIVATE -Wall -Wextra)
elseif (WIN32)
    target_compile_options(sniffuh PRIVATE /Wall)
    target_link_libraries(sniffuh PRIVATE iphlapi ws2_32)
endif ()

target_link_libraries(sniffuh PRIVATE argparse)
