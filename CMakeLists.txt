cmake_minimum_required(VERSION 3.30)

project(sniffuh)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED true)

add_executable(sniffuh src/main.cpp src/server.cpp src/logs.cpp src/parser.cpp)

target_compile_options(sniffuh PRIVATE -Wall -Wextra)
