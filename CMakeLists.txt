cmake_minimum_required(VERSION 3.17)
project(PEObfuscator)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(ObfuseConfuse)
add_executable(PEObfuscator main.cpp)
target_link_libraries(PEObfuscator obfuseconfuse)