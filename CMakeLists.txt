cmake_minimum_required(VERSION 3.15)

project(CryptoProject)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

add_executable(exe
    src/main.cpp
    src/crypto_manager.cpp
)

target_include_directories(exe PRIVATE src)

target_link_libraries(exe PRIVATE OpenSSL::SSL OpenSSL::Crypto)