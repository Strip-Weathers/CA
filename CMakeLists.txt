cmake_minimum_required(VERSION 3.16)

project(MiniPKI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

set(SOURCES
    src/main.cpp
    src/crypto_manager.cpp
)

add_executable(exe ${SOURCES})

target_link_libraries(exe PRIVATE OpenSSL::Crypto OpenSSL::SSL)

target_compile_options(exe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)