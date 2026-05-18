cmake_minimum_required(VERSION 3.16)

project(MiniPKI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------
# OpenSSL
# --------------------------------------
find_package(OpenSSL REQUIRED)

# --------------------------------------
# Include dirs
# --------------------------------------
include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

# --------------------------------------
# Source files
# --------------------------------------
set(SOURCES
    src/main.cpp
    src/crypto_manager.cpp
)

# --------------------------------------
# Executable
# --------------------------------------
add_executable(exe ${SOURCES})

# --------------------------------------
# Link OpenSSL
# --------------------------------------
target_link_libraries(exe PRIVATE OpenSSL::Crypto OpenSSL::SSL)

# --------------------------------------
# Warnings (opcjonalnie, ale polecam)
# --------------------------------------
target_compile_options(exe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)