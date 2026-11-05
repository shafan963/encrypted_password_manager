cmake_minimum_required(VERSION 3.16)
project(EncryptPasswordManager C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_executable(encrypt_server
    backend/main.c
    backend/crypto.c
    backend/crypto.h
    backend/json.c
    backend/json.h
)
target_include_directories(encrypt_server PRIVATE backend)
target_link_libraries(encrypt_server PRIVATE OpenSSL::Crypto SQLite::SQLite3)

if(WIN32)
    target_link_libraries(encrypt_server PRIVATE ws2_32)
endif()
