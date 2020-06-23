cmake_minimum_required(VERSION 3.15)
project(crypt_prj3)

set(CMAKE_CXX_STANDARD 14)


set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)


add_executable(crypt_prj3 TLS_user.h main.cpp)

target_link_libraries(crypt_prj3 OpenSSL::Crypto)