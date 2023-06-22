cmake_minimum_required(VERSION 2.6)
project (v5-aead-decr-oracle)

SET(EAX_DECR_BINARY eax_decr)

FILE(GLOB_RECURSE SOURCES src/*.cpp)


add_executable(${EAX_DECR_BINARY} ${SOURCES})
target_compile_options(${EAX_DECR_BINARY} PRIVATE -g -ggdb)
