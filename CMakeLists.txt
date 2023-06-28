cmake_minimum_required(VERSION 2.6)
project (v5-aead-decr-oracle)


set(CMAKE_CXX_STANDARD 20)

set(BOTAN_INCLUDE_DIR "" CACHE STRING "Botan include directory")
include_directories(${BOTAN_INCLUDE_DIR})


set(BOTAN_LIB_DIR "" CACHE STRING "Botan library directory")
link_directories(${BOTAN_LIB_DIR})

set(TARGS_INCLUDE_DIR "../args" CACHE STRING "include directory https://github.com/Taywee/args")
include_directories(${TARGS_INCLUDE_DIR})



SET(EAX_DECR_BINARY eax_decr)

FILE(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(${EAX_DECR_BINARY} ${SOURCES})
target_compile_options(${EAX_DECR_BINARY} PRIVATE -g -ggdb)
target_link_libraries(${EAX_DECR_BINARY} -lbotan-3)
