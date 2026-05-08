cmake_minimum_required(VERSION 4.0)
project(sebsatiansd)

set(CMAKE_CXX_STANDARD 20)

# Static linking flags for MinGW
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")

add_executable(lucefdecryptor main.cpp)

target_link_libraries(lucefdecryptor PRIVATE)