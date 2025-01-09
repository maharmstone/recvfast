cmake_minimum_required(VERSION 3.12)

project(recvfast
    LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_executable(recvfast src/recvfast.cpp)

target_compile_options(recvfast PUBLIC -Wall -Wextra)

install(TARGETS recvfast
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
