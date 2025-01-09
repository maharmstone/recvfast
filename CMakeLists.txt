cmake_minimum_required(VERSION 3.12)

project(recvfast
    LANGUAGES CXX)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_executable(recvfast src/recvfast.cpp)

target_compile_options(recvfast PUBLIC -Wall -Wextra)
target_link_libraries(recvfast PkgConfig::LIBURING)

install(TARGETS recvfast
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
