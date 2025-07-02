cmake_minimum_required(VERSION 3.15)
project(asm)

add_executable(asm "asm.cpp" "asm.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET asm PROPERTY CXX_STANDARD 20)
endif()

find_package(Boost REQUIRED COMPONENTS process)
find_package(crow CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(pugixml CONFIG REQUIRED)
find_package(SQLite3 REQUIRED)

target_link_libraries(asm
  PRIVATE
    Boost::process
    crow
    yaml-cpp
    spdlog::spdlog
    pugixml
    SQLite::SQLite3
)
