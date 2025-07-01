cmake_minimum_required(VERSION 3.15) # 버전을 3.15로 올리는 것을 권장합니다.
project(ASM_System CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find necessary packages (버전 정보는 vcpkg가 알아서 찾으므로 생략 가능)
find_package(Boost REQUIRED COMPONENTS system process)
find_package(yaml-cpp REQUIRED)
find_package(Threads REQUIRED)
find_package(PugiXML REQUIRED)
find_package(spdlog REQUIRED)
find_package(Crow REQUIRED)
find_package(SQLite3 REQUIRED)

# Add executable
add_executable(asm asm/ASM.cpp)

# Link libraries
target_link_libraries(asm
    PRIVATE
    # vcpkg가 제공하는 표준 타겟 이름만 명시합니다.
    Threads::Threads
    Boost::system
    Boost::process
    yaml-cpp::yaml-cpp   
    pugixml::pugixml     
    spdlog::spdlog       
    Crow::Crow 
    SQLite::SQLite3      # <-- ${SQLITE3_LIBRARIES} 대신 이 타겟 이름을 사용합니다.
)

# --- 아래 'target_include_directories' 섹션은 vcpkg 사용 시 불필요하므로 모두 삭제합니다. ---
# target_include_directories(asm
#     PRIVATE
#     ${Boost_INCLUDE_DIRS}
#     ${YAML-CPP_INCLUDE_DIRS}
#     ${PUGIXML_INCLUDE_DIR}
#     ${SPDLOG_INCLUDE_DIRS}
#     ${CROW_INCLUDE_DIRS}
# )