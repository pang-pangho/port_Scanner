cmake_minimum_required(VERSION 3.16)
project(MyApp)

# CMP0167 정책 설정 (CMake 3.30+ 전용)
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW) # BoostConfig.cmake 사용
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 외부 라이브러리 찾기 (필요시)
find_package(yaml-cpp REQUIRED)
find_package(spdlog REQUIRED)
find_package(PugiXML REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS process)
# Crow는 헤더온리라면 include_directories만 추가

# 실행 파일 생성 (소스 파일 경로 주의!)
add_executable(port_scanner scanner/port_scanner.cpp)

# 라이브러리 링크
target_link_libraries(port_scanner
    yaml-cpp
    spdlog::spdlog
    pugixml
    Boost::process
)
