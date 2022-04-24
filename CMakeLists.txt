cmake_minimum_required(VERSION 3.21)
project(BPTF_SOCKET)

set(CMAKE_CXX_STANDARD 17)

add_compile_definitions(RAPIDJSON_HAS_STDSTRING=1)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.75.0 REQUIRED)
find_package(RapidJSON REQUIRED)

add_executable(BPTF_SOCKET main.cpp)

include_directories(BPTF_SOCKET PRIVATE ${Boost_INCLUDE_DIR} http_parser ${RAPIDJSON_INCLUDE_DIRS} $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/certify/include>)
TARGET_LINK_LIBRARIES(BPTF_SOCKET PUBLIC ${Boost_LIBRARIES})
target_link_libraries(BPTF_SOCKET PRIVATE OpenSSL::SSL ws2_32)
IF (WIN32)
    TARGET_LINK_LIBRARIES(BPTF_SOCKET PRIVATE crypt32)
    add_compile_definitions(_WIN32_WINNT=0x0601)
    add_compile_definitions(WIN32_LEAN_AND_MEAN)
    add_compile_definitions(BOOST_ASIO_NO_WIN32_LEAN_AND_MEAN )
    add_definitions(/bigobj)
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    add_definitions(-Wa,-mbig-obj)
ENDIF()