cmake_minimum_required(VERSION 2.8)
project(sec_doodle)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)


include_directories(${PROJECT_SOURCE_DIR}/boost_export)

find_package(OpenSSL REQUIRED QUIET)
find_package(ABY QUIET)
if(ABY_FOUND)
	message(STATUS "Found ABY")
elseif (NOT ABY_FOUND AND NOT TARGET ABY::aby)
	message("ABY was not found: add ABY subdirectory")
	add_subdirectory(extern/ABY)
endif()


add_executable(sec_doodle sec_doodle.cpp common/sec_doodle.cpp)
target_link_libraries(sec_doodle ABY::aby)
target_link_libraries(sec_doodle OpenSSL::SSL)
