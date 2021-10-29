cmake_minimum_required(VERSION 3.8)

# https://cmake.org/cmake/help/latest/prop_tgt/CXX_STANDARD.html
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# expected behaviour
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++lastest")

project(PBKDF2)

set(SRCDIR "../src/")

# add your .cpp files here
add_executable(test.out ../tests/test_oop.cpp ../src/pbkdf2/oop/pbkdf2.cpp)

# add include directory
target_include_directories(test.out PUBLIC ../src/pbkdf2/oop)

target_link_libraries(test.out)