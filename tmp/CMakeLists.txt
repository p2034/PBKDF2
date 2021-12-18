cmake_minimum_required(VERSION 3.8)

# https://cmake.org/cmake/help/latest/prop_tgt/CXX_STANDARD.html
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# expected behaviour
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++lastest")

project(PBKDF2)

set(SRCDIR "../src/")

set(OUTPUT test.out)

# add your .cpp files here
add_executable(${OUTPUT} ../tests/test_oop.cpp ../tests/hmac.cpp ../tests/sha256.cpp ../src/pbkdf2/functional/pbkdf2.cpp)

# add include directory
target_include_directories(${OUTPUT} PUBLIC ../src/pbkdf2/functional)

target_link_libraries(${OUTPUT} PRIVATE ssl crypto)