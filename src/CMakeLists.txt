cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)

project(MySha VERSION 0.0.1 LANGUAGES CXX)

set( BUILD_TESTS TRUE CACHE BOOL "whether to build the tests" )

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options("-fdiagnostics-color")
endif ()
# TODO IF MSVC -> add_compile_options("/WX /Wall")

if (BUILD_TESTS)
    find_package(Catch2)
    # include("${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
    # conan_basic_setup(TARGETS)
    add_executable(tests tests.cpp)
    # target_include_directories(tests PUBLIC CONAN_PKG::Catch2)
    target_link_libraries(tests PUBLIC Catch2::Catch2)
    target_compile_features(tests PUBLIC cxx_std_20)
endif()

add_executable(mysha main.cpp)
target_compile_features(mysha PUBLIC cxx_std_20)
