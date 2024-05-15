# INSTALL TO BUILD DIRECTORY INSTEAD OF SYSTEM WIDE
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}" CACHE PATH "install location" FORCE)
endif()
set(TEST_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test")

# https://cmake.org/cmake/help/latest/command/set.html
set(DEBUG_BUILD TRUE CACHE BOOL "enable extra debugging tests & messages")
set(BUILD_TESTS FALSE CACHE BOOL "whether to build the tests")
set(ENABLE_COLOR_OUTPUT TRUE CACHE BOOL "enable color for compiler output (applicable only for GNU compiler)")
set(IS_MINGW_SUBSYSTEM TRUE CACHE BOOL "enable if compiling within a mingw on windows")
set(USE_OUTSIDE_MINGW TRUE CACHE BOOL "enable if you want to use your compiled binaries outside of mingw (applicable only if IS_MINGW_SUBSYSTEM is enabled)")
cmake_path(SET doxygen_config_path_default "${CMAKE_SOURCE_DIR}/src/doxygen.conf.in")
set(DOXYGEN_CONFIG_PATH "${doxygen_config_path_default}" CACHE PATH "doxygen config path input file (configures it first if it ends in \".in\")")

set(doxygen_configured FALSE)
find_package(Doxygen)
if(TARGET Doxygen::doxygen)
    message(VERBOSE "Doxygen found")
    if(EXISTS "${DOXYGEN_CONFIG_PATH}")
        message(VERBOSE "Doxygen config found")
        cmake_path(GET DOXYGEN_CONFIG_PATH FILENAME doxygen_config_path_name)
        cmake_path(GET DOXYGEN_CONFIG_PATH EXTENSION LAST_ONLY doxygen_config_path_ext)
        if("${doxygen_config_path_ext}" STREQUAL ".in") # doxygen config has ".in" extension
            # remove .in extension in output file and configure
            cmake_path(REMOVE_EXTENSION doxygen_config_path_name LAST_ONLY OUTPUT_VARIABLE doxygen_config_path_without_ext)
            cmake_path(SET doxygen_config_path_configured "${CMAKE_BINARY_DIR}/${doxygen_config_path_without_ext}")
            configure_file("${DOXYGEN_CONFIG_PATH}" "${doxygen_config_path_configured}")
        else()
            # keep extension as is and just copy file
            cmake_path(SET doxygen_config_path_configured "${CMAKE_BINARY_DIR}/${doxygen_config_path_without_ext}")
            configure_file("${DOXYGEN_CONFIG_PATH}" "${doxygen_config_path_configured}" COPYONLY)
        endif()
        set(doxygen_configured TRUE)
    else() # config path does not exist
        message(VERBOSE "Doxygen config was not found, no docs will be generated")
    endif()
else() # doxygen not found
    message(STATUS "Doxygen not found, will not genererate documentation")
endif() # doxygen target


# FIND DEPENDENCIES AND LINK TO THEM
add_library(deps INTERFACE)

# find_package(some__pkg)
# target_link_libraries(deps INTERFACE some__pkg::some__pkg)

# ONLY COMPILED LIBRARIES NEED TO BE FOUND AND LINKED AGAINST
# example below for linking boost beast required libraries
# find_package(Boost REQUIRED COMPONENTS system regex locale)
# target_link_libraries(deps INTERFACE Boost::system Boost::regex Boost::locale ws2_32 mswsock)

find_package(msd-cpp-utils)


# COMPILE FEATURES AND OPTIONS COMMON FOR ALL TARGETS
add_library(common INTERFACE)
target_compile_features(common INTERFACE cxx_std_23)

target_link_libraries(common INTERFACE msd-cpp-utils::msd-cpp-utils)

# https://cmake.org/cmake/help/latest/manual/cmake-generator-expressions.7.html
# https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html
# ENABLE WARNINGS FOR GNU
target_compile_options(common INTERFACE
    $<$<CXX_COMPILER_ID:GNU>:-g>
    $<$<CXX_COMPILER_ID:GNU>:-O>
    $<$<CXX_COMPILER_ID:GNU>:-Wall>
    $<$<CXX_COMPILER_ID:GNU>:-Weffc++>
    $<$<CXX_COMPILER_ID:GNU>:-pedantic>
    $<$<CXX_COMPILER_ID:GNU>:-pedantic-errors>
    $<$<CXX_COMPILER_ID:GNU>:-Wextra>
    # $<$<CXX_COMPILER_ID:GNU>:-Waggregate-return>
    $<$<CXX_COMPILER_ID:GNU>:-Wcast-align>
    $<$<CXX_COMPILER_ID:GNU>:-Wcast-qual>
    $<$<CXX_COMPILER_ID:GNU>:-Wconversion>
    $<$<CXX_COMPILER_ID:GNU>:-Wdisabled-optimization>
    $<$<CXX_COMPILER_ID:GNU>:-Werror>
    $<$<CXX_COMPILER_ID:GNU>:-Wfloat-equal>
    $<$<CXX_COMPILER_ID:GNU>:-Wformat=2>
    $<$<CXX_COMPILER_ID:GNU>:-Wformat-nonliteral>
    $<$<CXX_COMPILER_ID:GNU>:-Wformat-security>
    $<$<CXX_COMPILER_ID:GNU>:-Wformat-y2k>
    $<$<CXX_COMPILER_ID:GNU>:-Wimport>
    $<$<CXX_COMPILER_ID:GNU>:-Winit-self>
    # $<$<CXX_COMPILER_ID:GNU>:-Winline>
    $<$<CXX_COMPILER_ID:GNU>:-Winvalid-pch>
    # $<$<CXX_COMPILER_ID:GNU>:-Wlong-long>
    $<$<CXX_COMPILER_ID:GNU>:-Wmissing-field-initializers>
    $<$<CXX_COMPILER_ID:GNU>:-Wmissing-format-attribute>
    $<$<CXX_COMPILER_ID:GNU>:-Wmissing-include-dirs>
    $<$<CXX_COMPILER_ID:GNU>:-Wmissing-noreturn>
    $<$<CXX_COMPILER_ID:GNU>:-Wpacked>
    # $<$<CXX_COMPILER_ID:GNU>:-Wpadded>
    $<$<CXX_COMPILER_ID:GNU>:-Wpointer-arith>
    $<$<CXX_COMPILER_ID:GNU>:-Wredundant-decls>
    $<$<CXX_COMPILER_ID:GNU>:-Wshadow> # alternatively use either -Wshadow-compatible OR -Wshadow-compatible-local
    $<$<CXX_COMPILER_ID:GNU>:-Wstack-protector>
    $<$<CXX_COMPILER_ID:GNU>:-Wstrict-aliasing=2>
    $<$<CXX_COMPILER_ID:GNU>:-Wswitch-default>
    $<$<CXX_COMPILER_ID:GNU>:-Wswitch-enum>
    $<$<CXX_COMPILER_ID:GNU>:-Wunreachable-code>
    $<$<CXX_COMPILER_ID:GNU>:-Wunused>
    $<$<CXX_COMPILER_ID:GNU>:-Wunused-parameter>
    $<$<CXX_COMPILER_ID:GNU>:-Wvariadic-macros>
    $<$<CXX_COMPILER_ID:GNU>:-Wwrite-strings>
    # $<$<CXX_COMPILER_ID:GNU>:-Wctor-dtor-privacy>
    # $<$<CXX_COMPILER_ID:GNU>:-Wlogical-op>
    # $<$<CXX_COMPILER_ID:GNU>:-Wmissing-declarations>
    # $<$<CXX_COMPILER_ID:GNU>:-Wnoexcept>
    # $<$<CXX_COMPILER_ID:GNU>:-Wold-style-cast>
    # $<$<CXX_COMPILER_ID:GNU>:-Woverloaded-virtual>
    # $<$<CXX_COMPILER_ID:GNU>:-Wsign-conversion>
    # $<$<CXX_COMPILER_ID:GNU>:-Wsign-promo>
    # $<$<CXX_COMPILER_ID:GNU>:-Wstrict-null-sentinel>
    # $<$<CXX_COMPILER_ID:GNU>:-Wstrict-overflow=5>
    # $<$<CXX_COMPILER_ID:GNU>:-Wundef>
)

# COMMON MS VISUAL C++ WARNINGS
target_compile_options(common INTERFACE $<$<CXX_COMPILER_ID:MSVC>:/WX /Wall>)

set(is_gnu $<CXX_COMPILER_ID:GNU>)

# ENABLE COLOR OUTPUT
set(should_enable_color $<AND:${is_gnu},$<BOOL:${ENABLE_COLOR_OUTPUT}>>)
target_compile_options(common INTERFACE $<${should_enable_color}:-fdiagnostics-color>)

set(will_use_outside_mingw $<AND:$<BOOL:${IS_MINGW_SUBSYSTEM}>,$<BOOL:${USE_OUTSIDE_MINGW}>>)
set(will_use_outside_mingw_and_gnu $<AND:${will_use_outside_mingw},${is_gnu}>)
target_link_libraries(common INTERFACE
    $<${will_use_outside_mingw_and_gnu}:-static-libgcc>
    $<${will_use_outside_mingw_and_gnu}:-static-libstdc++> # causes linking errors, sometimes
)

# enable fanitize address which is only available for cygwin and non windows
set(should_enable_address_sanitizer $<OR:$<BOOL:${CYGWIN}>,$<NOT:$<BOOL:${CMAKE_HOST_WIN32}>>>)
target_link_libraries(common INTERFACE
    $<${should_enable_address_sanitizer}:-fsanitize=address> # not avaiable on MSYS/MINGW
)

set(should_build_debug $<OR:$<CONFIG:Debug>,$<BOOL:${DEBUG_BUILD}>>)
set(should_enable_gnu_debug_flags $<AND:${is_gnu},${should_build_debug}>)
target_link_libraries(common INTERFACE $<${should_enable_gnu_debug_flags}:-ggdb3>)
target_compile_definitions(common INTERFACE $<${should_build_debug}:UNTITLED_PROJECT_IS_DEBUG>)


if(BUILD_TESTS)
    
    # LINK TESTING LIBRARY
    find_package(Catch2 3 REQUIRED)

    add_executable(tests tests.cpp)
    target_link_libraries(tests PUBLIC common Catch2::Catch2WithMain)

    set_target_properties(
        tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIRECTORY}/bin"
        PDB_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIRECTORY}/pdb"
        ARCHIVE_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIRECTORY}/archive"
        LIBRARY_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIRECTORY}/library"
        COMPILE_PDB_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIRECTORY}/cpdb"
    )

endif()

add_executable(mysha main.cpp utils.cpp)
target_link_libraries(mysha PUBLIC common)

set_target_properties(
    mysha
    PROPERTIES
    # https://cmake.org/cmake/help/latest/prop_tgt/RUNTIME_OUTPUT_DIRECTORY.html
    # https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#runtime-output-artifacts 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    # https://cmake.org/cmake/help/latest/prop_tgt/ARCHIVE_OUTPUT_DIRECTORY.html
    # https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#archive-output-artifacts
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/archive"
    # https://cmake.org/cmake/help/latest/prop_tgt/LIBRARY_OUTPUT_DIRECTORY.html
    # https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html#library-output-artifacts
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/library"
    # https://cmake.org/cmake/help/latest/prop_tgt/PDB_OUTPUT_DIRECTORY.html
    # microsoft debug pdb file generated by linker
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb"
    # https://cmake.org/cmake/help/latest/prop_tgt/COMPILE_PDB_OUTPUT_DIRECTORY.html
    # microsoft debug pdb file generated by compiler
    COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/cpdb"
)
