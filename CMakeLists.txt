# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# cmake -B build -G 'Unix Makefile'

# minimum platform
# - toolchain dependencies : cmake (2.8.10.2)

cmake_minimum_required (VERSION 2.8)

project (hotplace)

# set (CMAKE_BUILD_TYPE Release)
set (CMAKE_VERBOSE_MAKEFILE OFF)
set (CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

set (SET_STDCPP c++11)
set (SET_BUILDDIR build)
set (SUPPORT_DEBUG 0)
set (SUPPORT_ODBC 0)   # 
set (SUPPORT_PCH 0)    # cmake 2.x
set (SUPPORT_OQS 0)    # 
set (SUPPORT_SHARED 0) # set 1 in mingw, ubuntu, custom build
set (SUPPORT_STATIC 1) # 1 if not set disable_static
set (PROJECT_SDK_USE_STD_REGEX 1) # regex

if (NOT "$ENV{CMAKE_VERBOSE_MAKEFILE}" STREQUAL "")
    set (CMAKE_VERBOSE_MAKEFILE "$ENV{CMAKE_VERBOSE_MAKEFILE}")
endif ()
if (NOT "$ENV{CXXFLAGS}" STREQUAL "")
    # specify additional include, lib directories
    set (CMAKE_CXX_FLAGS "$ENV{CXXFLAGS}")
endif ()
if (NOT "$ENV{CMAKE_CXX_COMPILER}" STREQUAL "")
    set (CMAKE_CXX_COMPILER "$ENV{CMAKE_CXX_COMPILER}")
endif ()
if (NOT "$ENV{CMAKE_CXX_FLAGS}" STREQUAL "")
    set (CMAKE_CXX_FLAGS "$ENV{CMAKE_CXX_FLAGS}")
endif ()
if (NOT "$ENV{CMAKE_EXE_LINKER_FLAGS}" STREQUAL "")
    set (CMAKE_EXE_LINKER_FLAGS "$ENV{CMAKE_EXE_LINKER_FLAGS}")
endif ()
if (NOT "$ENV{SUPPORT_DEBUG}" STREQUAL "")
    set (SUPPORT_DEBUG $ENV{SUPPORT_DEBUG})
endif ()
if (NOT "$ENV{SUPPORT_STATIC}" STREQUAL "")
    set (SUPPORT_STATIC $ENV{SUPPORT_STATIC})
endif ()
if (NOT "$ENV{SUPPORT_SHARED}" STREQUAL "")
    set (SUPPORT_SHARED $ENV{SUPPORT_SHARED})
endif ()
if (NOT "$ENV{SUPPORT_ODBC}" STREQUAL "")
    set (SUPPORT_ODBC $ENV{SUPPORT_ODBC})
endif ()
if (CMAKE_VERSION VERSION_GREATER 3.8)
    if (NOT "$ENV{SUPPORT_PCH}" STREQUAL "")
        set (SUPPORT_PCH $ENV{SUPPORT_PCH})
    else (1)
        set (SUPPORT_PCH 1)
    endif ()
endif ()
if (NOT "$ENV{SUPPORT_OQS}" STREQUAL "")
    set (SUPPORT_OQS $ENV{SUPPORT_OQS})
endif ()
if (NOT "$ENV{SET_STDCPP}" STREQUAL "")
    set (SET_STDCPP $ENV{SET_STDCPP})
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (SUPPORT_DEBUG)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG -g")
    endif ()
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
        set (PROJECT_SDK_USE_STD_REGEX 0) # thirdparty
    endif()

    if (UNIX)
    # -std=c++11
    # https://man7.org/linux/man-pages/man8/execstack.8.html
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-z,noexecstack")
    elseif (WIN32)
    set (SET_STDCPP c++14)
    endif ()

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=${SET_STDCPP} -Wl,--as-needed -Wl,--version-script=${PROJECT_SOURCE_DIR}/sdk/version.script")
    set (SET_THIRDPARTY_DIR ${PROJECT_SOURCE_DIR}/thirdparty/gcc)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set (SET_STDCPP c++17) # C7525
    set (SET_BUILDDIR build_msvc)
    # debug iterator
    # compiler | default  | desc
    # gcc      | disabled | turn on  : -D_GLIBCXX_DEBUG
    # msvc     | enabled  | turn on  : -D_ITERATOR_DEBUG_LEVEL=2
    #          |          | turn off : -D_ITERATOR_DEBUG_LEVEL=0
    if (SUPPORT_DEBUG)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
    endif ()
    # set(CMAKE_GENERATOR_PLATFORM x64 CACHE STRING "Target Architecture" FORCE)
    # https://learn.microsoft.com/ko-kr/cpp/standard-library/iterator-debug-level?view=msvc-170
    add_compile_definitions(_$ENV{PROCESSOR_ARCHITECTURE}_ __x86_64__ _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_WARNINGS _ITERATOR_DEBUG_LEVEL=0 NOMINMAX)
    # https://learn.microsoft.com/ko-kr/cpp/build/reference/zc-cplusplus?view=msvc-170
    # https://learn.microsoft.com/ko-kr/cpp/build/reference/utf-8-set-source-and-executable-character-sets-to-utf-8?view=msvc-170
    add_compile_options(/Zc:__cplusplus /std:${SET_STDCPP} /utf-8)
    set (SET_THIRDPARTY_DIR ${PROJECT_SOURCE_DIR}/thirdparty/msvc)
endif ()

# verbose
message (STATUS "CMAKE_VERBOSE_MAKEFILE $ENV{CMAKE_VERBOSE_MAKEFILE}")
message (STATUS "CXXFLAGS $ENV{CXXFLAGS}")
message (STATUS "CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")
message (STATUS "CMAKE_CXX_COMPILER_ID ${CMAKE_CXX_COMPILER_ID}")
message (STATUS "CMAKE_CXX_COMPILER_VERSION ${CMAKE_CXX_COMPILER_VERSION}")
message (STATUS "CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")
message (STATUS "CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS}")
message (STATUS "PROJECT_SDK_USE_STD_REGEX ${PROJECT_SDK_USE_STD_REGEX}")
message (STATUS "SUPPORT_DEBUG ${SUPPORT_DEBUG}")
message (STATUS "SUPPORT_STATIC ${SUPPORT_STATIC}")
message (STATUS "SUPPORT_SHARED ${SUPPORT_SHARED}")
message (STATUS "SUPPORT_ODBC ${SUPPORT_ODBC}")
message (STATUS "SUPPORT_PCH ${SUPPORT_PCH}")
message (STATUS "SUPPORT_OQS ${SUPPORT_OQS}")

# project modules
set (PROJECT_SDK_MODULE_BASE ${CMAKE_PROJECT_NAME}-sdk-base)
set (PROJECT_SDK_MODULE_IO ${CMAKE_PROJECT_NAME}-sdk-io)
set (PROJECT_SDK_MODULE_CRYPTO ${CMAKE_PROJECT_NAME}-sdk-crypto)
set (PROJECT_SDK_MODULE_NET ${CMAKE_PROJECT_NAME}-sdk-net)
set (PROJECT_SDK_MODULE_ODBC ${CMAKE_PROJECT_NAME}-sdk-odbc)
if (SUPPORT_STATIC)
    set (MODULE_SO_TYPE "static")
elseif (SUPPORT_SHARED)
    set (MODULE_SO_TYPE "shared")
endif ()

set (PROJECT_SDK_MODULE_DEPENDENCIES ${PROJECT_SDK_MODULE_BASE}-${MODULE_SO_TYPE} ${PROJECT_SDK_MODULE_IO}-${MODULE_SO_TYPE} ${PROJECT_SDK_MODULE_CRYPTO}-${MODULE_SO_TYPE} ${PROJECT_SDK_MODULE_NET}-${MODULE_SO_TYPE})
if (SUPPORT_ODBC)
    set (PROJECT_SDK_MODULE_DEPENDENCIES ${PROJECT_SDK_MODULE_DEPENDENCIES} ${PROJECT_SDK_MODULE_ODBC}-${MODULE_SO_TYPE})
endif ()

# dependencies
if (SUPPORT_DEBUG)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set (PROJECT_THIRDPARTY_DEPENDENCIES crypto ssl jansson_d zd yaml-cppd)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        set (PROJECT_THIRDPARTY_DEPENDENCIES libcrypto libssl jansson_d zd yaml-cppd)
    endif ()
else (1)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set (PROJECT_THIRDPARTY_DEPENDENCIES crypto ssl jansson z yaml-cpp)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        set (PROJECT_THIRDPARTY_DEPENDENCIES libcrypto libssl jansson z yaml-cpp)
    endif ()
endif ()

if (UNIX)
    set (PROJECT_SDK_PLATFORM_DEPENDENCIES dl pthread ${PROJECT_THIRDPARTY_DEPENDENCIES})
elseif (WIN32)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set (PROJECT_SDK_PLATFORM_DEPENDENCIES ws2_32 ${PROJECT_THIRDPARTY_DEPENDENCIES})
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        set (PROJECT_SDK_PLATFORM_DEPENDENCIES ws2_32 ${PROJECT_THIRDPARTY_DEPENDENCIES})
    endif ()
endif ()
if (PROJECT_SDK_USE_STD_REGEX EQUAL 0)
    set (PROJECT_SDK_PLATFORM_DEPENDENCIES ${PROJECT_SDK_PLATFORM_DEPENDENCIES} pcre)
endif ()

if (SUPPORT_ODBC)
# yum install unixodbc-devel
# pacman -S mingw64/mingw-w64-x86_64-unixodbc-dev
# or custom build
set (PROJECT_SDK_PLATFORM_DEPENDENCIES ${PROJECT_SDK_PLATFORM_DEPENDENCIES} odbc)
endif ()

# copy header files to destination
function(copy_headers_with_hierarchy SOURCE_DIR DESTINATION_DIR)
    if(CMAKE_VERSION VERSION_LESS 3.0)
    else(1)
        file(GLOB_RECURSE HEADER_FILES ${SOURCE_DIR}/*.hpp ${SOURCE_DIR}/*.h)

        foreach(HEADER_FILE ${HEADER_FILES})
            file(RELATIVE_PATH HEADER_RELATIVE_PATH ${SOURCE_DIR} ${HEADER_FILE})
            get_filename_component(HEADER_DESTINATION_PATH "${DESTINATION_DIR}/${HEADER_RELATIVE_PATH}" DIRECTORY)

            file(MAKE_DIRECTORY ${HEADER_DESTINATION_PATH})
            file(COPY ${HEADER_FILE} DESTINATION ${HEADER_DESTINATION_PATH})
        endforeach()
    endif()
endfunction()

# makelib name type source header library
function (makelib module_name module_type group_source group_header module_library)
    message (STATUS "makelib ${module_name} ${module_type} ${group_source} ${group_header} ${module_library}")
    message (STATUS "\\- module_library ${${module_library}}")
    string (TOLOWER ${module_type} postfix)
    add_library(${module_name}-${postfix} ${module_type} ${${group_source}})
    if(SUPPORT_PCH)
        target_precompile_headers(${module_name}-${postfix} PRIVATE ${${group_header}})
    endif ()
    set_target_properties(${module_name}-${postfix} PROPERTIES OUTPUT_NAME ${module_name} CLEAN_DIRECT_OUTPUT 1 LINKER_LANGUAGE CXX)
    target_link_libraries(${module_name}-${postfix} ${${module_library}})
    add_custom_command(TARGET ${module_name}-${postfix} POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${module_name}-${postfix}> ${CMAKE_INSTALL_RPATH})
endfunction ()

# makelib name type source header dependency library
function (makelibdep module_name module_type group_source group_header module_dependency module_library)
    message (STATUS "makelibdep ${module_name} ${module_type} ${group_source} ${group_header} ${module_dependency} ${module_library}")
    message (STATUS "\\- module_dependency ${${module_dependency}}")
    message (STATUS "\\- module_library ${${module_library}}")
    string (TOLOWER ${module_type} postfix)
    add_library(${module_name}-${postfix} ${module_type} ${${group_source}})
    if(SUPPORT_PCH)
        target_precompile_headers(${module_name}-${postfix} PRIVATE ${${group_header}})
    endif ()
    set_target_properties(${module_name}-${postfix} PROPERTIES OUTPUT_NAME ${module_name} CLEAN_DIRECT_OUTPUT 1 LINKER_LANGUAGE CXX)
    target_link_libraries(${module_name}-${postfix} ${${module_dependency}} ${${module_library}})
    add_dependencies(${module_name}-${postfix} ${${module_dependency}})
    add_custom_command(TARGET ${module_name}-${postfix} POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${module_name}-${postfix}> ${CMAKE_INSTALL_RPATH})
endfunction ()

# maketest name source dependency library
function (maketest module_name group_source module_dependency module_library ctest)
    message (STATUS "maketest ${module_name} ${group_source} ${module_dependency} ${module_library}")
    message (STATUS "\\- module_dependency ${${module_dependency}}")
    message (STATUS "\\- module_library ${${module_library}}")
    message (STATUS "\\- ctest ${ctest}")
    add_executable (test-${module_name} ${${group_source}})
    target_link_libraries (test-${module_name} ${${module_dependency}} ${${module_library}})
    add_dependencies (test-${module_name} ${${module_dependency}})
    if (${ctest})
        add_test (NAME test-${module_name} COMMAND test-${module_name})
    endif ()
endfunction ()

# -Ixxx
include_directories (..)
include_directories (${SET_THIRDPARTY_DIR}/include)
# -Lxxx
link_directories (${CMAKE_INSTALL_RPATH})
link_directories (${SET_THIRDPARTY_DIR}/lib64)
link_directories (${SET_THIRDPARTY_DIR}/lib)

# mkdir xxx
file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
# copy header files
copy_headers_with_hierarchy(${PROJECT_SOURCE_DIR}/sdk ${PROJECT_SOURCE_DIR}/include/hotplace/sdk)

# build
add_subdirectory (sdk)
# test
enable_testing ()
# testcase
add_subdirectory (testcase)
# applet
add_subdirectory (testapplet)

# copy certificates
add_subdirectory (etc)
