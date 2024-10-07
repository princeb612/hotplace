# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

cmake_minimum_required (VERSION 2.6)
#cmake_minimum_required (VERSION 3.5)
project (hotplace)

#set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_VERBOSE_MAKEFILE OFF)
set (CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set (SUPPORT_STATIC 1) # always set 1
set (SUPPORT_SHARED 0) # set 1 in mingw, ubuntu, custom build
set (SUPPORT_ODBC 0)   # 
set (SUPPORT_PCH 0)    # cmake 2.x
set (SET_STDCPP c++14)

if (NOT "$ENV{CXXFLAGS}" STREQUAL "")
    # specify additional include, lib directories
    set (CMAKE_CXX_FLAGS "$ENV{CXXFLAGS}")
endif ()
if (NOT "$ENV{CMAKE_CXX_COMPILER}" STREQUAL "")
    set (CMAKE_CXX_COMPILER "$ENV{CMAKE_CXX_COMPILER}")
endif ()
if (NOT "$ENV{CMAKE_CXX_FLAGS}" STREQUAL "")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} $ENV{CMAKE_CXX_FLAGS}")
endif ()
if (NOT "$ENV{SUPPORT_SHARED}" STREQUAL "")
    set (SUPPORT_SHARED $ENV{SUPPORT_SHARED})
endif ()
if (NOT "$ENV{SUPPORT_ODBC}" STREQUAL "")
    set (SUPPORT_ODBC $ENV{SUPPORT_ODBC})
endif ()
if(CMAKE_VERSION VERSION_GREATER 3.8)
    if (NOT "$ENV{SUPPORT_PCH}" STREQUAL "")
        set (SUPPORT_PCH $ENV{SUPPORT_PCH})
    else (1)
        set (SUPPORT_PCH 1)
    endif ()
endif ()
if (NOT "$ENV{SET_STDCPP}" STREQUAL "")
    set (SET_STDCPP $ENV{SET_STDCPP})
endif ()
if (UNIX)
# -std=c++11
# -Wl,-z,noexecstack
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=${SET_STDCPP} -Wl,-z,noexecstack -Wl,--as-needed -Wl,--version-script=${PROJECT_SOURCE_DIR}/sdk/hotplace.version")
else (1)
endif ()

# verbose
message (STATUS "CXXFLAGS $ENV{CXXFLAGS}")
message (STATUS "CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")
message (STATUS "SUPPORT_STATIC ${SUPPORT_STATIC}")
message (STATUS "SUPPORT_SHARED ${SUPPORT_SHARED}")
message (STATUS "SUPPORT_ODBC ${SUPPORT_ODBC}")
message (STATUS "SUPPORT_PCH ${SUPPORT_PCH}")

# project modules
set (PROJECT_SDK_MODULE_BASE ${CMAKE_PROJECT_NAME}-sdk-base)
set (PROJECT_SDK_MODULE_IO ${CMAKE_PROJECT_NAME}-sdk-io)
set (PROJECT_SDK_MODULE_CRYPTO ${CMAKE_PROJECT_NAME}-sdk-crypto)
set (PROJECT_SDK_MODULE_NET ${CMAKE_PROJECT_NAME}-sdk-net)
set (PROJECT_SDK_MODULE_ODBC ${CMAKE_PROJECT_NAME}-sdk-odbc)
set (PROJECT_SDK_MODULE_DEPENDENCIES ${PROJECT_SDK_MODULE_BASE}-static ${PROJECT_SDK_MODULE_IO}-static ${PROJECT_SDK_MODULE_CRYPTO}-static ${PROJECT_SDK_MODULE_NET}-static)
if (SUPPORT_ODBC)
set (PROJECT_SDK_MODULE_DEPENDENCIES ${PROJECT_SDK_MODULE_DEPENDENCIES} ${PROJECT_SDK_MODULE_ODBC}-static)
endif ()

# dependencies
if (UNIX)
set (PROJECT_SDK_PLATFORM_DEPENDENCIES dl pthread crypto ssl jansson z)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        message(STATUS "GCC version " ${CMAKE_CXX_COMPILER_VERSION})
        if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
            set (PROJECT_SDK_PLATFORM_DEPENDENCIES ${PROJECT_SDK_PLATFORM_DEPENDENCIES} pcre)
        endif()
    endif()
elseif (WIN32)
set (PROJECT_SDK_PLATFORM_DEPENDENCIES ws2_32 crypto ssl jansson z)
endif ()
if (SUPPORT_ODBC)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSUPPORT_FEATURE_ODBC")
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
include_directories (.)
include_directories (${PROJECT_SOURCE_DIR}/thirdparty/include)
# -Lxxx
link_directories (${CMAKE_INSTALL_RPATH})
link_directories (${PROJECT_SOURCE_DIR}/thirdparty/lib64)
link_directories (${PROJECT_SOURCE_DIR}/thirdparty/lib)

# mkdir xxx
file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
# copy test.sh to xxx/build/test/
file (COPY ${PROJECT_SOURCE_DIR}/test/test.sh DESTINATION ${PROJECT_SOURCE_DIR}/build/test/)

# copy header files
copy_headers_with_hierarchy(${PROJECT_SOURCE_DIR}/sdk ${PROJECT_SOURCE_DIR}/include/hotplace/sdk)

# build
add_subdirectory (sdk)
# test
enable_testing ()
add_subdirectory (test)

