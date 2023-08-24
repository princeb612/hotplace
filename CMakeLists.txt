# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

cmake_minimum_required (VERSION 2.6)
project (hotplace)

set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_VERBOSE_MAKEFILE ON)

set (CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}") #  -Wl,--rpath,${CMAKE_INSTALL_RPATH}

if (UNIX)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-z,noexecstack")
endif ()

set (SUPPORT_STATIC 1)
if (UNIX)
set (SUPPORT_SHARED 0)
elseif (WIN32)
set (SUPPORT_SHARED 1)
endif ()

set (PROJECT_SDK_MODULE_BASE ${CMAKE_PROJECT_NAME}-sdk-base)
set (PROJECT_SDK_MODULE_IO ${CMAKE_PROJECT_NAME}-sdk-io)
set (PROJECT_SDK_MODULE_CRYPTO ${CMAKE_PROJECT_NAME}-sdk-crypto)
set (PROJECT_SDK_MODULE_NET ${CMAKE_PROJECT_NAME}-sdk-net)
set (PROJECT_SDK_MODULE_DEPENDENCIES ${PROJECT_SDK_MODULE_BASE}-static ${PROJECT_SDK_MODULE_IO}-static ${PROJECT_SDK_MODULE_CRYPTO}-static ${PROJECT_SDK_MODULE_NET}-static)

if (UNIX)
set (PROJECT_SDK_PLATFORM_DEPENDENCIES pthread crypto ssl jansson z)
elseif (WIN32)
set (PROJECT_SDK_PLATFORM_DEPENDENCIES ws2_32 crypto ssl jansson z)
endif ()

function(copy_headers_with_hierarchy SOURCE_DIR DESTINATION_DIR)
    file(GLOB_RECURSE HEADER_FILES ${SOURCE_DIR}/*.hpp ${SOURCE_DIR}/*.h)

    foreach(HEADER_FILE ${HEADER_FILES})
        file(RELATIVE_PATH HEADER_RELATIVE_PATH ${SOURCE_DIR} ${HEADER_FILE})
        get_filename_component(HEADER_DESTINATION_PATH "${DESTINATION_DIR}/${HEADER_RELATIVE_PATH}" DIRECTORY)

        file(MAKE_DIRECTORY ${HEADER_DESTINATION_PATH})
        file(COPY ${HEADER_FILE} DESTINATION ${HEADER_DESTINATION_PATH})
    endforeach()
endfunction()

# makelib name type source header library
function (makelib module_name module_type group_source group_header module_library)
    message (STATUS "makelib ${module_name} ${module_type} ${group_source} ${group_header} ${module_library}")
    message (STATUS "\\- module_library ${${module_library}}")
    string (TOLOWER ${module_type} postfix)
    add_library(${module_name}-${postfix} ${module_type} ${${group_source}})
    target_precompile_headers(${module_name}-${postfix} PRIVATE ${${group_header}})
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
    target_precompile_headers(${module_name}-${postfix} PRIVATE ${${group_header}})
    set_target_properties(${module_name}-${postfix} PROPERTIES OUTPUT_NAME ${module_name} CLEAN_DIRECT_OUTPUT 1 LINKER_LANGUAGE CXX)
    target_link_libraries(${module_name}-${postfix} ${${module_dependency}} ${${module_library}})
    add_dependencies(${module_name}-${postfix} ${${module_dependency}})
    add_custom_command(TARGET ${module_name}-${postfix} POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${module_name}-${postfix}> ${CMAKE_INSTALL_RPATH})
endfunction ()

# maketest name source dependency library
function (maketest module_name group_source module_dependency module_library)
    message (STATUS "maketest ${module_name} ${group_source} ${module_dependency} ${module_library}")
    message (STATUS "\\- module_dependency ${${module_dependency}}")
    message (STATUS "\\- module_library ${${module_library}}")
    add_executable (test-${module_name} ${${group_source}})
    target_link_libraries (test-${module_name} ${${module_dependency}} ${${module_library}})
    add_dependencies (test-${module_name} ${${module_dependency}})
    add_test (NAME test-${module_name} COMMAND test-${module_name})
endfunction ()

include_directories (..)
link_directories (${CMAKE_INSTALL_RPATH})

file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
file (COPY ${PROJECT_SOURCE_DIR}/test/test.sh DESTINATION ${PROJECT_SOURCE_DIR}/build/test/)

copy_headers_with_hierarchy(${PROJECT_SOURCE_DIR}/sdk ${PROJECT_SOURCE_DIR}/include)

add_subdirectory (sdk)
add_subdirectory (test)
enable_testing ()
