# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB FILEGROUP_SDK_HEADER_BASE
    ${PROJECT_SOURCE_DIR}/sdk/base/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/base/basic/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/base/stream/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/base/string/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/base/system/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/base/unittest/*.hpp
)

file (GLOB FILEGROUP_SDK_SOURCE_BASE
    ${PROJECT_SOURCE_DIR}/sdk/base/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/basic/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/nostd/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/stream/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/string/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/system/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/unittest/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_BASE_LINUX
    ${PROJECT_SOURCE_DIR}/sdk/base/system/linux/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_BASE_WIN32
    ${PROJECT_SOURCE_DIR}/sdk/base/stream/windows/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/string/windows/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/system/windows/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_BASE_WIN32_UNICODE
    ${PROJECT_SOURCE_DIR}/sdk/base/basic/unicode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/stream/unicode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/string/unicode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/base/system/windows/unicode/*.cpp
)

set_source_files_properties(${FILEGROUP_SDK_SOURCE_BASE_WIN32_UNICODE} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

if (UNIX)
set (FILEGROUP_SDK_BASE ${FILEGROUP_SDK_HEADER_BASE} ${FILEGROUP_SDK_SOURCE_BASE} ${FILEGROUP_SDK_SOURCE_BASE_LINUX})
set (PLATFORM_LIB_SDK_BASE )
elseif (WIN32)
set (FILEGROUP_SDK_BASE ${FILEGROUP_SDK_HEADER_BASE} ${FILEGROUP_SDK_SOURCE_BASE} ${FILEGROUP_SDK_SOURCE_BASE_WIN32} ${FILEGROUP_SDK_SOURCE_BASE_WIN32_UNICODE})
set (PLATFORM_LIB_SDK_BASE ws2_32)
endif ()

if (SUPPORT_STATIC GREATER 0)
    makelib(${PROJECT_SDK_MODULE_BASE} STATIC FILEGROUP_SDK_BASE FILEGROUP_SDK_HEADER_BASE PLATFORM_LIB_SDK_BASE)
endif ()

if (SUPPORT_SHARED GREATER 0)
    makelib(${PROJECT_SDK_MODULE_BASE} SHARED FILEGROUP_SDK_BASE FILEGROUP_SDK_HEADER_BASE PLATFORM_LIB_SDK_BASE)
endif ()
