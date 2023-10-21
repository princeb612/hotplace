# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB FILEGROUP_SDK_HEADER_IO
    ${PROJECT_SOURCE_DIR}/sdk/io/basic/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/io/cbor/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/io/stream/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/io/string/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/io/system/*.hpp
)

file (GLOB FILEGROUP_SDK_SOURCE_IO
    ${PROJECT_SOURCE_DIR}/sdk/io/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/basic/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/cbor/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/string/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/stream/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/system/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_IO_LINUX
    ${PROJECT_SOURCE_DIR}/sdk/io/stream/linux/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/system/linux/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_IO_WIN32
    ${PROJECT_SOURCE_DIR}/sdk/io/stream/windows/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/string/windows/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/system/windows/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_IO_WIN32_UNICODE
    ${PROJECT_SOURCE_DIR}/sdk/io/stream/unicode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/string/unicode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/io/system/windows/unicode/*.cpp
)

set_source_files_properties(${FILEGROUP_SDK_SOURCE_IO_WIN32_UNICODE} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

if (UNIX)
set (FILEGROUP_SDK_IO ${FILEGROUP_SDK_HEADER_IO} ${FILEGROUP_SDK_SOURCE_IO} ${FILEGROUP_SDK_SOURCE_IO_LINUX})
set (PLATFORM_LIB_SDK_IO z)
elseif (WIN32)
set (FILEGROUP_SDK_IO ${FILEGROUP_SDK_HEADER_IO} ${FILEGROUP_SDK_SOURCE_IO} ${FILEGROUP_SDK_SOURCE_IO_WIN32} ${FILEGROUP_SDK_SOURCE_IO_WIN32_UNICODE})
set (PLATFORM_LIB_SDK_IO ws2_32 z bfd)
endif ()

if (SUPPORT_STATIC GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_IO_STATIC ${PROJECT_SDK_MODULE_BASE}-static)
    makelibdep(${PROJECT_SDK_MODULE_IO} STATIC FILEGROUP_SDK_IO FILEGROUP_SDK_HEADER_IO PROJECT_SDK_MODULE_DEPENDENCIES_IO_STATIC PLATFORM_LIB_SDK_IO)
endif ()

if (SUPPORT_SHARED GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_IO_SHARED ${PROJECT_SDK_MODULE_BASE}-shared)
    makelibdep(${PROJECT_SDK_MODULE_IO} SHARED FILEGROUP_SDK_IO FILEGROUP_SDK_HEADER_IO PROJECT_SDK_MODULE_DEPENDENCIES_IO_SHARED PLATFORM_LIB_SDK_IO)
endif ()
