# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB FILEGROUP_SDK_HEADER_NET
    ${PROJECT_SOURCE_DIR}/sdk/net/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/basic/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/auth/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/http2/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/http3/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/server/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/extension/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/handshake/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/record/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/frame/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/packet/*.hpp
)

file (GLOB FILEGROUP_SDK_SOURCE_NET
    ${PROJECT_SOURCE_DIR}/sdk/net/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/basic/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/auth/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/http2/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/http/http3/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/server/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/advisor/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/extension/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/handshake/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/protection/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/tls1/record/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/frame/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/net/quic/packet/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_NET_LINUX
)

file (GLOB FILEGROUP_SDK_SOURCE_NET_WIN32
    ${PROJECT_SOURCE_DIR}/sdk/net/basic/windows/*.cpp
)

if (UNIX)
set (FILEGROUP_SDK_NET ${FILEGROUP_SDK_HEADER_NET} ${FILEGROUP_SDK_SOURCE_NET} ${FILEGROUP_SDK_SOURCE_NET_LINUX})
set (PLATFORM_LIB_SDK_NET crypto ssl)
elseif (WIN32)
set (FILEGROUP_SDK_NET ${FILEGROUP_SDK_HEADER_NET} ${FILEGROUP_SDK_SOURCE_NET} ${FILEGROUP_SDK_SOURCE_NET_WIN32})
set (PLATFORM_LIB_SDK_NET crypto ssl)
endif ()

if (SUPPORT_STATIC GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_NET_STATIC ${PROJECT_SDK_MODULE_BASE}-static ${PROJECT_SDK_MODULE_IO}-static ${PROJECT_SDK_MODULE_CRYPTO}-static)
    makelibdep(${PROJECT_SDK_MODULE_NET} STATIC FILEGROUP_SDK_NET FILEGROUP_SDK_HEADER_NET PROJECT_SDK_MODULE_DEPENDENCIES_NET_STATIC PLATFORM_LIB_SDK_NET)
endif ()

if (SUPPORT_SHARED GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_NET_SHARED ${PROJECT_SDK_MODULE_BASE}-shared ${PROJECT_SDK_MODULE_IO}-shared ${PROJECT_SDK_MODULE_CRYPTO}-static)
    makelibdep(${PROJECT_SDK_MODULE_NET} SHARED FILEGROUP_SDK_NET FILEGROUP_SDK_HEADER_NET PROJECT_SDK_MODULE_DEPENDENCIES_NET_SHARED PLATFORM_LIB_SDK_NET)
endif ()
