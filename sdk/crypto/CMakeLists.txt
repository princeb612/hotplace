# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB FILEGROUP_SDK_HEADER_CRYPTO
    ${PROJECT_SOURCE_DIR}/sdk/crypto/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/authenticode/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/cose/*.hpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/jose/*.hpp
)

file (GLOB FILEGROUP_SDK_SOURCE_CRYPTO
    ${PROJECT_SOURCE_DIR}/sdk/crypto/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/advisor/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/crypt/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/digest/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/kdf/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/key/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/keyexchange/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/mac/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/prng/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/sdk/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/basic/sign/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/authenticode/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/cose/*.cpp
    ${PROJECT_SOURCE_DIR}/sdk/crypto/jose/*.cpp
)

file (GLOB FILEGROUP_SDK_SOURCE_CRYPTO_LINUX
)

file (GLOB FILEGROUP_SDK_SOURCE_CRYPTO_WIN32
)

if (UNIX)
set (FILEGROUP_SDK_CRYPTO ${FILEGROUP_SDK_HEADER_CRYPTO} ${FILEGROUP_SDK_SOURCE_CRYPTO} ${FILEGROUP_SDK_SOURCE_CRYPTO_LINUX})
set (PLATFORM_LIB_SDK_CRYPTO crypto ssl jansson)
elseif (WIN32)
set (FILEGROUP_SDK_CRYPTO ${FILEGROUP_SDK_HEADER_CRYPTO} ${FILEGROUP_SDK_SOURCE_CRYPTO} ${FILEGROUP_SDK_SOURCE_CRYPTO_WIN32})
set (PLATFORM_LIB_SDK_CRYPTO crypto ssl jansson)
endif ()

if (SUPPORT_STATIC GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_CRYPTO_STATIC ${PROJECT_SDK_MODULE_BASE}-static ${PROJECT_SDK_MODULE_IO}-static)
    makelibdep(${PROJECT_SDK_MODULE_CRYPTO} STATIC FILEGROUP_SDK_CRYPTO FILEGROUP_SDK_HEADER_CRYPTO PROJECT_SDK_MODULE_DEPENDENCIES_CRYPTO_STATIC PLATFORM_LIB_SDK_CRYPTO)
endif ()

if (SUPPORT_SHARED GREATER 0)
    set (PROJECT_SDK_MODULE_DEPENDENCIES_CRYPTO_SHARED ${PROJECT_SDK_MODULE_BASE}-shared ${PROJECT_SDK_MODULE_IO}-shared)
    makelibdep(${PROJECT_SDK_MODULE_CRYPTO} SHARED FILEGROUP_SDK_CRYPTO FILEGROUP_SDK_HEADER_CRYPTO PROJECT_SDK_MODULE_DEPENDENCIES_CRYPTO_SHARED PLATFORM_LIB_SDK_CRYPTO)
endif ()
