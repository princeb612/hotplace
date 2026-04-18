# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module crypto)
file (GLOB COMMON_SOURCE_FILES
    *.cpp
    advisor/*.cpp
    crypt/*.cpp
    hash/*.cpp
    kdf/*.cpp
    key/*.cpp
    pqc/*.cpp
    prng/*.cpp
    sign/*.cpp
)
set (SOURCE_FILES ${COMMON_SOURCE_FILES})
if (SUPPORT_OQS)
    file (GLOB SOURCE_FILES_OQS pqc/oqs/*.cpp)
    set (SOURCE_FILES ${COMMON_SOURCE_FILES} ${SOURCE_FILES_OQS})
else (1)
    file (GLOB SOURCE_FILES_DUMMY pqc/dummy/*.cpp)
    set (SOURCE_FILES ${COMMON_SOURCE_FILES} ${SOURCE_FILES_DUMMY})
endif ()

if(NOT ${CMAKE_VERSION} VERSION_LESS "3.8.0")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCE_FILES})
endif ()

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
