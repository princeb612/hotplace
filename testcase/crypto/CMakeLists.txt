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
file (GLOB DATA_FILES
    *.yml
    advisor/*.yml
    crypt/*.yml
    hash/*.yml
    kdf/*.yml
    key/*.yml
    pqc/*.yml
    prng/*.yml
    sign/*.yml
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
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCE_FILES} ${DATA_FILES})
endif ()

file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testcase/${module}/)

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
