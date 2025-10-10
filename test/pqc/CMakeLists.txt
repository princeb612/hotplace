# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module pqc)
file (GLOB SOURCE_FILES_TEST *.cpp)
set (SOURCE_FILES ${SOURCE_FILES_TEST})
if (SUPPORT_OQS)
    file (GLOB SOURCE_FILES_OQS oqs/*.cpp)
    set (SOURCE_FILES ${SOURCE_FILES_TEST} ${SOURCE_FILES_OQS})
else (1)
    file (GLOB SOURCE_FILES_DUMMY dummy/*.cpp)
    set (SOURCE_FILES ${SOURCE_FILES_TEST} ${SOURCE_FILES_DUMMY})
endif ()

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
