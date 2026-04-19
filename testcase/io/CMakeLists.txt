# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module io)
file (GLOB SOURCE_FILES
    *.cpp
    basic/*.cpp
    system/*.cpp
)

if(NOT ${CMAKE_VERSION} VERSION_LESS "3.8.0")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCE_FILES})
endif ()

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
