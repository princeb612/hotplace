# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module base)
file (GLOB SOURCE_FILES
    *.cpp
    basic/*.cpp
    graph/*.cpp
    nostd/*.cpp
    pattern/*.cpp
    stream/*.cpp
    string/*.cpp
    system/*.cpp
    unittest/*.cpp
)
file (GLOB DATA_FILES
    *.yml
    basic/*.yml
    graph/*.yml
    nostd/*.yml
    pattern/*.yml
    stream/*.yml
    string/*.yml
    system/*.yml
    unittest/*.yml
)

if(NOT ${CMAKE_VERSION} VERSION_LESS "3.8.0")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${SOURCE_FILES} ${DATA_FILES})
endif ()

file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testcase/${module}/)

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
