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

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
