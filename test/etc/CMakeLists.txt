# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module_start start)
file (GLOB SOURCE_FILES_START start*.cpp)
maketest (${module_start} SOURCE_FILES_START PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

set (module_varstring varstring)
file (GLOB SOURCE_FILES_VARSTRING var*.cpp)
maketest (${module_varstring} SOURCE_FILES_VARSTRING PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
