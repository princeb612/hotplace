# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

#template
set (module_start start)
file (GLOB SOURCE_FILES_START start*.cpp)
maketest (${module_start} SOURCE_FILES_START PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

# c98 const char* variables
set (module_varstring varstring)
file (GLOB SOURCE_FILES_VARSTRING var*.cpp)
maketest (${module_varstring} SOURCE_FILES_VARSTRING PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

set (module_tcpclient tcpclient)
file (GLOB SOURCE_FILES_TCPCLIENT tcpclient.cpp)
maketest (${module_tcpclient} SOURCE_FILES_TCPCLIENT PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

set (module_udpclient udpclient)
file (GLOB SOURCE_FILES_UDPCLIENT udpclient.cpp)
maketest (${module_udpclient} SOURCE_FILES_UDPCLIENT PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

set (module_tlsclient tlsclient)
file (GLOB SOURCE_FILES_TLSCLIENT tlsclient.cpp)
maketest (${module_tlsclient} SOURCE_FILES_TLSCLIENT PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)

set (module_dtlsclient dtlsclient)
file (GLOB SOURCE_FILES_DTLSCLIENT dtlsclient.cpp)
maketest (${module_dtlsclient} SOURCE_FILES_DTLSCLIENT PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
