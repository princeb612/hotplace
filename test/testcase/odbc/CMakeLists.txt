# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module odbc)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/*.hpp)

if (WIN32)
    set (SOURCE_FILES ${SOURCE_FILES} ${PROJECT_BINARY_DIR}/test/testcase/${module}/resource.rc)
endif ()
maketest (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
