# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module makeparsingtable)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/*.hpp)

maketool (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 0)
