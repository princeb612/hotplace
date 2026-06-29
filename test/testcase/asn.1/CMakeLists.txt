# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module asn.1)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/*.hpp)

file (GLOB DATA_FILES *.asn1 *.yml)
file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/${module}/)

maketest (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 1)
