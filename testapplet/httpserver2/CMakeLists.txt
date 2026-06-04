# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module httpserver2)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/testcase/*.hpp)

file (GLOB DATA_FILES *.html)
file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/${module}/)

maketest (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 0)
