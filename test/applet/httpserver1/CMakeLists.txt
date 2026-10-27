# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module httpserver1)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/*.hpp)

file (GLOB DATA_FILES *.html *.css)
file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/${module}/)

if (WIN32)
    set (SOURCE_FILES ${SOURCE_FILES} ${PROJECT_BINARY_DIR}/test/applet/${module}/resource.rc)
endif ()
makeapplet (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 0)
