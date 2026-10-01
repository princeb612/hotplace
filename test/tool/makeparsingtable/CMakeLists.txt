# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module makeparsingtable)
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp ${PROJECT_SOURCE_DIR}/*.hpp)

maketool (${module} SOURCE_FILES HEADER_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 0)

# MINGW64 - development environment
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
if (WIN32)
add_custom_command(
  TARGET makeparsingtable
  POST_BUILD
  COMMAND makeparsingtable ARGS -o asn1notation.ptb
  COMMAND makeparsingtable ARGS -o asn1.ptb -glr
  COMMAND zip ARGS parsingtable.zip asn1notation.ptb asn1.ptb
)
endif ()
endif ()
