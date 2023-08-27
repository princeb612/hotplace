# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

set (module tlsserver)
file (GLOB SOURCE_FILES *.cpp)

file (GLOB DATA_FILES *.crt *.key)
file (COPY ${DATA_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/${module}/)

maketest (${module} SOURCE_FILES PROJECT_SDK_MODULE_DEPENDENCIES PROJECT_SDK_PLATFORM_DEPENDENCIES 0)
