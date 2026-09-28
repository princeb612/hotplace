# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

execute_process(
    COMMAND unzip -f parsingtable.zip -d ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/io
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

execute_process(
    COMMAND unzip -f parsingtable.zip -d ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/asn.1
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
