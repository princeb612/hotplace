# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# copy test.sh to xxx/build/test/testcase/
file (COPY test.sh DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/)
file (GLOB ASN1_FILES etc/asn.1/*.asn1)
file (COPY ${ASN1_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/asn.1/)
file (COPY ${ASN1_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/io/)

# base
add_subdirectory (base)
add_subdirectory (encode)

# io
add_subdirectory (io)
add_subdirectory (cbor)
add_subdirectory (asn.1)

# crypto
add_subdirectory (crypto)
add_subdirectory (jose)
add_subdirectory (cose)

# net
add_subdirectory (net)
add_subdirectory (tls)
add_subdirectory (quic)

# odbc
if (SUPPORT_ODBC)
add_subdirectory (odbc)
endif ()

# platform-specific testcases
if (UNIX)
add_subdirectory (linux)
endif ()
if (WIN32)
add_subdirectory (windows)
endif ()
