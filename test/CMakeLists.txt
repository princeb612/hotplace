# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# base
add_subdirectory (base)
add_subdirectory (encode)

# io
add_subdirectory (io)
add_subdirectory (cbor)
add_subdirectory (asn1)

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
