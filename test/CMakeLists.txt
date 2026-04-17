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
add_subdirectory (authenticode)

# net
add_subdirectory (net)
add_subdirectory (tcpserver1)
add_subdirectory (tcpserver2)
add_subdirectory (tlsserver)
add_subdirectory (httpserver1)
add_subdirectory (httpserver2)
add_subdirectory (udpserver1)
add_subdirectory (udpserver2)
add_subdirectory (dtlsserver)
add_subdirectory (netclient)
add_subdirectory (tls)
add_subdirectory (quic)
add_subdirectory (httpserver3)

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

# copy certificates
add_subdirectory (etc)
