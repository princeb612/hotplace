# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# base
add_subdirectory (base)
add_subdirectory (bufferio)
add_subdirectory (cmdline)
add_subdirectory (datetime)
add_subdirectory (encode)
add_subdirectory (ieee754)
add_subdirectory (graph)
add_subdirectory (nostd)
add_subdirectory (pattern)
add_subdirectory (thread)
add_subdirectory (unittest)

# io
add_subdirectory (cbor)
add_subdirectory (payload)
add_subdirectory (mlfq)
add_subdirectory (stream)
add_subdirectory (string)
add_subdirectory (asn1)
add_subdirectory (parser)
add_subdirectory (sysmon)

# crypto
add_subdirectory (random)
add_subdirectory (crypto)
add_subdirectory (kdf)
add_subdirectory (hash)
add_subdirectory (sign)
add_subdirectory (jose)
add_subdirectory (cose)
add_subdirectory (authenticode)

# net
add_subdirectory (ipaddr)
add_subdirectory (tcpserver1)
add_subdirectory (tcpserver2)
add_subdirectory (tlsserver)
add_subdirectory (httpserver)
add_subdirectory (httpauth)
add_subdirectory (httptest)
add_subdirectory (hpack)
add_subdirectory (httpserver2)
add_subdirectory (udpserver)
add_subdirectory (udpserver2)
add_subdirectory (dtlsserver)

# odbc
if (SUPPORT_ODBC)
add_subdirectory (odbc)
endif ()

# etc
add_subdirectory (etc)

# platform
if (UNIX)
add_subdirectory (linux)
endif ()
if (WIN32)
add_subdirectory (windows)
endif ()
