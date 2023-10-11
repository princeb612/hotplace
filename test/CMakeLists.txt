# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# base
add_subdirectory (base)
add_subdirectory (cmdline)

# io
add_subdirectory (unittest)
add_subdirectory (encode)
add_subdirectory (string)
add_subdirectory (stream)
add_subdirectory (bufferio)
add_subdirectory (datetime)
add_subdirectory (thread)
add_subdirectory (mlfq)
add_subdirectory (cbor)

# crypto
add_subdirectory (crypto)
add_subdirectory (kdf)
add_subdirectory (hash)
add_subdirectory (ecdsa)
add_subdirectory (jose)
add_subdirectory (cose)
add_subdirectory (authenticode)

# net
add_subdirectory (ipaddr)
add_subdirectory (tcpserver1)
add_subdirectory (tcpserver2)
add_subdirectory (tlsserver)
add_subdirectory (httpserver)

# odbc
if (SUPPORT_ODBC)
add_subdirectory (odbc)
endif ()

# etc
add_subdirectory (varstring)

# platform
if (UNIX)
add_subdirectory (linux)
endif ()
if (WIN32)
add_subdirectory (windows)
endif ()
