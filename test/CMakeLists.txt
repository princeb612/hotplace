# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

# base
add_subdirectory (base)

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
add_subdirectory (jose)
add_subdirectory (authenticode)

# net
add_subdirectory (ipaddr)
add_subdirectory (tcpserver1)
add_subdirectory (tcpserver2)
add_subdirectory (tlsserver)
add_subdirectory (httpserver)

# etc
add_subdirectory (incubator)

# platform
if (UNIX)
add_subdirectory (linux)
endif ()
if (WIN32)
add_subdirectory (windows)
endif ()
