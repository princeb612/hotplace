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
add_subdirectory (key)
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
add_subdirectory (httpserver1)
add_subdirectory (httpauth)
add_subdirectory (httptest)
add_subdirectory (hpack)
add_subdirectory (httpserver2)
add_subdirectory (udpserver1)
add_subdirectory (udpserver2)
add_subdirectory (dtlsserver)
add_subdirectory (netclient)
add_subdirectory (qpack)
add_subdirectory (httpaltsvc)
add_subdirectory (tls)
add_subdirectory (quic)
add_subdirectory (httpserver3)

# odbc
if (SUPPORT_ODBC)
add_subdirectory (odbc)
endif ()

# oqs, pqc
if (SUPPORT_PQC)
add_subdirectory (pqc)
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

file (GLOB TRUSTCERT_FILES cert/trust/trust.crt)
file (COPY ${TRUSTCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/authenticode/)
file (GLOB SERVERCERT_FILES cert/server.crt cert/server.key)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/dtlsserver/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpaltsvc/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpauth/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver1/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver2/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/tls/)
file (GLOB ECDSACERT_FILES cert/ecdsa.crt cert/ecdsa.key)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/dtlsserver/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver1/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver2/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver3/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/quic/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/tls/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/tlsserver/)
file (GLOB RSACERT_FILES cert/rsa.crt cert/rsa.key)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/dtlsserver/)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver1/)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/httpserver2/)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/quic/)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/tls/)
file (COPY ${RSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/build/test/tlsserver/)
