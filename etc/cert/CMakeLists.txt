# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB TRUSTCERT_FILES trust/trust.crt)
file (COPY ${TRUSTCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/authenticode/)
file (GLOB ECDSACERT_FILES ecdsa.crt ecdsa.key rsa.crt rsa.key mldsa.crt mldsa.key)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testcase/quic/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testcase/tls/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/dtlsserver/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/httpserver1/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/httpserver2/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/httpserver3/)
file (COPY ${ECDSACERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/testapplet/tlsserver/)
