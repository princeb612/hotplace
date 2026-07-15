# @author Soo Han, Kim (princeb612.kr@gmail.com)
# @desc
# Revision History
# Date         Name                Description
#

file (GLOB TRUSTCERT_FILES trust/trust.crt)
file (COPY ${TRUSTCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/authenticode/)
file (GLOB SERVERCERT_FILES server-*.crt server-*.key)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/quic/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/tls/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/dtlsserver/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/httpserver1/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/httpserver2/)
file (COPY ${SERVERCERT_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/applet/tlsserver/)
file (GLOB DER_FILES server-*.der)
file (COPY ${DER_FILES} DESTINATION ${PROJECT_SOURCE_DIR}/${SET_BUILDDIR}/test/testcase/asn.1/)
