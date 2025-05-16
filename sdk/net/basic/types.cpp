/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/types.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

socket_context_t::socket_context_t() : fd(INVALID_SOCKET), flags(0) { handle.ssl = nullptr; }

socket_context_t::socket_context_t(socket_t s, uint32 f) : fd(s), flags(f) {
    handle.ssl = nullptr;
    if ((INVALID_SOCKET != s) && (closesocket_if_tcp & flags)) {
        int optval = 0;
        socklen_t optlen = sizeof(optval);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&optval, &optlen);

        if (SOCK_STREAM == optval) {
            flags |= closesocket_ondestroy;
        }
    }
}

socket_context_t::~socket_context_t() {
    if (tls_using_openssl & flags) {
        auto ssl = handle.ssl;
        if (ssl) {
            int rc = SSL_shutdown(ssl);
            if (2 == rc) {
                // received close notify - SSL_RECEIVED_SHUTDOWN & SSL_get_shutdown(ssl)
                // send close notify
                SSL_shutdown(ssl);
            }

            SSL_free(ssl);
        }
    } else {
        auto session = handle.session;
        if (session) {
            session->release();
        }
    }

    if (closesocket_ondestroy & flags) {
        close_socket(fd, true, 0);
    }
}

}  // namespace net
}  // namespace hotplace
