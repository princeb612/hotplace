/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/basic/trial/trial_quic_server_socket.hpp>
#include <hotplace/sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

trial_quic_server_socket::trial_quic_server_socket() : naive_udp_server_socket() {}

trial_quic_server_socket::~trial_quic_server_socket() {}

return_t trial_quic_server_socket::dtls_open(socket_context_t** handle, socket_t fd) {
    return_t ret = errorcode_t::success;
    __try2 {
        // TODO
    }
    __finally2 {}
    return ret;
}

return_t trial_quic_server_socket::dtls_handshake(netsession_t* sess) {
    return_t ret = errorcode_t::success;

    __try2 {
        // TODO
    }
    __finally2 {}
    return ret;
}

return_t trial_quic_server_socket::recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                            socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        // TODO
    }
    __finally2 {}
    return ret;
}

return_t trial_quic_server_socket::sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                                          socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        // TODO
    }
    __finally2 {}
    return ret;
}

bool trial_quic_server_socket::support_tls() { return true; }

uint32 trial_quic_server_socket::get_scheme() { return socket_scheme_quic | socket_scheme_trial | socket_scheme_server; }

}  // namespace net
}  // namespace hotplace
