/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   secure_client_socket.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <utility>

namespace hotplace {
namespace net {

secure_client_socket::secure_client_socket(tls_version_t spec) : client_socket_prosumer(), _session(new tls_session()), _spec(spec) {}

secure_client_socket::secure_client_socket(tls_version_t spec, tls_session_ptr session) : client_socket_prosumer(), _session(std::move(session)), _spec(spec) {
    if (nullptr == _session) {
        throw exception(errorcode_t::no_session);
    }
}

secure_client_socket::~secure_client_socket() {}

return_t secure_client_socket::do_handshake() {
    return_t ret = errorcode_t::success;

    __try2 {
        tls_composer composer(get_session());
        composer.set_minver(_spec);
        composer.set_maxver(_spec);

        auto lambda = [this](tls_session*, binary_t& bin) -> return_t { return do_send(bin); };
        // TLS  client_hello,                                             server_hello, ...
        // DTLS client_hello, hello_verify_request, client_hello(cookie), server_hello, ...
        ret = composer.handshake(from_client, get_wto(), lambda);
    }
    __finally2 {}

    return ret;
}

return_t secure_client_socket::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    ret = get_secure_prosumer()->consume(socket_type(), get_wto(), ptr_data, size_data, cbread, addr, addrlen);

    return ret;
}

return_t secure_client_socket::do_secure() {
    return_t ret = errorcode_t::success;

    auto session = get_session();
    ret = get_secure_prosumer()->produce(session, from_server, [&](basic_stream& s, sockaddr_storage_t& addr) -> void { do_consume(s, addr); });

    // RFC 2246 7.2.2. Error alerts
    // RFC 8448 6.2.  Error Alerts

    return ret;
}

return_t secure_client_socket::do_transport_disconnect() { return _secure.notify_transport_closed(); }

return_t secure_client_socket::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        uint32 status = session->get_session_status();
        const uint32 established = session_status_client_finished | session_status_server_finished;

        // close_notify is meaningful only after the TLS handshake completed and
        // while the transport is still usable. A peer-closed transport cannot
        // complete the reciprocal close_notify exchange.
        if (is_remote_transport_closed() || (established != (status & established)) || (INVALID_SOCKET == get_socket())) {
            __leave2;
        }

        binary_t bin;

        auto dir = from_client;
        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_t::alert).set(dir).construct().build();
        if (record) {
            *record << new tls_record_alert(session, tls_alertlevel_t::warning, tls_alertdesc_t::close_notify);
            ret = record->write(dir, bin);
            record->release();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ret = do_send(bin);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = session->wait_change_session_status(session_status_server_close_notified, get_wto());
    }
    __finally2 {}
    return ret;
}

/* override */
return_t secure_client_socket::do_send(binary_t& bin) { return errorcode_t::success; }

tls_session* secure_client_socket::get_session() { return _session.get(); }

tls_version_t secure_client_socket::get_version() { return _spec; }

bool secure_client_socket::support_tls() const { return true; }

secure_prosumer* secure_client_socket::get_secure_prosumer() { return &_secure; }

}  // namespace net
}  // namespace hotplace
