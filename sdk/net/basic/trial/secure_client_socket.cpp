/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

secure_client_socket::secure_client_socket(tls_version_t spec) : client_socket_prosumer(), _spec(spec) {}

secure_client_socket::~secure_client_socket() {}

return_t secure_client_socket::do_handshake() {
    return_t ret = errorcode_t::success;

    __try2 {
        tls_composer composer(get_session());
        composer.set_minver(_spec);
        composer.set_maxver(_spec);

        auto lambda = [&](tls_session*, binary_t& bin) -> void { do_send(bin); };
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

return_t secure_client_socket::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        binary_t bin;

        auto dir = from_client;
        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_alert).set(dir).construct().build();
        if (record) {
            *record << new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify);
            record->write(dir, bin);
            record->release();
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        do_send(bin);

        session->wait_change_session_status(session_status_server_close_notified, get_wto());
        auto session_status = session->get_session_status();
    }
    __finally2 {}
    return ret;
}

/* override */
return_t secure_client_socket::do_send(binary_t& bin) { return errorcode_t::success; }

tls_session* secure_client_socket::get_session() { return &_session; }

tls_version_t secure_client_socket::get_version() { return _spec; }

bool secure_client_socket::support_tls() { return true; }

secure_prosumer* secure_client_socket::get_secure_prosumer() { return &_secure; }

}  // namespace net
}  // namespace hotplace
