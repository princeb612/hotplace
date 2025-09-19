/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_end_of_early_data.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_new_session_ticket.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello_done.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_unknown.hpp>

namespace hotplace {
namespace net {

tls_handshake_builder::tls_handshake_builder() : _type(tls_hs_client_hello), _session(nullptr) {}

tls_handshake_builder& tls_handshake_builder::set(tls_hs_type_t type) {
    _type = type;
    return *this;
}

tls_handshake_builder& tls_handshake_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

tls_handshake* tls_handshake_builder::build() {
    tls_handshake* handshake = nullptr;
    auto hstype = get_type();
    auto session = get_session();
    switch (hstype) {
        case tls_hs_client_hello: {
            __try_new_catch_only(handshake, new tls_handshake_client_hello(session));
        } break;
        case tls_hs_server_hello: {
            __try_new_catch_only(handshake, new tls_handshake_server_hello(session));
        } break;
        case tls_hs_hello_verify_request: {
            __try_new_catch_only(handshake, new tls_handshake_hello_verify_request(session));
        } break;
        case tls_hs_new_session_ticket: {
            __try_new_catch_only(handshake, new tls_handshake_new_session_ticket(session));
        } break;
        case tls_hs_end_of_early_data: {
            __try_new_catch_only(handshake, new tls_handshake_end_of_early_data(session));
        } break;
        case tls_hs_encrypted_extensions: {
            __try_new_catch_only(handshake, new tls_handshake_encrypted_extensions(session));
        } break;
        case tls_hs_certificate: {
            __try_new_catch_only(handshake, new tls_handshake_certificate(session));
        } break;
        case tls_hs_server_key_exchange: {
            __try_new_catch_only(handshake, new tls_handshake_server_key_exchange(session));
        } break;
        case tls_hs_server_hello_done: {
            __try_new_catch_only(handshake, new tls_handshake_server_hello_done(session));
        } break;
        case tls_hs_certificate_verify: {
            __try_new_catch_only(handshake, new tls_handshake_certificate_verify(session));
        } break;
        case tls_hs_client_key_exchange: {
            __try_new_catch_only(handshake, new tls_handshake_client_key_exchange(session));
        } break;
        case tls_hs_finished: {
            __try_new_catch_only(handshake, new tls_handshake_finished(session));
        } break;
        case tls_hs_hello_request:
        case tls_hs_request_connection_id:
        case tls_hs_new_connection_id:
        case tls_hs_certificate_request:  // RFC 4346 7.4.4. Certificate request
        case tls_hs_client_certificate_request:
        case tls_hs_certificate_url:
        case tls_hs_certificate_status:
        case tls_hs_key_update:
        case tls_hs_compressed_certificate:
        default: {
            __try_new_catch_only(handshake, new tls_handshake_unknown(hstype, session));
        } break;
    }
    return handshake;
}

tls_handshake* tls_handshake_builder::build(tls_hs_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func) {
    tls_handshake* handshake = nullptr;
    auto temp = set(type).set(session).build();
    if (temp) {
        if (func) {
            auto test = func(temp);
            if (errorcode_t::success == test) {
                handshake = temp;
            } else {
                temp->release();
            }
        } else {
            handshake = temp;
        }
    }
    return handshake;
}

tls_hs_type_t tls_handshake_builder::get_type() { return _type; }

tls_session* tls_handshake_builder::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
