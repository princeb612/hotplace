/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_session_ticket.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   RFC 5077 SessionTicket extension for TLS 1.2.
 */

#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_session_ticket.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_extension_session_ticket::tls_extension_session_ticket(tls_handshake* handshake) : tls_extension(tls_extension_type_t::session_ticket, handshake) {}

tls_extension_session_ticket::~tls_extension_session_ticket() {}

const binary_t& tls_extension_session_ticket::get_ticket() const { return _ticket; }

void tls_extension_session_ticket::set_ticket(const binary_t& ticket) { _ticket = ticket; }

return_t tls_extension_session_ticket::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto handshake = get_handshake();
        auto session = handshake ? handshake->get_session() : nullptr;
        bool client_hello = (nullptr != handshake) && (tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir);
        bool server_hello = (nullptr != handshake) && (tls_handshake_type_t::server_hello == handshake->get_type()) && (from_server == dir);
        if ((false == client_hello) && (false == server_hello)) {
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
            }
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

        const size_t body_end = endpos_extension();
        if ((nullptr == stream) || (pos > body_end) || (body_end > size)) {
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
            }
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

        _ticket.clear();
        if (client_hello) {
            // RFC 5077 §3.2: an empty ClientHello extension requests a ticket;
            // a non-empty body carries the opaque ticket to be resumed.
            _ticket.assign(stream + pos, stream + body_end);
            pos = body_end;
        } else if (pos != body_end) {
            // The ServerHello form is an empty acknowledgement.
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
            }
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_session_ticket::do_write_body(tls_direction_t dir, binary_t& bin) {
    auto handshake = get_handshake();
    bool client_hello = (nullptr != handshake) && (tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir);
    bool server_hello = (nullptr != handshake) && (tls_handshake_type_t::server_hello == handshake->get_type()) && (from_server == dir);

    if (client_hello) {
        // An empty ticket is the RFC 5077 request for a new ticket.
        bin.insert(bin.end(), _ticket.begin(), _ticket.end());
        return errorcode_t::success;
    }
    if (server_hello && _ticket.empty()) {
        // ServerHello acknowledges ticket issuance with an empty extension.
        return errorcode_t::success;
    }
    return errorcode_t::invalid_parameter;
}

}  // namespace net
}  // namespace hotplace
