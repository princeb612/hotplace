/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_change_cipher_spec.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_record_change_cipher_spec::tls_record_change_cipher_spec(tls_session* session) : tls_record(tls_content_type_t::change_cipher_spec, session) {}

tls_record_change_cipher_spec::~tls_record_change_cipher_spec() {}

static return_t validate_change_cipher_spec_phase(tls_session* session, tls_direction_t dir, bool outbound) {
    if ((nullptr == session) || (session_type_t::tls != session->get_type())) {
        return errorcode_t::success;
    }

    auto& protection = session->get_tls_protection();
    auto negotiated_version = (tls_version_t)session->get_keyvalue().get(session_tls_version);
    bool tls13 = protection.is_kindof_tls13() || (tls_13 == negotiated_version) || (dtls_13 == negotiated_version);
    if ((false == tls13) && (tls_version_t{} == negotiated_version)) {
        auto& context = protection.get_protection_context();
        context.for_each_supported_versions([&tls13](tls_version_t version, bool* stop) -> void {
            if ((tls_13 == version) || (dtls_13 == version)) {
                tls13 = true;
                *stop = true;
            }
        });
    }
    if (false == tls13) {
        // In the initial TLS 1.2 handshake, CCS switches this direction to the
        // negotiated protection state. A second plaintext CCS must not repeat
        // that transition. TLS 1.2 renegotiation is not supported by this path.
        if (session->get_session_info(dir).apply_protection()) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            return errorcode_t::unexpected;
        }

        // Match the TLS 1.2 Finished prerequisites: the client may switch
        // after ServerKeyExchange and ClientKeyExchange; the server switches
        // only after the client's Finished. Each endpoint must send CCS
        // before its own Finished.
        uint32 status = session->get_session_status();
        uint32 prerequisite = session_status_server_key_exchange | session_status_client_key_exchange;
        bool sender_is_client = (from_client == dir);
        if (false == sender_is_client) {
            prerequisite |= session_status_client_finished;
        }
        uint32 sender_finished = sender_is_client ? session_status_client_finished : session_status_server_finished;
        if ((prerequisite != (prerequisite & status)) || (0 != (status & sender_finished))) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            return errorcode_t::unexpected;
        }
        return errorcode_t::success;
    }

    // For inbound records, dir identifies the peer that sent Finished.
    // For outbound records, the peer is the opposite direction.
    bool peer_is_client = outbound ? (from_server == dir) : (from_client == dir);
    uint32 peer_finished = peer_is_client ? session_status_client_finished : session_status_server_finished;
    uint32 status = session->get_session_status();
    bool client_hello_seen = (0 != (status & (session_status_client_hello | session_status_hello_retry_request | session_status_server_hello)));
    if ((false == client_hello_seen) || (status & peer_finished)) {
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
        return errorcode_t::unexpected;
    }
    return errorcode_t::success;
}

return_t tls_record_change_cipher_spec::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    if (session) {
        auto& protection = session->get_tls_protection();
        auto negotiated_version = (tls_version_t)session->get_keyvalue().get(session_tls_version);
        bool negotiated = (tls_version_t{} != negotiated_version);
        bool tls13 = protection.is_kindof_tls13() || (tls_13 == negotiated_version) || (dtls_13 == negotiated_version);
        if ((false == negotiated) && (false == tls13)) {
            // Before ServerHello, a TLS 1.3 offer may be followed by a
            // compatibility CCS. Do not infer the negotiated version from the
            // ClientHello offer once ServerHello has selected a version.
            auto& context = protection.get_protection_context();
            context.for_each_supported_versions([&tls13](tls_version_t version, bool* stop) -> void {
                if ((tls_13 == version) || (dtls_13 == version)) {
                    tls13 = true;
                    *stop = true;
                }
            });
        }
        if (tls13) {
            // TLS 1.3 ChangeCipherSpec is compatibility-only and MUST NOT
            // change the record-protection state or sequence number.
            return ret;
        }
        session->get_session_info(dir).begin_protection();
        // TLS 1.2 starts a new record sequence at the CCS transition.
        // Keep the generic reset_recordno() version-gated for its other callers.
        session->get_session_info(dir).reset_recordno();
#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record,
                              [&](basic_stream& dbs) -> void { dbs.println("> change_cipher_spec %s", tlsadvisor->nameof_direction(dir).c_str()); });
        }
#endif
    }
    return ret;
}

return_t tls_record_change_cipher_spec::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 9846 Section 5 / RFC 5246 Section 7.1:
        // ChangeCipherSpec is exactly one byte with the value change_cipher_spec(1).
        if ((nullptr == stream) || (1 != get_body_size()) || (size <= pos) || (1 != stream[pos])) {
            auto session = get_session();
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            }
            ret = errorcode_t::unexpected;
            __leave2;
        }

        ret = validate_change_cipher_spec_phase(get_session(), dir, false);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record_change_cipher_spec::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = validate_change_cipher_spec_phase(get_session(), dir, true);
    if (errorcode_t::success == ret) {
        binary_append(bin, uint8(1));
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
