/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_early_data.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_early_data.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

const char constexpr_max_early_data_size[] = "max early data size";
const char constexpr_new_session_ticket[] = "new session ticket";

tls_extension_early_data::tls_extension_early_data(tls_handshake* handshake) : tls_extension(tls_extension_type_t::early_data, handshake) {}

tls_extension_early_data::~tls_extension_early_data() {}

uint32 tls_extension_early_data::get_max_early_data_size() const { return _max_early_data_size; }

return_t tls_extension_early_data::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.10.  Early Data Indication
        // struct {
        //     select (Handshake.msg_type) {
        //         case new_session_ticket:   uint32 max_early_data_size;
        //         case client_hello:         Empty;
        //         case encrypted_extensions: Empty;
        //     };
        // } EarlyDataIndication;

        auto handshake = get_handshake();
        auto session = handshake->get_session();
        auto& protection = session->get_tls_protection();

        // RFC 9846 §4.3.10 (RFC 8446 §4.2.10): early_data is defined
        // only for ClientHello, EncryptedExtensions, and NewSessionTicket.
        bool valid_context = ((tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir)) ||
                             ((tls_handshake_type_t::encrypted_extensions == handshake->get_type()) && (from_server == dir)) ||
                             ((tls_handshake_type_t::new_session_ticket == handshake->get_type()) && (from_server == dir));
        if (false == valid_context) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        // RFC 8446 §4.2.10: a client MUST NOT send early_data in
        // ClientHello2. A server that receives it after HRR MUST abort with
        // illegal_parameter; silently ignoring it would accept a malformed
        // second ClientHello.
        if ((tls_flow_t::hello_retry_request == protection.get_flow()) && (from_client == dir) && (tls_handshake_type_t::client_hello == get_handshake()->get_type())) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        if ((from_client == dir) && (tls_handshake_type_t::client_hello == get_handshake()->get_type())) {
            // Set this while parsing ClientHello, before the final PSK
            // extension is processed and decides whether identity zero is
            // eligible for early data.
            auto& early_state = session->get_session_info(from_server).get_keyvalue();
            early_state.set(session_early_data_offered, 1);
            early_state.set(session_early_data_offered_initial, 1);
            // Initialize the independent ciphertext-discard budget here as
            // well as in the PSK parser: a malformed offer may omit PSK.
            early_state.set(session_early_data_discard_limit, session->get_early_data_discard_limit());
            early_state.set(session_early_data_discarded, 0);
            early_state.set(session_early_data_discarded_records, 0);
        }

        {
            auto is_nst = (tls_handshake_type_t::new_session_ticket == get_handshake()->get_type());
            if (false == is_nst) {
                // ClientHello and EncryptedExtensions carry an empty body.
                // Do not call payload::read() for an empty structure: its
                // no_data result is a trivial diagnostic, not a parse failure.
                if (pos != endpos_extension()) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }
            } else {
#if defined DEBUG
                uint32 max_early_data_size = 0;
#endif
                payload pl;
                pl << new payload_member(uint32(0), true, constexpr_max_early_data_size, constexpr_new_session_ticket);
                pl.set_group(constexpr_new_session_ticket, true);

                ret = pl.read(stream, size, pos);
                if (errorcode_t::success != ret) {
                    // NewSessionTicket requires exactly one uint32 value.
                    // A missing or truncated value is malformed wire data.
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }
                if (pos != endpos_extension()) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                _max_early_data_size = pl.t_value_of<uint32>(constexpr_max_early_data_size);
#if defined DEBUG
                max_early_data_size = _max_early_data_size;
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                        dbs.println("  > %s 0x%04x(%i)", constexpr_max_early_data_size, max_early_data_size, max_early_data_size);
                    });
                }
#endif
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_early_data::do_write_body(tls_direction_t dir, binary_t& bin) {
    auto handshake = get_handshake();
    if (nullptr == handshake) {
        return errorcode_t::invalid_parameter;
    }
    bool valid_client_hello = ((tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir));
    bool valid_context = valid_client_hello || ((tls_handshake_type_t::encrypted_extensions == handshake->get_type()) && (from_server == dir)) ||
                         ((tls_handshake_type_t::new_session_ticket == handshake->get_type()) && (from_server == dir));
    if (false == valid_context) {
        return errorcode_t::invalid_parameter;
    }

    // RFC 8446 §4.2.10: a client MUST NOT include early_data in ClientHello2.
    // Reject the local write instead of emitting a protocol-invalid extension.
    auto session = handshake->get_session();
    if (valid_client_hello) {
        if ((nullptr == session) || (tls_flow_t::hello_retry_request == session->get_tls_protection().get_flow())) {
            return errorcode_t::invalid_parameter;
        }
        const auto& early_state = session->get_session_info(from_server).get_keyvalue();
        if ((tls_flow_t::zero_rtt != session->get_tls_protection().get_flow()) || (0 == early_state.get(session_early_data_limit)) ||
            (nullptr == handshake->get_extensions().get(tls_extension_type_t::pre_shared_key))) {
            return errorcode_t::invalid_parameter;
        }
    }

    // Keep the server's direct extension writer subject to the same acceptance
    // policy as tls_extensions::write(). Otherwise callers could bypass the
    // container filter and emit an unsolicited or ineligible EncryptedExtensions
    // early_data indication.
    if ((tls_handshake_type_t::encrypted_extensions == handshake->get_type()) && (from_server == dir)) {
        if (nullptr == session) {
            return errorcode_t::invalid_parameter;
        }
        auto& protection = session->get_tls_protection();
        auto& early_state = session->get_session_info(from_server).get_keyvalue();
        uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
        uint16 ticket_cipher_suite = t_narrow_cast(session->get_keyvalue().get(session_server_psk_ticket_cipher_suite));
        tls_resumption_ticket early_ticket = session->get_early_data_ticket();
        auto alpn_extension = static_cast<tls_extension_alpn*>(handshake->get_extensions().get(tls_extension_type_t::application_layer_protocol_negotiation));
        binary_t negotiated_alpn = (nullptr != alpn_extension) ? alpn_extension->get_protocols() : binary_t();
        bool ticket_parameters_match = (false == early_ticket.identity.empty()) && (early_ticket.version == static_cast<uint16>(protection.get_tls_version())) &&
                                       (early_ticket.cipher_suite == protection.get_cipher_suite()) && (early_ticket.alpn == negotiated_alpn) &&
                                       (early_state.get(session_early_data_limit) <= early_ticket.max_early_data_size);
        bool accept_early_data = (tls_flow_t::zero_rtt == protection.get_flow()) && (0 == selected_identity) && (0 != early_state.get(session_early_data_offered)) &&
                                 (0 != early_state.get(session_early_data_limit)) && (0 != ticket_cipher_suite) &&
                                 (protection.get_cipher_suite() == ticket_cipher_suite) && ticket_parameters_match;
        if (false == accept_early_data) {
            return errorcode_t::invalid_parameter;
        }
        // Keep session state coherent even when this extension is serialized
        // directly rather than through tls_extensions::write().
        early_state.set(session_early_data_accepted, 1);
    } else if (valid_client_hello) {
        // The local ClientHello offer must be remembered by the peer-side
        // acceptance validator even when callers write this extension directly.
        auto& early_state = session->get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        early_state.set(session_early_data_offered_initial, 1);
    }
    return errorcode_t::success;
}

}  // namespace net
}  // namespace hotplace
