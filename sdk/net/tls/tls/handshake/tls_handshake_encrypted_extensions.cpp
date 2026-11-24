/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_encrypted_extensions.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

static void rollback_encrypted_extensions_early_data(tls_session* session, tls_flow_t original_flow) {
    if (nullptr == session) {
        return;
    }

    auto& protection = session->get_tls_protection();
    session->reset_session_status();

    // A failed EncryptedExtensions message terminates the handshake. Retire
    // provisional PSK/binder and 0-RTT secrets, but preserve handshake traffic
    // secrets so a fatal alert can still use the installed handshake keys.
    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::resumption_early, binary_t());
    secrets.erase(tls_secret_t::resumption_binder_hash);
    secrets.erase(tls_secret_t::resumption_binder_key);
    secrets.erase(tls_secret_t::resumption_finished_key);
    secrets.erase(tls_secret_t::resumption_finished);
    secrets.assign(tls_secret_t::c_e_traffic, binary_t());
    secrets.assign(tls_secret_t::e_exp_master, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t());

    auto& session_kv = session->get_keyvalue();
    session_kv.set(session_server_psk_selected_identity, 0xffff);
    session_kv.set(session_server_psk_key_exchange_mode, 0xffff);
    session_kv.set(session_server_psk_ticket_cipher_suite, 0);
    session->set_offered_resumption_tickets(std::vector<tls_resumption_ticket>());
    session->clear_early_data_ticket();
    auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
    early_data_state.set(session_early_data_offered, 0);
    early_data_state.set(session_early_data_offered_initial, 0);
    early_data_state.set(session_early_data_limit, 0);
    early_data_state.set(session_early_data_accepted, 0);
    auto& client_info = session->get_session_info(from_client);
    if (tls_flow_t::zero_rtt == original_flow) {
        // A final ServerHello derives the client handshake traffic secret.
        // Malformed/out-of-order EncryptedExtensions can arrive before that
        // point, so zero_rtt alone does not prove that handshake keys exist.
        const auto& client_handshake_secret = protection.get_secrets().get(tls_secret_t::c_hs_traffic);
        protection.set_flow(tls_flow_t::one_rtt);
        if (false == client_handshake_secret.empty()) {
            // The final ServerHello installed handshake keys; use them for
            // the fatal alert instead of retaining the obsolete 0-RTT key.
            client_info.begin_protection();
            session->reset_recordno(from_client);
        } else {
            // No handshake key exists yet (for example, invalid EE after
            // ClientHello/HRR only). Disable the early-data protection.
            client_info.reset_protection();
        }
    } else if (tls_flow_t::hello_retry_request == original_flow) {
        // EncryptedExtensions before a final ServerHello is out of order;
        // HRR has not installed handshake traffic keys, so keep this path
        // unprotected while terminating the handshake.
        protection.set_flow(tls_flow_t::one_rtt);
        client_info.reset_protection();
    }
}

tls_handshake_encrypted_extensions::tls_handshake_encrypted_extensions(tls_session* session) : tls_handshake(tls_handshake_type_t::encrypted_extensions, session) {}

tls_handshake_encrypted_extensions::~tls_handshake_encrypted_extensions() {}

return_t tls_handshake_encrypted_extensions::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        original_flow = protection.get_flow();

        // RFC 8446 4.2.11: if the server accepts early data in EncryptedExtensions,
        // it MUST have selected the first PSK identity offered by the client.
        const bool early_data_accepted_in_message = (nullptr != get_extensions().get(tls_extension_type_t::early_data));
        if ((from_server == dir) && (tls_io_operation_t::read == opdir) && (true == early_data_accepted_in_message)) {
            // A received EncryptedExtensions early_data indication is an
            // acceptance signal. Validate the selected identity and every
            // parameter associated with the first PSK identity.
            uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
            const auto& early_state = session->get_session_info(from_server).get_keyvalue();
            bool early_data_offered = (0 != early_state.get(session_early_data_offered));
            tls_resumption_ticket early_ticket = session->get_early_data_ticket();
            auto alpn_extension = static_cast<tls_extension_alpn*>(get_extensions().get(tls_extension_type_t::application_layer_protocol_negotiation));
            binary_t negotiated_alpn = (nullptr != alpn_extension) ? alpn_extension->get_protocols() : binary_t();
            const uint32 early_data_limit = session->get_session_info(from_server).get_keyvalue().get(session_early_data_limit);
            const bool early_flow_match = (tls_flow_t::zero_rtt == protection.get_flow());
            const bool ticket_identity_present = (false == early_ticket.identity.empty());
            const bool ticket_version_match = (early_ticket.version == static_cast<uint16>(protection.get_tls_version()));
            const bool ticket_cipher_suite_match = (early_ticket.cipher_suite == protection.get_cipher_suite());
            const bool ticket_alpn_match = (early_ticket.alpn == negotiated_alpn);
            const bool early_data_limit_valid = (0 != early_data_limit) && (early_data_limit <= early_ticket.max_early_data_size);
            bool ticket_parameters_match =
                early_flow_match && ticket_identity_present && ticket_version_match && ticket_cipher_suite_match && ticket_alpn_match && early_data_limit_valid;
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                    dbs.println(" > EncryptedExtensions early_data validation");
                    dbs.println("   flow %u (zero_rtt=%u), offered %u, selected_identity %u", static_cast<uint32>(protection.get_flow()),
                                static_cast<uint32>(tls_flow_t::zero_rtt), early_data_offered ? 1 : 0, selected_identity);
                    dbs.println("   ticket identity present %u, version 0x%04x/0x%04x match %u", ticket_identity_present ? 1 : 0, early_ticket.version,
                                static_cast<uint16>(protection.get_tls_version()), ticket_version_match ? 1 : 0);
                    dbs.println("   cipher suite 0x%04x/0x%04x match %u", early_ticket.cipher_suite, protection.get_cipher_suite(), ticket_cipher_suite_match ? 1 : 0);
                    dbs.println("   ALPN size %zu/%zu match %u", early_ticket.alpn.size(), negotiated_alpn.size(), ticket_alpn_match ? 1 : 0);
                    dbs.println("   early data limit %u, ticket max %u, valid %u", early_data_limit, early_ticket.max_early_data_size, early_data_limit_valid ? 1 : 0);
                    dbs.println("   ticket parameters match %u", ticket_parameters_match ? 1 : 0);
                });
            }
            if ((false == early_data_offered) || (0 != selected_identity) || (false == ticket_parameters_match)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
            session->get_session_info(from_server).get_keyvalue().set(session_early_data_accepted, 1);
        } else if ((from_server == dir) && (tls_io_operation_t::read == opdir) && (false == early_data_accepted_in_message) &&
                   (tls_flow_t::zero_rtt == protection.get_flow())) {
            // The server declined 0-RTT. Switch the client direction to
            // handshake traffic keys and reset its per-key record sequence.
            protection.set_flow(tls_flow_t::one_rtt);
            session->get_session_info(from_client).begin_protection();
            session->reset_recordno(from_client);
        } else if ((from_server == dir) && (tls_io_operation_t::write == opdir) && (tls_flow_t::zero_rtt == protection.get_flow())) {
            auto& early_state = session->get_session_info(from_server).get_keyvalue();
            // The server's EncryptedExtensions is the acceptance signal. The
            // decision is recorded only after the eligible extension is written.
            if ((false == early_data_accepted_in_message) || (0 == early_state.get(session_early_data_accepted))) {
                early_state.set(session_early_data_accepted, 0);
                protection.set_flow(tls_flow_t::one_rtt);
                session->get_session_info(from_client).begin_protection();
                session->reset_recordno(from_client);
            }
        }

        protection.update_transcript_hash(session, stream + hspos, get_size());

        session->update_session_status(session_status_encrypted_extensions);
        if ((session_type_t::tls == session->get_type()) && (from_server == dir) && (tls_io_operation_t::write == opdir) &&
            (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_offered))) {
            // Resume records that arrived in flight with ClientHello only after
            // the EncryptedExtensions writer has committed to accept or reject 0-RTT.
            ret = session->get_secure_prosumer()->resume_pending_records(session, from_client);
        }
    }
    __finally2 {
        if ((from_server == dir) && (errorcode_t::success != ret)) {
            // Invalid EncryptedExtensions cannot leave 0-RTT active after
            // the peer has rejected the server's early-data decision.
            rollback_encrypted_extensions_early_data(get_session(), original_flow);
        }
    }
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    __try2 {
        auto session = get_session();
        original_flow = session->get_tls_protection().get_flow();
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            // RFC 8446 4.3.1: the extension vector must fit exactly
            // within this handshake message body.
            // auto& protection = session->get_tls_protection();
            const size_t body_end = offsetof_body() + get_body_size();
            if ((body_end > size) || (pos > body_end) || (body_end - pos < sizeof(uint16))) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            uint16 len = ntoh16(*(uint16*)(stream + pos));
            pos += sizeof(uint16);
            if (len != body_end - pos) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            ret = get_extensions().read(this, dir, stream, body_end, pos);
            if (errorcode_t::no_more == ret) {
                // The EncryptedExtensions body is complete. A short trailing
                // extension header is malformed wire input, not fragmentation.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
            if (pos != body_end) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            session->clear_scheduled_extensions();  // release ALPN
        }
    }
    __finally2 {
        if ((from_server == dir) && (errorcode_t::success != ret) && (errorcode_t::no_more != ret)) {
            rollback_encrypted_extensions_early_data(get_session(), original_flow);
        }
    }
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    binary_t extensions;
    session->select_into_scheduled_extension(&get_extensions());

    ret = get_extensions().write(dir, extensions);
    if (errorcode_t::success == ret) {
        binary_append(bin, uint16(extensions.size()), hton16);
        binary_append(bin, extensions);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
