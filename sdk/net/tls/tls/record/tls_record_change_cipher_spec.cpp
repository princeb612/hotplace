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
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
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
    bool tls13 = protection.is_kindof_tls1_3() || (tls1_3 == negotiated_version) || (dtls1_3 == negotiated_version);
    if ((false == tls13) && (tls_version_t{} == negotiated_version)) {
        auto& context = protection.get_protection_context();
        context.for_each_supported_versions([&tls13](tls_version_t version, bool* stop) -> void {
            if ((tls1_3 == version) || (dtls1_3 == version)) {
                tls13 = true;
                *stop = true;
            }
        });
    }
    if (false == tls13) {
        // A direction normally activates TLS 1.2 protection only once.
        // During secure renegotiation, its old state remains active until this
        // direction's one permitted CCS installs the pending key block.
        auto& direction_info = session->get_session_info(dir);
        bool renegotiation = (tls_flow_t::renegotiation == protection.get_flow());
        bool renegotiation_ccs_seen = (0 != direction_info.get_keyvalue().get(session_tls12_renegotiation_ccs));
        if ((direction_info.apply_protection() && (false == renegotiation)) || (renegotiation && renegotiation_ccs_seen)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            return errorcode_t::unexpected;
        }

        // Full TLS 1.2 handshakes switch the server after Client Finished.
        // RFC 5077 abbreviated handshakes switch the server first and the
        // client only after Server Finished. Each endpoint sends CCS before
        // its own Finished.
        uint32 status = session->get_session_status();
        uint32 prerequisite = session_status_server_key_exchange | session_status_client_key_exchange;
        bool sender_is_client = (from_client == dir);
        bool abbreviated = protection.is_kindof_tls1_2() && (0 != session->get_keyvalue().get(session_tls1_2_ticket_resumed));
        if (false == sender_is_client) {
            if (false == abbreviated) {
                prerequisite |= session_status_client_finished;
            }
        } else if (abbreviated) {
            prerequisite |= session_status_server_finished;
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

static return_t activate_tls12_ccs_state(tls_session* session, tls_direction_t dir) {
    if (nullptr == session) {
        return errorcode_t::success;
    }

    auto& protection = session->get_tls_protection();
    const uint16 ciphersuite = protection.get_cipher_suite();

    // dir identifies the sender of this CCS for both inbound and outbound records.
    if (tls_flow_t::renegotiation == protection.get_flow()) {
        if (0 == ciphersuite) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
            return errorcode_t::internal_error;
        }
        const bool client = (from_client == dir);
        tls_secret_t pending_mac = client ? tls_secret_t::client_mac_key_renegotiation : tls_secret_t::server_mac_key_renegotiation;
        tls_secret_t pending_key = client ? tls_secret_t::client_key_renegotiation : tls_secret_t::server_key_renegotiation;
        tls_secret_t pending_iv = client ? tls_secret_t::client_iv_renegotiation : tls_secret_t::server_iv_renegotiation;
        tls_secret_t active_mac = client ? tls_secret_t::client_mac_key : tls_secret_t::server_mac_key;
        tls_secret_t active_key = client ? tls_secret_t::client_key : tls_secret_t::server_key;
        tls_secret_t active_iv = client ? tls_secret_t::client_iv : tls_secret_t::server_iv;

        auto& secrets = protection.get_secrets();
        const bool is_cbc = tls_advisor::get_instance()->is_kindof_cbc(ciphersuite);
        const bool complete = secrets.exist(pending_key) && secrets.exist(pending_iv) && ((false == is_cbc) || secrets.exist(pending_mac));
        if (false == complete) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
            return errorcode_t::not_found;
        }

        return_t ret = errorcode_t::success;
        if (is_cbc) {
            ret = secrets.moveto(pending_mac, active_mac);
        }
        if (errorcode_t::success == ret) {
            ret = secrets.moveto(pending_key, active_key);
        }
        if (errorcode_t::success == ret) {
            ret = secrets.moveto(pending_iv, active_iv);
        }
        if (errorcode_t::success != ret) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
            return ret;
        }
    }

    // Preserve the other direction's old suite until its own CCS arrives.
    // Some isolated initial-handshake paths do not have a selected suite yet.
    if (0 != ciphersuite) {
        session->get_session_info(dir).set_active_cipher_suite(ciphersuite);
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
        bool tls13 = protection.is_kindof_tls1_3() || (tls1_3 == negotiated_version) || (dtls1_3 == negotiated_version);
        if ((false == negotiated) && (false == tls13)) {
            // Before ServerHello, a TLS 1.3 offer may be followed by a
            // compatibility CCS. Do not infer the negotiated version from the
            // ClientHello offer once ServerHello has selected a version.
            auto& context = protection.get_protection_context();
            context.for_each_supported_versions([&tls13](tls_version_t version, bool* stop) -> void {
                if ((tls1_3 == version) || (dtls1_3 == version)) {
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
        ret = activate_tls12_ccs_state(session, dir);
        if (errorcode_t::success != ret) {
            return ret;
        }
        session->get_session_info(dir).begin_protection();
        if (tls_flow_t::renegotiation == protection.get_flow()) {
            session->get_session_info(dir).get_keyvalue().set(session_tls12_renegotiation_ccs, 1);
        }
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
        auto session = get_session();
        if ((nullptr == stream) || (nullptr == session)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (apply_protection() && session->get_session_info(dir).apply_protection()) {
            // Once a TLS 1.2 read state is active, a one-byte CCS body is
            // plaintext. A protected CCS necessarily has record-protection
            // overhead, so reject this duplicate transition as unexpected
            // before attempting decryption with the active state.
            if (1 == get_body_size()) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                ret = errorcode_t::unexpected;
                __leave2;
            }

            // RFC 5246 §7.1: CCS is protected by the current (old) read
            // state. Activate the pending renegotiation state only afterward.
            auto& protection = session->get_tls_protection();
            binary_t plaintext;
            size_t recpos = offsetof_header();
            size_t limit = recpos + get_record_size();
            ret = protection.decrypt(session, dir, stream, limit, recpos, plaintext);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
            ret = validate_record_size_limit(dir, plaintext.size());
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
            if ((1 != plaintext.size()) || (1 != plaintext[0])) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                ret = errorcode_t::unexpected;
                __leave2;
            }
        } else {
            if ((1 != get_body_size()) || (size <= pos) || (1 != stream[pos])) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                ret = errorcode_t::unexpected;
                __leave2;
            }
        }

        ret = validate_change_cipher_spec_phase(session, dir, false);
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

bool tls_record_change_cipher_spec::apply_protection() const {
    auto session = get_session();
    return (nullptr != session) && (session_type_t::tls == session->get_type()) && session->get_tls_protection().is_kindof_tls1_2();
}

}  // namespace net
}  // namespace hotplace
