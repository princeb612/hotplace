/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_finished.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * TLS 1.2 PRF(master_secret, label, hash(handshake_message))
 *         master_secret after keyexchange
 * TLS 1.3 HMAC(finished_key, hash(handshake context))
 */

constexpr char constexpr_verify_data[] = "verify data";

tls_handshake_finished::tls_handshake_finished(tls_session* session) : tls_handshake(tls_handshake_type_t::finished, session) {}

tls_handshake_finished::~tls_handshake_finished() {}

void tls_handshake_finished::run_scheduled(tls_direction_t dir) {
    auto session = get_session();
    auto& session_info = session->get_session_info(dir);
    session_info.set_status(get_type());

    // TLS 1.3 switches from handshake traffic keys to application traffic keys
    // at Finished, so the new protection epoch starts with record number zero.
    // TLS 1.2 keeps the same write-state sequence across Finished; its sequence
    // number was reset when ChangeCipherSpec activated the negotiated cipher.
    if (session->get_tls_protection().is_kindof_tls1_3()) {
        session->reset_recordno(dir);
    }
}

return_t tls_handshake_finished::do_preprocess(tls_direction_t dir, tls_io_operation_t opdir) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto tlsver = protection.get_tls_version();
        auto session_status = session->get_session_status();
        uint32 session_status_prerequisite = 0;
        auto flow = protection.get_flow();
        if (true == tlsadvisor->is_kindof_tls1_3(tlsver)) {
            if (tls_flow_t::one_rtt == flow) {
                // RFC 8446 4.4.2 / 4.4.4: Finished follows EncryptedExtensions.
                // Certificate authentication is absent for a PSK-authenticated
                // handshake, so require certificate verification only when no
                // offered PSK identity was selected.
                uint16 offered_identity_count = session->get_keyvalue().get(session_client_psk_identity_count);
                uint16 selected_identity = session->get_keyvalue().get(session_server_psk_selected_identity);
                bool psk_selected = (0 != offered_identity_count) && (selected_identity < offered_identity_count);
                session_status_prerequisite = session_status_server_hello | session_status_encrypted_extensions;
                if (false == psk_selected) {
                    session_status_prerequisite |= session_status_server_cert_verified;
                }
                if (from_client == dir) {
                    session_status_prerequisite |= session_status_server_finished;
                }
            } else if (tls_flow_t::zero_rtt == flow) {
                session_status_prerequisite = session_status_client_hello | session_status_server_hello | session_status_encrypted_extensions;
            }
        } else {
            // TLS 1.2, DTLS 1.2
            // change_cipher_spec
            bool isprotected = session->get_session_info(dir).apply_protection();
            if (false == isprotected) {
                ret = errorcode_t::confidential;
                __leave2;
            }

            // Full handshake: client Finished precedes server Finished.
            // Abbreviated ticket handshake: server Finished precedes client Finished.
            session_status_prerequisite = session_status_server_key_exchange | session_status_client_key_exchange;
            bool abbreviated = protection.is_kindof_tls1_2() && (0 != session->get_keyvalue().get(session_tls1_2_ticket_resumed));
            if (abbreviated) {
                // RFC 5077 abbreviated order: server Finished precedes client Finished.
                if (from_client == dir) {
                    session_status_prerequisite |= session_status_server_finished;
                }
            } else if (from_server == dir) {
                // Full TLS 1.2 order: client Finished precedes server Finished.
                session_status_prerequisite |= session_status_client_finished;
            }
        }

        if ((tls_flow_t::zero_rtt == flow) && (from_client == dir) && (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_accepted)) &&
            (0 == session->get_session_info(from_server).get_keyvalue().get(session_early_data_finished))) {
            // If the server accepted 0-RTT, the client must send EndOfEarlyData
            // before its Finished. Rejected 0-RTT does not require this message.
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        if (session_status_prerequisite != (session_status_prerequisite & session_status)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        {
            ret = protection.update_transcript_hash(session, stream + hspos, get_size());
            if (errorcode_t::success != ret) {
                // Finished has entered the transcript, but the local handshake
                // state cannot continue if transcript processing fails.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                session->reset_session_status();
                // An unusable locally configured cipher suite can prevent
                // transcript-hash initialization before key-schedule processing.
                if (errorcode_t::not_supported == ret) {
                    ret = errorcode_t::internal_error;
                }
                __leave2_trace(ret);
            }

            // from_server : application, exporter related
            // from_client : resumption related
            ret = protection.calc(session, tls_handshake_type_t::finished, dir);
            if (errorcode_t::success != ret) {
                // Do not leave a reusable session with Finished in the
                // transcript but without its application/resumption secrets.
                // The key-schedule helper clears partial outputs; terminate the
                // handshake so callers cannot continue with this transcript.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                session->reset_session_status();
                // The TLS alert for an unusable negotiated cipher suite is
                // internal_error; do not expose not_supported as the handshake result.
                if (errorcode_t::not_supported == ret) {
                    ret = errorcode_t::internal_error;
                }
                __leave2_trace(ret);
            }

            secrets.erase(tls_secret_t::client_hello_random);
            secrets.erase(tls_secret_t::server_hello_random);

            session->get_keyvalue().set(session_handshake_finished, 1);

            if (from_client == dir) {
                secrets.assign(tls_secret_t::client_verifydata, _verify_data);  // copy
            } else if (from_server == dir) {
                secrets.assign(tls_secret_t::server_verifydata, _verify_data);  // copy
            }

            if (from_server == dir) {
                ret = session->update_session_status(session_status_server_finished);
                if (errorcode_t::success != ret) {
                    __leave2_trace(ret);
                }

                // A TLS 1.2 NewSessionTicket precedes Server Finished on the
                // wire. Publish it only after this Finished has been verified
                // and the post-processing/key-schedule step has succeeded.
                if (false == protection.is_kindof_tls1_3()) {
                    auto& ticket_state = session->get_session_info(from_server).get_keyvalue();
                    if (0 != ticket_state.get(session_ticket_pending)) {
                        binary_t pending_ticket = secrets.get(tls_secret_t::new_session_ticket_pending);

                        // The client can resume a later TLS 1.2 connection only
                        // after authenticating the server Finished that closes
                        // the handshake in which this ticket was issued.
                        if ((tls_io_operation_t::read == opdir) && protection.is_kindof_tls1_2()) {
                            const binary_t& master_secret = secrets.get(tls_secret_t::master);
                            if ((false == pending_ticket.empty()) && (48 == master_secret.size())) {
                                tls1_2_resumption_ticket ticket;
                                ticket.identity = pending_ticket;
                                ticket.master_secret = master_secret;
                                ticket.server_name = session->get_client_server_name();
                                ticket.alpn = secrets.get(tls_secret_t::alpn);
                                ticket.lifetime = static_cast<uint32>(ticket_state.get(session_ticket_pending_lifetime));
                                ticket.timestamp = ticket_state.get(session_ticket_pending_timestamp);
                                ticket.version = static_cast<uint16>(protection.get_tls_version());
                                ticket.cipher_suite = protection.get_cipher_suite();
                                const auto& session_values = session->get_keyvalue();
                                ticket.extended_master_secret = (0 != session_values.get(session_extended_master_secret));
                                ticket.encrypt_then_mac = (0 != session_values.get(session_encrypt_then_mac));

                                session->stage_tls1_2_resumption_ticket(ticket);
                                session->confirm_tls1_2_resumption_ticket(ticket.identity);
                            }
                        }

                        secrets.assign(tls_secret_t::new_session_ticket, std::move(pending_ticket));
                        secrets.erase(tls_secret_t::new_session_ticket_pending);
                        ticket_state.set(session_ticket_lifetime, static_cast<uint32>(ticket_state.get(session_ticket_pending_lifetime)));
                        ticket_state.set(session_ticket_age_add, 0);
                        ticket_state.set(session_ticket_timestamp, ticket_state.get(session_ticket_pending_timestamp));
                        ticket_state.set(session_ticket_pending, 0);
                        ticket_state.set(session_ticket_pending_lifetime, 0);
                        ticket_state.set(session_ticket_pending_timestamp, 0);
                    }
                }
            } else if (from_client == dir) {
                ret = session->update_session_status(session_status_client_finished);
                if (errorcode_t::success != ret) {
                    __leave2_trace(ret);
                }

                // A TLS 1.2 server may have issued a replacement ticket before
                // receiving Client Finished (abbreviated handshake). Promote
                // those tickets only after Finished verification and key
                // schedule post-processing have both succeeded.
                if (protection.is_kindof_tls1_2()) {
                    const auto pending_tickets = session->get_pending_tls1_2_resumption_tickets();
                    for (const auto& pending_ticket : pending_tickets) {
                        session->confirm_tls1_2_resumption_ticket(pending_ticket.identity);
                    }
                }

                // A client that was rejected for 0-RTT does not send
                // EndOfEarlyData. Its Finished still closes the early-data
                // phase before any subsequent 1-RTT application data.
                if (protection.is_kindof_tls1_3() && (tls_flow_t::zero_rtt == protection.get_flow())) {
                    session->get_session_info(from_server).get_keyvalue().set(session_early_data_finished, 1);
                }
            }

            if (tls_flow_t::renegotiation == protection.get_flow()) {
                const uint32 finished_status = session_status_client_finished | session_status_server_finished;
                if (finished_status == (session->get_session_status() & finished_status)) {
                    // The new handshake is complete. The next renegotiation,
                    // if enabled, must start from the freshly stored verify_data.
                    protection.set_flow(tls_flow_t::one_rtt);
                    session->get_session_info(from_client).get_keyvalue().set(session_tls12_renegotiation_ccs, 0);
                    session->get_session_info(from_server).get_keyvalue().set(session_tls12_renegotiation_ccs, 0);
                }
            }
            session->schedule(this);  // run_scheduled
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8446 2.  Protocol Overview
        // Finished:  A MAC (Message Authentication Code) over the entire
        //    handshake.  This message provides key confirmation, binds the
        //    endpoint's identity to the exchanged keys, and in PSK mode also
        //    authenticates the handshake.  [Section 4.4.4]

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        const size_t body_end = offsetof_body() + get_body_size();
        if ((body_end > size) || (pos > body_end)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            session->reset_session_status();
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }
        auto& protection = session->get_tls_protection();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            const uint16 ciphersuite = protection.get_cipher_suite();
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(ciphersuite);
            // Cipher suite 0 is TLS_NULL_WITH_NULL_NULL, not a negotiated
            // TLS 1.3 cipher suite. Do not treat its registry entry as valid.
            if ((0 == ciphersuite) || (nullptr == hint_tls_alg)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                session->reset_session_status();
                ret = errorcode_t::internal_error;
                __leave2_trace(ret);
            }
            if (tlsadvisor->is_kindof_tls1_3(tlsversion)) {
                dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));
            } else {
                dlen = 12;
            }
            hmacalg = algof_mac(hint_tls_alg);
        }

        binary_t verify_data;

        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_verify_data);
            pl.reserve(constexpr_verify_data, dlen);
            ret = pl.read(stream, body_end, pos);
            if ((errorcode_t::success != ret) || (pos != body_end)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            pl.get_binary(constexpr_verify_data, verify_data);
        }

        {
            tls_secret_t typeof_secret;
            binary_t maced;
            ret = protection.calc_finished(dir, hmacalg, dlen, typeof_secret, maced);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }

            verify_data.resize(maced.size());
            if (maced.empty() || (verify_data != maced)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::verification_failure;
            }

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                    auto& secrets = protection.get_secrets();
                    dbs.autoindent(1);
                    dbs.println("> %s " ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", constexpr_verify_data, (errorcode_t::success == ret) ? "true" : "false");
                    if (check_trace_level(loglevel_t::loglevel_debug)) {
                        dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
                    }
                    const binary_t ht_secret = secrets.get(typeof_secret);
                    dbs.println("  > secret [0x%08x] %s (%s)", typeof_secret, base16_encode(ht_secret).c_str(), tlsadvisor->nameof_secret(typeof_secret).c_str());
                    dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
                    dbs.println("  > verify data %s", base16_encode(verify_data).c_str());
                    dbs.println("  > maced       %s", base16_encode(maced).c_str());
                    dbs.autoindent(0);
                });
            }
#endif

            if (errorcode_t::success != ret) {
                __leave2;
            }

            _verify_data = std::move(verify_data);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            const uint16 ciphersuite = protection.get_cipher_suite();
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(ciphersuite);
            // Cipher suite 0 is TLS_NULL_WITH_NULL_NULL, not a negotiated
            // TLS 1.3 cipher suite. Do not treat its registry entry as valid.
            if ((0 == ciphersuite) || (nullptr == hint_tls_alg)) {
                // Finished cannot be encoded without a negotiated cipher suite.
                // The local handshake state is inconsistent; fail before
                // emitting an empty body and report fatal internal_error.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                session->reset_session_status();
                ret = errorcode_t::internal_error;
                __leave2_trace(ret);
            }
            if (tlsadvisor->is_kindof_tls1_3(tlsversion)) {
                dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));
            } else {
                dlen = 12;
            }
            hmacalg = algof_mac(hint_tls_alg);
        }

        tls_secret_t typeof_secret;
        binary_t verify_data;
        ret = protection.calc_finished(dir, hmacalg, dlen, typeof_secret, verify_data);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        {
            payload pl;
            pl << new payload_member(verify_data, constexpr_verify_data);
            ret = pl.write(bin);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                auto& secrets = protection.get_secrets();
                dbs.println("> %s", constexpr_verify_data);
                if (check_trace_level(loglevel_t::loglevel_debug)) {
                    dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
                }
                const binary_t ht_secret = secrets.get(typeof_secret);
                dbs.println("  > secret [0x%08x] %s (%s)", typeof_secret, base16_encode(ht_secret).c_str(), tlsadvisor->nameof_secret(typeof_secret).c_str());
                dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
                dbs.println("  > verify data %s", base16_encode(verify_data).c_str());
            });
        }
#endif

        _verify_data = std::move(verify_data);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
