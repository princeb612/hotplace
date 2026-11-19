/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_client_hello.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <chrono>
#include <cstring>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/split.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr uint16 constexpr_session_client_supported_versions_key = 0x2005;

constexpr char constexpr_version[] = "version";
constexpr char constexpr_random[] = "random";
constexpr char constexpr_session_id[] = "session id";
constexpr char constexpr_session_id_len[] = "session id len";
constexpr char constexpr_cipher_suite[] = "cipher suite";
constexpr char constexpr_cipher_suite_len[] = "cipher suite len";
constexpr char constexpr_compression_method_len[] = "compression method len";
constexpr char constexpr_compression_method[] = "compression method";
constexpr char constexpr_extension_len[] = "extension len";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_cookie_len[] = "cookie len";
constexpr char constexpr_cookie[] = "cookie";

static void rollback_client_hello_early_data(tls_session* session, tls_flow_t original_flow) {
    if (nullptr == session) {
        return;
    }

    auto& protection = session->get_tls_protection();
    session->reset_session_status();

    auto& secrets = protection.get_secrets();
    auto& session_kv = session->get_keyvalue();
    session_kv.set(session_server_psk_selected_identity, 0xffff);
    session_kv.set(session_server_psk_key_exchange_mode, 0xffff);
    session_kv.set(session_server_psk_ticket_cipher_suite, 0);
    session_kv.set(session_client_psk_identity_count, 0);

    secrets.assign(tls_secret_t::resumption_early, binary_t());
    secrets.erase(tls_secret_t::resumption_binder_hash);
    secrets.erase(tls_secret_t::resumption_binder_key);
    secrets.erase(tls_secret_t::resumption_finished_key);
    secrets.erase(tls_secret_t::resumption_finished);
    secrets.assign(tls_secret_t::c_e_traffic, binary_t());
    secrets.assign(tls_secret_t::e_exp_master, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t());

    session->set_offered_resumption_tickets(std::vector<tls_resumption_ticket>());
    session->clear_early_data_ticket();

    auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
    early_data_state.set(session_early_data_offered, 0);
    early_data_state.set(session_early_data_offered_initial, 0);
    early_data_state.set(session_early_data_limit, 0);
    early_data_state.set(session_early_data_accepted, 0);

    if ((tls_flow_t::zero_rtt == original_flow) || (tls_flow_t::hello_retry_request == original_flow)) {
        protection.set_flow(tls_flow_t::one_rtt);
        session->get_session_info(from_client).reset_protection();
    }
}

tls_handshake_client_hello::tls_handshake_client_hello(tls_session* session) : tls_handshake(tls_handshake_type_t::client_hello, session) {}

tls_handshake_client_hello::~tls_handshake_client_hello() {}

return_t tls_handshake_client_hello::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_client != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        auto session = get_session();
        auto& protection = session->get_tls_protection();
        // RFC 8446 4.2.11: bind cached PSKs to the SNI used by this ClientHello.
        binary_t client_server_name;
        auto ext_sni = get_extensions().get(tls_extension_type_t::server_name);
        if (ext_sni && (0 == static_cast<tls_extension_sni*>(ext_sni)->get_nametype())) {
            const auto& hostname = static_cast<tls_extension_sni*>(ext_sni)->get_hostname();
            client_server_name.assign(hostname.begin(), hostname.end());
        }
        session->set_client_server_name(client_server_name);
        session->get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
        session->get_keyvalue().set(session_server_psk_key_exchange_mode, 0xffff);
        session->get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0);
        session->clear_early_data_ticket();
        // A new ClientHello starts a fresh record_size_limit negotiation, including
        // renegotiation and resumption. Do not carry limits from the prior key epoch.
        session->get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 0);
        session->get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 0);
        auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
        bool after_hrr = (tls_flow_t::hello_retry_request == protection.get_flow());
        if (false == after_hrr) {
            // Do not let a selected_group from an earlier retry leak into a new handshake.
            session->get_session_info(from_server).get_keyvalue().set(session_key_share_group, t_underlying(tls_group_t::unknown));
        }
        early_data_state.set(session_early_data_offered, 0);
        early_data_state.set(session_early_data_limit, 0);
        early_data_state.set(session_early_data_received, 0);
        early_data_state.set(session_early_data_sent, 0);
        if (false == after_hrr) {
            early_data_state.set(session_early_data_offered_initial, 0);
            early_data_state.set(session_early_data_discard_limit, 0);
            early_data_state.set(session_early_data_discarded, 0);
            early_data_state.set(session_early_data_discarded_records, 0);
        }
        early_data_state.set(session_early_data_finished, 0);
        early_data_state.set(session_early_data_accepted, 0);
        session->get_keyvalue().set(constexpr_session_client_supported_versions_key, 0);
        // ClientHello2 after HelloRetryRequest must preserve the original offer.
        if (tls_flow_t::hello_retry_request != protection.get_flow()) {
            session->get_keyvalue().set(session_client_post_handshake_auth, 0);
            session->reset_certificate_request_contexts();
            // The negotiated ALPN belongs to the connection that issued a
            // ticket. Clear the previous connection's value before parsing or
            // composing a new ClientHello; the new EncryptedExtensions will
            // populate it again when ALPN is negotiated.
            protection.get_secrets().assign(tls_secret_t::alpn, binary_t());
        }
        // auto& secrets = protection.get_secrets();
        // auto session_type = session->get_type();
        auto session_status = session->get_session_status();

        // RFC 8446
        // Because TLS 1.3 forbids renegotiation, if a server has negotiated
        // TLS 1.3 and receives a ClientHello at any other time, it MUST
        // terminate the connection with an "unexpected_message" alert.
        if (session_status) {
            if (session_status_hello_verify_request & session_status) {
                // DTLS cookie
                if (session_status_server_hello & session_status) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
            } else if ((session_status_server_finished | session_status_client_finished) & session_status) {
                // 0-RTT, renegotiation
            } else if (~(session_status_client_hello | session_status_server_hello | session_status_hello_retry_request) & session_status) {
                // not HRR
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        // finished -> client_hello
        auto hsstatus = session->get_session_info(dir).get_status();
        if ((tls_handshake_type_t::finished == hsstatus) || after_hrr) {
            // Client-side ticket policy applies to a new resumption ClientHello
            // and to ClientHello2 explicitly: the latter has ClientHello status
            // after ClientHello1 was serialized, but must re-evaluate tickets
            // against the cipher suite selected by HelloRetryRequest.
            // that already has a configured PSK offer. On the receiving side,
            // extensions have not been parsed yet; applying this policy there
            // would erase the server's resumption secrets before RFC 8448
            // ClientHello processing.
            if (protection.is_kindof_tls13() && (nullptr != get_extensions().get(tls_extension_type_t::pre_shared_key))) {
                // A TLS 1.3 resumption attempt is only usable while the cached
                // ticket is within both its advertised lifetime and the
                // RFC 8446 seven-day client maximum.
                constexpr uint64 max_ticket_lifetime = 7 * 24 * 60 * 60;
                auto& ticket_kv = session->get_session_info(from_server).get_keyvalue();
                uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                bool ticket_metadata_valid = false;
                bool ticket_within_lifetime = false;
                bool ticket_hash_compatible = false;
                uint64 first_ticket_early_data_limit = 0;
                bool psk_extension_configured = (nullptr != get_extensions().get(tls_extension_type_t::pre_shared_key));
                auto psk_extension = static_cast<tls_extension_client_psk*>(get_extensions().get(tls_extension_type_t::pre_shared_key));
                auto cached_tickets = session->get_resumption_tickets();
                auto alpn_extension = static_cast<tls_extension_alpn*>(get_extensions().get(tls_extension_type_t::application_layer_protocol_negotiation));
                binary_t offered_alpn = alpn_extension ? alpn_extension->get_protocols() : binary_t();
                auto ticket_alpn_is_offered = [](const binary_t& offered, const binary_t& ticket_alpn) -> bool {
                    if (ticket_alpn.empty()) {
                        return offered.empty();
                    }
                    if (ticket_alpn.size() < 2 || static_cast<size_t>(ticket_alpn[0]) + 1 != ticket_alpn.size()) {
                        return false;
                    }
                    size_t pos = 0;
                    while (pos < offered.size()) {
                        uint8 protocol_size = offered[pos++];
                        if ((0 == protocol_size) || (protocol_size > offered.size() - pos)) {
                            return false;
                        }
                        if ((ticket_alpn.size() == static_cast<size_t>(protocol_size) + 1) &&
                            std::equal(ticket_alpn.begin() + 1, ticket_alpn.end(), offered.begin() + pos)) {
                            return true;
                        }
                        pos += protocol_size;
                    }
                    return false;
                };

                if ((false == cached_tickets.empty())) {
                    const binary_t current_server_name = session->get_client_server_name();
                    for (const auto& ticket : cached_tickets) {
                        if (ticket.server_name != current_server_name) {
                            continue;
                        }
                        bool metadata_valid = (false == ticket.identity.empty()) && (ticket.identity.size() <= 0xffff) && (false == ticket.psk.empty()) &&
                                              (ticket.lifetime > 0) && (ticket.timestamp > 0) && (ticket.timestamp <= now_ms);
                        if ((false == metadata_valid)) {
                            continue;
                        }
                        ticket_metadata_valid = true;
                        uint64 bounded_lifetime = (ticket.lifetime > max_ticket_lifetime) ? max_ticket_lifetime : ticket.lifetime;
                        uint64 ticket_age_ms = now_ms - ticket.timestamp;
                        if (ticket_age_ms > bounded_lifetime * 1000) {
                            continue;
                        }
                        ticket_within_lifetime = true;

                        const tls_cipher_suite_t* ticket_suite = tls_advisor::get_instance()->hintof_cipher_suite(ticket.cipher_suite);
                        if ((false == psk_extension_configured) || (nullptr == ticket_suite) || (tls_13 != ticket_suite->spec)) {
                            continue;
                        }
                        auto crypto_advisor_instance = crypto_advisor::get_instance();
                        const hint_digest_t* ticket_hash = crypto_advisor_instance->hintof_digest(ticket_suite->mac);
                        if ((nullptr == ticket_hash) || (ticket.psk.size() != ticket_hash->digest_size)) {
                            continue;
                        }
                        // The first PSK identity must fit together with its
                        // binder and both vector-length fields in the complete
                        // pre_shared_key extension body (RFC 8446 §4.2.11).
                        const size_t minimum_psk_extension_size =
                            sizeof(uint16) + sizeof(uint16) + sizeof(uint16) + ticket.identity.size() + sizeof(uint32) + sizeof(uint8) + ticket_hash->digest_size;
                        if (minimum_psk_extension_size > 0xffff) {
                            continue;
                        }
                        if (after_hrr) {
                            const tls_cipher_suite_t* retry_suite = tls_advisor::get_instance()->hintof_cipher_suite(protection.get_cipher_suite());
                            ticket_hash_compatible = (nullptr != retry_suite) && (tls_13 == retry_suite->spec) && (retry_suite->mac == ticket_suite->mac);
                        } else {
                            for (const auto& offered_suite_code : _cipher_suites) {
                                const tls_cipher_suite_t* offered_suite = tls_advisor::get_instance()->hintof_cipher_suite(offered_suite_code);
                                if (offered_suite && (tls_13 == offered_suite->spec) && (offered_suite->mac == ticket_suite->mac)) {
                                    ticket_hash_compatible = true;
                                    break;
                                }
                            }
                        }
                        if (ticket_hash_compatible) {
                            // 0-RTT is bound to identity zero. Its ALPN must
                            // still be offered by this ClientHello, and the
                            // ticket must advertise a nonzero data allowance.
                            bool ticket_alpn_compatible = ticket_alpn_is_offered(offered_alpn, ticket.alpn);
                            bool ticket_version_compatible = (static_cast<uint16>(tls_13) == ticket.version);
                            first_ticket_early_data_limit = (ticket_alpn_compatible && ticket_version_compatible) ? ticket.max_early_data_size : 0;
                            break;
                        }
                    }
                } else {
                    const binary_t& ticket = protection.get_secrets().get(tls_secret_t::new_session_ticket);
                    const binary_t& resumption_psk = protection.get_secrets().get(tls_secret_t::resumption_early);
                    uint64 ticket_lifetime = ticket_kv.get(session_ticket_lifetime);
                    uint64 ticket_timestamp = ticket_kv.get(session_ticket_timestamp);
                    bool metadata_valid = (false == ticket.empty()) && (false == resumption_psk.empty()) && session->get_client_server_name().empty() &&
                                          (ticket_lifetime > 0) && (ticket_timestamp > 0) && (ticket_timestamp <= now_ms);
                    ticket_metadata_valid = metadata_valid;
                    if (metadata_valid) {
                        uint64 bounded_lifetime = (ticket_lifetime > max_ticket_lifetime) ? max_ticket_lifetime : ticket_lifetime;
                        uint64 ticket_age_ms = now_ms - ticket_timestamp;
                        ticket_within_lifetime = (ticket_age_ms <= bounded_lifetime * 1000);
                    }

                    // The legacy singleton ticket view has no ticket object,
                    // so retain its NewSessionTicket early_data allowance as
                    // separate metadata and restore it only for a valid PSK.
                    if (metadata_valid && ticket_within_lifetime) {
                        first_ticket_early_data_limit = ticket_kv.get(session_ticket_max_early_data_size);
                    }

                    // Compatibility for sessions that have not yet populated the ticket collection.
                    const tls_cipher_suite_t* ticket_suite = tls_advisor::get_instance()->hintof_cipher_suite(protection.get_cipher_suite());
                    if (psk_extension_configured && ticket_within_lifetime && ticket_suite && (tls_13 == ticket_suite->spec)) {
                        auto crypto_advisor_instance = crypto_advisor::get_instance();
                        const hint_digest_t* ticket_hash = crypto_advisor_instance->hintof_digest(ticket_suite->mac);
                        if (ticket_hash && (resumption_psk.size() == ticket_hash->digest_size)) {
                            const size_t minimum_psk_extension_size =
                                sizeof(uint16) + sizeof(uint16) + sizeof(uint16) + ticket.size() + sizeof(uint32) + sizeof(uint8) + ticket_hash->digest_size;
                            if (minimum_psk_extension_size > 0xffff) {
                                ticket_hash = nullptr;
                            }
                        }
                        if (ticket_hash && (resumption_psk.size() == ticket_hash->digest_size)) {
                            for (const auto& offered_suite_code : _cipher_suites) {
                                const tls_cipher_suite_t* offered_suite = tls_advisor::get_instance()->hintof_cipher_suite(offered_suite_code);
                                if (offered_suite && (tls_13 == offered_suite->spec) && (offered_suite->mac == ticket_suite->mac)) {
                                    ticket_hash_compatible = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (nullptr != psk_extension) {
                    // Omit the PSK extension whenever no cached identity can be offered under
                    // this ClientHello's lifetime and cipher-suite hash constraints.
                    psk_extension->set_suppressed(false == (ticket_within_lifetime && ticket_hash_compatible));
                }
                session->get_session_info(from_server).get_keyvalue().set(session_early_data_limit, first_ticket_early_data_limit);
                if (ticket_within_lifetime && ticket_hash_compatible) {
                    // ClientHello2 must remain in the HRR flow. Switching to
                    // zero_rtt here would make the later transcript processing
                    // treat it as an initial resumption ClientHello.
                    if (tls_flow_t::hello_retry_request != protection.get_flow()) {
                        protection.set_flow(tls_flow_t::zero_rtt);
                    }
                } else {
                    if (false == after_hrr) {
                        protection.set_flow(tls_flow_t::one_rtt);
                    }
                    if (cached_tickets.empty() && ((false == ticket_metadata_valid) || (false == ticket_within_lifetime))) {
                        // Preserve the legacy singleton cleanup only when no authoritative ticket collection exists.
                        protection.get_secrets().assign(tls_secret_t::new_session_ticket, binary_t());
                        protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t());
                        ticket_kv.set(session_ticket_lifetime, 0);
                        ticket_kv.set(session_ticket_age_add, 0);
                        ticket_kv.set(session_ticket_timestamp, 0);
                        ticket_kv.set(session_ticket_max_early_data_size, 0);
                    }
                }
                // Keep the HRR status marker until ClientHello2 postprocessing
                // has preserved the message_hash || HelloRetryRequest transcript.
                if (tls_flow_t::hello_retry_request != protection.get_flow()) {
                    session->reset_session_status();
                }
            } else if ((false == protection.is_kindof_tls13())) {
                // renegotiation
                //   review
                //     - tls12renogotiation.pcapng
                //       - client finished 92d20ede5b77d916bb376397 (tls_secret_t::client_verifydata)
                //       - server finished 522748448a013f75119810f6 (tls_secret_t::server_verifydata)
                //       - client_hello renegotiation_info 92d20ede5b77d916bb376397
                //         - must be (tls_secret_t::client_verifydata)
                //       - server_hello renegotiation_info 92d20ede5b77d916bb376397522748448a013f75119810f6
                //         - must be (tls_secret_t::client_verifydata || tls_secret_t::server_verifydata)
                //     - tls12no_renogotiation.pcapng
                //   tls_handshake_client_hello
                //     - test the value of session_conf_enable_renegotiation
                //       - if zero, renegotiation is prohibited
                //         - alert(fatal, tls_alertdesc_t::no_renegotiation)
                //       - else
                //         - set_flow(tls_flow_t::renegotiation);
                //         - renegotiation_info must be the verify data of finished
                //         - key calcuration (TODO)
                //   tls_handshake_server_hello
                //     - if renegotiation allowed
                //       - reply renegotiation_info
                //       - key calcuration (TODO)
                //
#if 0
                auto& kv = session->get_keyvalue();
                if (kv.get(session_conf_enable_renegotiation)) {
                    protection.set_flow(tls_flow_t::renegotiation);
                } else
#endif
                {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::no_renegotiation);
                    session->reset_session_status();
                    ret = errorcode_t::negotiation_failure;
                    __leave2;
                }
            }
        }

        switch (protection.get_flow()) {
            case tls_flow_t::one_rtt: {
                // Start a fresh negotiation epoch. Preserve the prior negotiated
                // version for resumed 0-RTT and HRR flows, which use other branches.
                session->get_keyvalue().set(session_tls_version, 0);
            } break;
            case tls_flow_t::zero_rtt: {
                session->reset_recordno(from_client);
                session->reset_recordno(from_server);
            } break;
            case tls_flow_t::hello_retry_request: {
                session->clear_session_status(session_status_server_hello);

                auto& tlskey = protection.get_key();
                tlskey.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);  // client_hello key_share
                tlskey.erase(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC);  // server_hello key_share
            } break;
            case tls_flow_t::renegotiation: {
                // TODO
            } break;
            default: {
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_client_hello::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        original_flow = protection.get_flow();
        auto& secrets = protection.get_secrets();
        auto tlsadvisor = tls_advisor::get_instance();
        auto session_status = session->get_session_status();

        // RFC 8446 4.2.6: post_handshake_auth is an empty ClientHello extension.
        auto ext_post_handshake_auth = get_extensions().get(tls_extension_type_t::post_handshake_auth);
        if ((nullptr != ext_post_handshake_auth) && (0 != ext_post_handshake_auth->get_body_size())) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            session->reset_session_status();
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

        if (session_status_hello_verify_request & session_status) {
            bool cond1 = (get_random() != secrets.get(tls_secret_t::client_hello_random));
            bool cond2 = (get_cookie() != secrets.get(tls_secret_t::cookie));
            if (cond1 || cond2) {
                // client_hello
                // hello_verify_request (cookie)
                // client_hello (cookie)
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        // RFC 8446 4.2.9: a ClientHello that offers pre_shared_key
        // MUST also include psk_key_exchange_modes.
        if ((from_client == dir) && (tls_io_operation_t::read == opdir) && (nullptr != get_extensions().get(tls_extension_type_t::pre_shared_key)) &&
            (nullptr == get_extensions().get(tls_extension_type_t::psk_key_exchange_modes))) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        // 0-RTT, pre_shared_key extension
        if (tls_flow_t::zero_rtt == protection.get_flow()) {
            auto ext_psk = get_extensions().get(tls_extension_type_t::pre_shared_key);
            if (nullptr == ext_psk) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }
        // The client binder is patched only after the complete ClientHello has been
        // serialized, so all enclosing length fields already describe the final
        // message including the binder bytes.
        if ((tls_io_operation_t::write == opdir) && ((tls_flow_t::zero_rtt == protection.get_flow()) || (tls_flow_t::hello_retry_request == protection.get_flow()))) {
            auto ext = get_extensions().get(tls_extension_type_t::pre_shared_key);
            if ((nullptr != ext) && (false == static_cast<tls_extension_client_psk*>(ext)->is_suppressed())) {
                auto psk = static_cast<tls_extension_client_psk*>(ext);
                size_t hspos = offsetof_header();
                size_t handshake_header_size = (session_type_t::dtls == session->get_type()) ? 12 : 4;
                size_t body_prefix_size = sizeof(uint16) + 32 + sizeof(uint8) + _session_id.size();
                if (session_type_t::dtls == session->get_type()) {
                    body_prefix_size += sizeof(uint8) + _cookie.size();
                }
                body_prefix_size += sizeof(uint16) + (_cipher_suites.size() * sizeof(uint16)) + sizeof(uint8) + sizeof(uint8) + sizeof(uint16);

                // Locate the PSK extension in the serialized ClientHello rather
                // than combining offsets retained by independently serialized
                // extension objects. The latter can be relative to a temporary
                // extension buffer and is not a reliable absolute wire offset.
                size_t extensions_offset = hspos + handshake_header_size + body_prefix_size;
                size_t extensions_length_offset = extensions_offset - sizeof(uint16);
                if ((extensions_length_offset + sizeof(uint16) > size) || (extensions_offset > size)) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }
                uint16 extensions_length = (static_cast<uint16>(stream[extensions_length_offset]) << 8) | stream[extensions_length_offset + 1];
                size_t extensions_end = extensions_offset + extensions_length;
                if (extensions_end > size) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                size_t binder_list_offset = size;
                size_t extension_pos = extensions_offset;
                while (extension_pos + 4 <= extensions_end) {
                    uint16 extension_type = (static_cast<uint16>(stream[extension_pos]) << 8) | stream[extension_pos + 1];
                    uint16 extension_size = (static_cast<uint16>(stream[extension_pos + 2]) << 8) | stream[extension_pos + 3];
                    size_t extension_body = extension_pos + 4;
                    size_t extension_end = extension_body + extension_size;
                    if (extension_end > extensions_end) {
                        ret = errorcode_t::bad_format;
                        break;
                    }
                    if (static_cast<uint16>(tls_extension_type_t::pre_shared_key) == extension_type) {
                        if (extension_size < 4) {
                            ret = errorcode_t::bad_format;
                            break;
                        }
                        uint16 identities_length = (static_cast<uint16>(stream[extension_body]) << 8) | stream[extension_body + 1];
                        binder_list_offset = extension_body + sizeof(uint16) + identities_length;
                        if ((binder_list_offset + sizeof(uint16) > extension_end) || (extension_end - binder_list_offset < sizeof(uint16))) {
                            ret = errorcode_t::bad_format;
                            break;
                        }
                        break;
                    }
                    extension_pos = extension_end;
                }
                if (errorcode_t::success != ret) {
                    __leave2_trace(ret);
                }
                if ((binder_list_offset == size) || (binder_list_offset + sizeof(uint16) > extensions_end)) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                uint16 binders_length = (static_cast<uint16>(stream[binder_list_offset]) << 8) | stream[binder_list_offset + 1];
                size_t binders_end = binder_list_offset + sizeof(uint16) + binders_length;
                if (binders_end > extensions_end) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
                if (nullptr == hint_tls_alg) {
                    ret = errorcode_t::not_supported;
                    __leave2_trace(ret);
                }

                const auto& binder_psks = psk->get_binder_psks();
                const auto& offered_tickets = session->get_offered_resumption_tickets();
                const bool legacy_singleton = offered_tickets.empty();
                if (binder_psks.empty() || (legacy_singleton ? (1 != binder_psks.size()) : (binder_psks.size() != offered_tickets.size()))) {
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                binary_t previous_psk = secrets.get(tls_secret_t::resumption_early);
                uint16 previous_cipher_suite = protection.get_cipher_suite();
                binary_t first_psk_early_secret;
                size_t binder_offset = binder_list_offset + 2;
                for (size_t i = 0; i < binder_psks.size(); ++i) {
                    if (binder_offset >= binders_end) {
                        ret = errorcode_t::bad_format;
                        break;
                    }
                    uint8 binder_len = stream[binder_offset++];
                    if ((0 == binder_len) || (binder_len > binders_end - binder_offset)) {
                        ret = errorcode_t::bad_format;
                        break;
                    }

                    uint16 ticket_cipher_suite = legacy_singleton ? previous_cipher_suite : offered_tickets[i].cipher_suite;
                    const tls_cipher_suite_t* ticket_suite = tlsadvisor->hintof_cipher_suite(ticket_cipher_suite);
                    if ((nullptr == ticket_suite) || (tls_13 != ticket_suite->spec)) {
                        ret = errorcode_t::not_supported;
                        break;
                    }
                    const hint_digest_t* ticket_hash = crypto_advisor::get_instance()->hintof_digest(ticket_suite->mac);
                    if ((nullptr == ticket_hash) || (binder_len != ticket_hash->digest_size)) {
                        ret = errorcode_t::bad_format;
                        break;
                    }

                    binary_t binder_hash;
                    ret = protection.calc_context_hash(session, ticket_suite->mac, stream + hspos, binder_list_offset - hspos, binder_hash);
                    if (errorcode_t::success != ret) {
                        break;
                    }

                    if (legacy_singleton) {
                        // Legacy singleton state already stores the early secret.
                        secrets.assign(tls_secret_t::resumption_early, binder_psks[i]);
                        if (0 == i) {
                            first_psk_early_secret = binder_psks[i];
                        }
                    } else {
                        protection.set_cipher_suite(ticket_cipher_suite);
                        binary_t ticket_early_secret;
                        ret = protection.calc_resumption_early_secret(binder_psks[i], ticket_early_secret);
                        if (errorcode_t::success != ret) {
                            break;
                        }
                        if (0 == i) {
                            // RFC 8446 4.2.10: early traffic keys always use
                            // the PSK at wire identity zero, not the last
                            // cached ticket secret left in the session.
                            first_psk_early_secret = ticket_early_secret;
                        }
                        secrets.assign(tls_secret_t::resumption_early, std::move(ticket_early_secret));
                    }
                    binary_t binder;
                    ret = protection.calc_psk_binder(session, binder_hash, binder);
                    if ((errorcode_t::success != ret) || (binder.size() != binder_len)) {
                        if (errorcode_t::success == ret) {
                            ret = errorcode_t::bad_format;
                        }
                        break;
                    }

                    std::memcpy(const_cast<byte_t*>(stream) + binder_offset, binder.data(), binder.size());
                    binder_offset += binder_len;
                }
                bool keep_first_psk_early_secret = (errorcode_t::success == ret) && (binder_offset == binders_end) && (tls_flow_t::zero_rtt == protection.get_flow()) &&
                                                   (false == first_psk_early_secret.empty());
                secrets.assign(tls_secret_t::resumption_early, keep_first_psk_early_secret ? std::move(first_psk_early_secret) : previous_psk);
                protection.set_cipher_suite(previous_cipher_suite);
                if ((errorcode_t::success != ret) || (binder_offset != binders_end)) {
                    if (errorcode_t::success == ret) {
                        ret = errorcode_t::bad_format;
                    }
                    __leave2_trace(ret);
                }
            }
        }

        // transcript hash, keycalc
        {
            auto hspos = offsetof_header();
            auto size_header_body = get_size();

            switch (protection.get_flow()) {
                case tls_flow_t::one_rtt: {
                    secrets.assign(tls_secret_t::client_hello, stream + hspos, size_header_body);  // transcript hash, see server_hello
                } break;
                case tls_flow_t::zero_rtt: {
                    // Keep the complete first ClientHello available: if the
                    // server selects HelloRetryRequest, ServerHello processing
                    // replaces it with the synthetic message_hash transcript.
                    // Do not overwrite it when processing a resumed ClientHello2.
                    if (0 == (session_status_hello_retry_request & session_status)) {
                        secrets.assign(tls_secret_t::client_hello, stream + hspos, size_header_body);
                        protection.reset_transcript_hash(session);
                    }
                    // A PSK ClientHello2 follows the synthetic message_hash and
                    // HelloRetryRequest already present in the transcript.
                    // Preserve that prefix instead of restarting at ClientHello2.
                    protection.update_transcript_hash(session, stream + hspos, size_header_body /*, handshake_hash */);  // client_hello
                    ret = protection.calc(session, tls_handshake_type_t::client_hello, dir);
                    if (errorcode_t::success != ret) {
                        // ClientHello has entered the transcript, but the
                        // local 0-RTT key schedule failed. Abort rather than
                        // committing ClientHello state with missing early keys.
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                        rollback_client_hello_early_data(session, original_flow);
                    }
                } break;
                case tls_flow_t::hello_retry_request: {
                    protection.update_transcript_hash(session, stream + hspos, size_header_body /*, handshake_hash */);  // client_hello
                } break;
                case tls_flow_t::renegotiation: {
                    // TODO
                } break;
            }

            if (errorcode_t::success != ret) {
                // Leave the outer try scope so its finalizer can retire any
                // expired ticket records after rolling back the failed read.
                __leave2_trace(ret);
            }

            session->get_session_info(dir).set_status(get_type());
        }

        // Preserve whether this exact ClientHello offered early_data. The server
        // must not infer 0-RTT permission merely from successful PSK selection.
        if (from_client == dir) {
            bool early_data_extension_present = (nullptr != get_extensions().get(tls_extension_type_t::early_data));
            bool early_data_offered = (tls_flow_t::hello_retry_request != protection.get_flow()) && early_data_extension_present;
            if (tls_io_operation_t::write == opdir) {
                // The client writer suppresses early_data when identity zero
                // has no compatible ticket allowance. Track only an extension
                // that was actually eligible for serialization.
                early_data_offered = (tls_flow_t::zero_rtt == protection.get_flow()) && early_data_offered &&
                                     (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_limit)) &&
                                     (nullptr != get_extensions().get(tls_extension_type_t::pre_shared_key));
            }
            // On read, retain the peer's offer even when the server later
            // determines that the ticket is ineligible.
            auto& early_state = session->get_session_info(from_server).get_keyvalue();
            early_state.set(session_early_data_offered, early_data_offered ? 1 : 0);
            if (tls_flow_t::hello_retry_request != protection.get_flow()) {
                early_state.set(session_early_data_offered_initial, early_data_offered ? 1 : 0);
            }
        }

        // Keep the actual PSK identity count from this ClientHello. This is
        // replaced by ClientHello2 after HRR, so ServerHello validation uses
        // the offer to which the server actually responded.
        auto ext_psk_offer = get_extensions().get(tls_extension_type_t::pre_shared_key);
        bool psk_offer_suppressed = (nullptr != ext_psk_offer) && static_cast<tls_extension_client_psk*>(ext_psk_offer)->is_suppressed();
        if ((nullptr == ext_psk_offer) || psk_offer_suppressed) {
            // A suppressed ClientHello2 PSK object is not an offer on the wire.
            // Discard ClientHello1's local binder/ticket snapshot as well.
            session->set_offered_resumption_tickets(std::vector<tls_resumption_ticket>());
            session->get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
            session->get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0);
        }
        auto& psk_secrets = protection.get_secrets();
        const bool after_hrr = (tls_flow_t::hello_retry_request == protection.get_flow());
        std::vector<binary_t> current_psk_identities;
        if (nullptr != ext_psk_offer) {
            current_psk_identities = static_cast<tls_extension_client_psk*>(ext_psk_offer)->get_identities();
        }

        auto encode_psk_identities = [](const std::vector<binary_t>& identities) -> binary_t {
            binary_t encoded;
            for (const auto& identity : identities) {
                if (identity.empty() || (identity.size() > 0xffff)) {
                    return binary_t();
                }
                uint16 length = t_narrow_cast(identity.size());
                encoded.push_back(static_cast<byte_t>(length >> 8));
                encoded.push_back(static_cast<byte_t>(length));
                encoded.insert(encoded.end(), identity.begin(), identity.end());
            }
            return encoded;
        };
        auto decode_psk_identities = [](const binary_t& encoded, std::vector<binary_t>& identities) -> bool {
            size_t pos = 0;
            while (pos < encoded.size()) {
                if (encoded.size() - pos < 2) {
                    return false;
                }
                uint16 length = (static_cast<uint16>(encoded[pos]) << 8) | encoded[pos + 1];
                pos += 2;
                if ((0 == length) || (length > encoded.size() - pos)) {
                    return false;
                }
                identities.emplace_back(encoded.begin() + pos, encoded.begin() + pos + length);
                pos += length;
            }
            return true;
        };

        binary_t current_psk_identity_snapshot = encode_psk_identities(current_psk_identities);
        if ((false == current_psk_identities.empty()) && current_psk_identity_snapshot.empty()) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }
        if (after_hrr) {
            std::vector<binary_t> original_psk_identities;
            const binary_t& original_snapshot = psk_secrets.get(tls_secret_t::client_hello_psk_identities);
            bool valid_identity_snapshot = decode_psk_identities(original_snapshot, original_psk_identities);
            bool valid_identity_order = valid_identity_snapshot;
            size_t original_index = 0;
            // RFC 8446 4.1.4 says clients SHOULD NOT offer PSKs whose hash
            // differs from the HRR-selected cipher suite. The server cannot
            // infer the hash of every identity (for example, an unknown ticket),
            // so validate that ClientHello2 is an ordered subset of ClientHello1
            // without requiring server-side cache metadata to justify omissions.
            for (const auto& identity : current_psk_identities) {
                while (valid_identity_order && (original_index < original_psk_identities.size()) && (original_psk_identities[original_index] != identity)) {
                    ++original_index;
                }
                if (original_index >= original_psk_identities.size()) {
                    valid_identity_order = false;
                    break;
                }
                ++original_index;
            }
            if ((false == valid_identity_order)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        } else {
            psk_secrets.assign(tls_secret_t::client_hello_psk_identities, std::move(current_psk_identity_snapshot));
        }

        // RFC 8446 4.1.4 recommends that ClientHello2 omit PSKs whose hash
        // differs from the HRR-selected suite. Retained identities must remain
        // an ordered subset of ClientHello1; the server may not know the hash
        // of every omitted identity. psk_key_exchange_modes is not an exception:
        // preserve its exact extension encoding across the retry.
        auto ext_psk_modes = get_extensions().get(tls_extension_type_t::psk_key_exchange_modes);
        binary_t current_psk_modes_wire;
        if (nullptr != ext_psk_modes) {
            ret = ext_psk_modes->write(dir, current_psk_modes_wire);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
        }
        if (after_hrr) {
            if (current_psk_modes_wire != psk_secrets.get(tls_secret_t::client_hello_psk_modes)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        } else {
            psk_secrets.assign(tls_secret_t::client_hello_psk_modes, std::move(current_psk_modes_wire));
        }

        uint16 psk_identity_count = t_narrow_cast(current_psk_identities.size());
        session->get_keyvalue().set(session_client_psk_identity_count, psk_identity_count);

        // Preserve the PSK exchange modes and binder hash from this exact
        // ClientHello. ClientHello2 replaces these values after HRR.
        uint8 psk_modes = 0;
        if (nullptr != ext_psk_modes) {
            psk_modes = static_cast<tls_extension_psk_key_exchange_modes*>(ext_psk_modes)->get_modes();
        }
        session->get_keyvalue().set(session_client_psk_modes_present, (nullptr != ext_psk_modes) ? 1 : 0);
        session->get_keyvalue().set(session_client_psk_modes, psk_modes);

        uint16 psk_hash = 0;
        if ((0 != psk_identity_count) && (nullptr != ext_psk_offer)) {
            const tls_cipher_suite_t* psk_suite = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
            if (nullptr != psk_suite) {
                psk_hash = static_cast<uint16>(psk_suite->mac);
            }
        }
        session->get_keyvalue().set(session_client_psk_hash, psk_hash);

        auto& protection_context = protection.get_protection_context();
        {
            for (const auto& cs : _cipher_suites) {
                protection_context.add_cipher_suite(cs);
            }

            auto ext_ver = get_extensions().get(tls_extension_type_t::supported_versions);
            // Keep extension presence distinct from the offered version list: a modern client may offer TLS 1.2 only.
            session->get_keyvalue().set(constexpr_session_client_supported_versions_key, (nullptr != ext_ver) ? 1 : 0);
            if (nullptr == ext_ver) {  // TLS 1.2
                protection_context.add_supported_version(protection.get_lagacy_version());
            }
        }

        {
            // encrypt_then_mac
            auto ext_etm = get_extensions().get(tls_extension_type_t::encrypt_then_mac);
            session->get_keyvalue().set(session_encrypt_then_mac, (ext_etm) ? 1 : 0);

            // enxtended master secret
            auto ext_ems = get_extensions().get(tls_extension_type_t::extended_master_secret);
            session->get_keyvalue().set(session_extended_master_secret, (ext_ems) ? 1 : 0);
        }

        session->update_session_status(session_status_client_hello);

        if ((errorcode_t::success == ret) && (tls_flow_t::zero_rtt == protection.get_flow()) &&
            (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_limit)) &&
            (nullptr != get_extensions().get(tls_extension_type_t::early_data))) {
            // Early data uses the client early traffic secret immediately after ClientHello.
            // Activate only the client direction; ServerHello later activates both handshake directions.
            session->schedule(this);
        }

        if ((tls_io_operation_t::read == opdir) && (from_client == dir) && (tls_flow_t::hello_retry_request == protection.get_flow())) {
            // RFC 8446 4.1.4: when HRR requested a new key share, ClientHello2
            // MUST contain the key_share extension. The entry's group and
            // cardinality are validated while parsing that extension.
            uint16 retry_group = t_narrow_cast(session->get_session_info(from_server).get_keyvalue().get(session_key_share_group));
            if ((t_underlying(tls_group_t::unknown) != retry_group) && (nullptr == get_extensions().get(tls_extension_type_t::key_share))) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        if (tls_io_operation_t::read == opdir) {
            // RFC 8446 4.2.11
            // The "pre_shared_key" extension MUST be the last extension in the
            // ClientHello (this facilitates implementation as described below).
            // Servers MUST check that it is the last extension and otherwise fail
            // the handshake with an "illegal_parameter" alert.
            size_t size = 0;
            std::vector<size_t> indexes;
            auto test = get_extensions().find(tls_extension_type_t::pre_shared_key, indexes, size);
            if (test) {
                if (1 + indexes.back() != size) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
            }
        }

        if (errorcode_t::success == ret) {
            // RFC 9846 4.2.4: ClientHello2 retains the ClientHello1 offer except
            // for the explicitly permitted changes. Do not let CH2 add or remove
            // post_handshake_auth and thereby rewrite the original PHA offer.
            uint16 post_handshake_auth_offer = (nullptr != ext_post_handshake_auth) ? 1 : 0;
            if (tls_flow_t::hello_retry_request == protection.get_flow()) {
                if (post_handshake_auth_offer != session->get_keyvalue().get(session_client_post_handshake_auth)) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
            } else {
                // Record the extension actually sent in the initial ClientHello
                // only after the complete message passes its applicable checks.
                session->get_keyvalue().set(session_client_post_handshake_auth, post_handshake_auth_offer);
            }
        }
    }
    __finally2 {
        if ((tls_io_operation_t::read == opdir) && (from_client == dir)) {
            // The PSK extension verifies its binder before ClientHello
            // postprocessing validates the remaining HRR invariants. Any
            // later failure must roll back that provisional PSK selection,
            // regardless of which invariant rejected ClientHello2.
            if (errorcode_t::success != ret) {
                rollback_client_hello_early_data(get_session(), original_flow);
            }

            // Retire expired server tickets only after the ClientHello's HRR
            // identity-order validation has had access to their hash metadata.
            auto ext_psk = static_cast<tls_extension_client_psk*>(get_extensions().get(tls_extension_type_t::pre_shared_key));
            if (nullptr != ext_psk) {
                ext_psk->retire_expired_tickets();
            }
        }
    }
    return ret;
}

void tls_handshake_client_hello::run_scheduled(tls_direction_t dir) {
    (void)dir;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls13() && (tls_flow_t::zero_rtt == protection.get_flow()) &&
        (nullptr != get_extensions().get(tls_extension_type_t::early_data))) {
        session->get_session_info(from_client).begin_protection();
        session->reset_recordno(from_client);
    }
}

return_t tls_handshake_client_hello::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    bool malformed_extension_vector = false;
    auto session = get_session();
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /* RFC 8446 4.1.2.  Client Hello
         *  uint16 ProtocolVersion;
         *  opaque Random[32];
         *
         *  uint8 CipherSuite[2];    // Cryptographic suite selector
         *
         *  struct {
         *      ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
         *      Random random;
         *      opaque legacy_session_id<0..32>;
         *      CipherSuite cipher_suite_len<2..2^16-2>;
         *      opaque legacy_compression_methods<1..2^8-1>;
         *      Extension extensions<8..2^16-1>;
         *  } ClientHello;
         */

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        const size_t message_end = offsetof_body() + get_body_size();
        if ((message_end > size) || (pos > message_end)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            session->reset_session_status();
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

        auto legacy_version = protection.get_lagacy_version();
#if defined DEBUG
        uint16 version = 0;
#endif
        binary_t random;
        binary_t session_id;
        binary_t cipher_suites;
        binary_t compression_methods;
        // uint8 session_id_len = 0;
        uint16 cipher_suite_len = 0;
        uint8 compression_method_len = 0;
        binary_t cookie;
        uint16 extension_len = 0;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version)                    // TLS 1.2
               << new payload_member(binary_t(), constexpr_random)                          // 32 bytes
               << new payload_member(uint8(0), constexpr_session_id_len)                    //
               << new payload_member(binary_t(), constexpr_session_id)                      //
               << new payload_member(uint8(0), constexpr_cookie_len, constexpr_group_dtls)  // dtls
               << new payload_member(binary_t(), constexpr_cookie, constexpr_group_dtls)    // dtls
               << new payload_member(uint16(0), true, constexpr_cipher_suite_len)           //
               << new payload_member(binary_t(), constexpr_cipher_suite)                    //
               << new payload_member(uint8(0), constexpr_compression_method_len)            //
               << new payload_member(binary_t(), constexpr_compression_method)              //
               << new payload_member(uint16(0), true, constexpr_extension_len);             //

            pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));

            pl.reserve(constexpr_random, 32);
            pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
            pl.set_reference_value(constexpr_cipher_suite, constexpr_cipher_suite_len);
            pl.set_reference_value(constexpr_compression_method, constexpr_compression_method_len);
            pl.set_reference_value(constexpr_cookie, constexpr_cookie_len);  // dtls
            ret = pl.read(stream, message_end, pos);
            if (errorcode_t::success != ret) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            // RFC 8446 4.1.1.  Cryptographic Negotiation
            // -  A list of cipher suites
            // -  A "supported_groups" (Section 4.2.7) extension
            // -  A "signature_algorithms" (Section 4.2.3) extension
            // -  A "pre_shared_key" (Section 4.2.11) extension

#if defined DEBUG
            version = pl.t_value_of<uint16>(constexpr_version);
#endif
            pl.get_binary(constexpr_random, random);
            // session_id_len = pl.t_value_of<uint8>(constexpr_session_id_len);
            pl.get_binary(constexpr_session_id, session_id);
            pl.get_binary(constexpr_cookie, cookie);
            cipher_suite_len = pl.t_value_of<uint16>(constexpr_cipher_suite_len);
            pl.get_binary(constexpr_cipher_suite, cipher_suites);
            compression_method_len = pl.t_value_of<uint8>(constexpr_compression_method_len);
            pl.get_binary(constexpr_compression_method, compression_methods);
            extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
        }

        {
            for (size_t i = 0; i < cipher_suite_len / sizeof(uint16); i++) {
                auto cs = t_binary_to_integer<uint16>(&cipher_suites[i << 1], sizeof(uint16));
                _cipher_suites.push_back(cs);
            }
            for (auto i = 0; i < compression_method_len; i++) {
                auto compr = t_binary_to_integer<uint8>(&compression_methods[i], sizeof(uint8));
                _compression_methods.push_back(compr);
            }
        }

        {
            _random = random;
            _session_id = session_id;
            _cookie = cookie;
            set_extension_len(extension_len);
        }

        {
            // server_key_update
            secrets.assign(tls_secret_t::client_hello_random, std::move(random));
            secrets.assign(tls_secret_t::session_id, std::move(session_id));  // avoid routines:tls_process_server_hello:invalid session id
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                uint16 i = 0;
                t_enum_type<tls_version_t> etversion(version);

                dbs.autoindent(1);
                dbs.println(" > %s 0x%04x (%s)", constexpr_version, etversion, tlsadvisor->nameof_tls_version(etversion).c_str());
                dbs.println(" > %s", constexpr_random);
                if (random.size()) {
                    dbs.println("   %s", base16_encode(random).c_str());
                }
                dbs.println(" > %s %02x(%zi)", constexpr_session_id, session_id.size(), session_id.size());
                if (session_id.size()) {
                    dbs.println("   %s", base16_encode(session_id).c_str());
                }
                dbs.println(" > %s %s", constexpr_cookie, base16_encode(cookie).c_str());
                dbs.println(" > %s %04x(%i ent.)", constexpr_cipher_suite_len, cipher_suite_len, cipher_suite_len >> 1);
                i = 0;
                for (const auto& cs : _cipher_suites) {
                    dbs.println("   [%i] 0x%04x %s", i++, cs, tlsadvisor->nameof_tls_cipher_suite(cs).c_str());
                }
                dbs.println(" > %s %i", constexpr_compression_method_len, compression_method_len);
                i = 0;
                for (const auto& compr : _compression_methods) {
                    dbs.println("   [%i] 0x%02x %s", i++, compr, tlsadvisor->nameof_compression_method(compr).c_str());
                }
                dbs.println(" > %s 0x%04x(%i)", constexpr_extension_len, extension_len, extension_len);
                dbs.autoindent(0);
            });
        }
#endif

        if (0 == extension_len) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        // The extension vector is the final field of ClientHello. Bound it
        // by this handshake message, not by the enclosing record (which may
        // contain bytes belonging to a following handshake message).
        if ((pos > message_end) || (extension_len != message_end - pos)) {
            ret = errorcode_t::bad_format;
            malformed_extension_vector = true;
            __leave2_trace(ret);
        }

        ret = get_extensions().read(this, dir, stream, message_end, pos);
        if (errorcode_t::no_more == ret) {
            // The complete ClientHello has already been assembled and its
            // extension vector is bounded by message_end. A truncated
            // extension header/body here is malformed wire input, not
            // transport fragmentation.
            ret = errorcode_t::bad_format;
            malformed_extension_vector = true;
            __leave2_trace(ret);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (tls_flow_t::renegotiation == protection.get_flow()) {
            // client renegotiation
            auto ext_renegotiationinfo = get_extensions().get(tls_extension_type_t::renegotiation_info);
            if (nullptr == ext_renegotiationinfo) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }
    }
    __finally2 {
        if (malformed_extension_vector) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            session->reset_session_status();
        }
    }
    return ret;
}

return_t tls_handshake_client_hello::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        auto ext_psk_offer = get_extensions().get(tls_extension_type_t::pre_shared_key);
        // tls_extensions::write omits PSK and early_data when preprocessing
        // has selected a full handshake (one_rtt). Validate the PSK offer
        // only when it will actually be serialized; an expired ticket may
        // leave its configured extension object attached to this ClientHello.
        if ((nullptr != ext_psk_offer) && (tls_flow_t::one_rtt != protection.get_flow())) {
            auto ext_psk_modes = get_extensions().get(tls_extension_type_t::psk_key_exchange_modes);
            auto last_extension = get_extensions().getat(get_extensions().size() - 1);
            if ((nullptr == ext_psk_modes) || (0 == static_cast<tls_extension_psk_key_exchange_modes*>(ext_psk_modes)->get_modes()) || (nullptr == last_extension) ||
                (tls_extension_type_t::pre_shared_key != last_extension->get_type())) {
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }
        }

        binary_t extensions;
        ret = get_extensions().write(dir, extensions);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        auto legacy_version = protection.get_lagacy_version();
        binary_t cipher_suites;
        for (const auto& cs : _cipher_suites) {
            binary_append(cipher_suites, cs, hton16);
        }

        binary_t compression_methods;
        compression_methods.resize(1);

        auto session_status = session->get_session_status();
        if (session_status_hello_verify_request & session_status) {
            _random = secrets.get(tls_secret_t::client_hello_random);
        } else {
            openssl_prng prng;
            if (32 != _random.size()) {
                // gmt_unix_time(4 bytes) + random(28 bytes)
                binary_t random;
                time_t gmt_unix_time = time(nullptr);
                uint32 gmt = (uint32)gmt_unix_time;
                binary_append(random, gmt, hton32);
                binary_t temp;
                prng.random(temp, 28);
                binary_append(random, temp);

                _random = std::move(random);
            }
            // if (_session_id.empty()) {
            //     prng.random(_session_id, 32);
            // }
        }

        {
            payload pl;
            pl << new payload_member(uint16(legacy_version), true, constexpr_version)                      //
               << new payload_member(_random, constexpr_random)                                            //
               << new payload_member(uint8(_session_id.size()), constexpr_session_id_len)                  //
               << new payload_member(_session_id, constexpr_session_id)                                    //
               << new payload_member(uint8(_cookie.size()), constexpr_cookie_len, constexpr_group_dtls)    // dtls
               << new payload_member(_cookie, constexpr_cookie, constexpr_group_dtls)                      // dtls
               << new payload_member(uint16(cipher_suites.size()), true, constexpr_cipher_suite_len)       //
               << new payload_member(cipher_suites, constexpr_cipher_suite)                                //
               << new payload_member(uint8(compression_methods.size()), constexpr_compression_method_len)  //
               << new payload_member(compression_methods, constexpr_compression_method)                    //
               << new payload_member(uint16(extensions.size()), true, constexpr_extension_len);            //

            pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));
            ret = pl.write(bin);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
        }

        {
            // finished
            secrets.assign(tls_secret_t::client_hello_random, _random);  // copy
        }

        binary_append(bin, extensions);
    }
    __finally2 {}
    return ret;
}

void tls_handshake_client_hello::set_random(const binary_t& value) { _random = value; }

void tls_handshake_client_hello::set_session_id(const binary_t& value) { _session_id = value; }

void tls_handshake_client_hello::set_cookie(const binary_t& cookie) { _cookie = cookie; }

const binary_t& tls_handshake_client_hello::get_random() { return _random; }

const binary_t& tls_handshake_client_hello::get_session_id() { return _session_id; }

const binary_t& tls_handshake_client_hello::get_cookie() { return _cookie; }

const std::vector<uint16>& tls_handshake_client_hello::get_cipher_suites() { return _cipher_suites; }

const std::vector<uint8>& tls_handshake_client_hello::get_compression_methods() { return _compression_methods; }

return_t tls_handshake_client_hello::add_ciphersuites(const char* ciphersuites) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ciphersuites) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto lambda = [this, &tlsadvisor](const std::string& item) -> void {
            auto hint = tlsadvisor->hintof_cipher_suite(item);
            if (hint && (tls_flag_support & hint->flags)) {
                auto code = hint->code;
                _cipher_suites.push_back(code);
            }
        };

        split_context_t* context = nullptr;
        split_begin(&context, ciphersuites, ":");
        split_foreach(context, lambda);
        split_end(context);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_client_hello::add_ciphersuite(uint16 ciphersuite) {
    return_t ret = errorcode_t::success;
    _cipher_suites.push_back(ciphersuite);
    return ret;
}

tls_handshake_client_hello& tls_handshake_client_hello::operator<<(const std::string& ciphersuites) {
    add_ciphersuites(ciphersuites.c_str());
    return *this;
}

}  // namespace net
}  // namespace hotplace
