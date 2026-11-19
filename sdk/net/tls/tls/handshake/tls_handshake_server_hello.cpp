/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_server_hello.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/system/uint.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr uint16 constexpr_session_client_supported_versions_key = 0x2005;

constexpr char constexpr_version[] = "version";
constexpr char constexpr_random[] = "random";
constexpr char constexpr_session_id_len[] = "session id len";
constexpr char constexpr_session_id[] = "session id";
constexpr char constexpr_cipher_suite[] = "cipher suite";
constexpr char constexpr_compression_method[] = "compression method";
constexpr char constexpr_extension_len[] = "extension len";
constexpr char constexpr_extension[] = "extension";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_cookie_len[] = "cookie len";
constexpr char constexpr_cookie[] = "cookie";

static bool is_hello_retry_request_random(const binary_t& random) {
    static const byte_t hello_retry_request_random[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    };
    if (32 != random.size()) {
        return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (random[i] != hello_retry_request_random[i]) {
            return false;
        }
    }
    return true;
}

static bool is_tls_downgrade_sentinel(const binary_t& random) {
    static const byte_t downgrade_tls12[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    static const byte_t downgrade_tls11[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00};
    if (32 != random.size()) {
        return false;
    }

    bool match_tls12 = true;
    bool match_tls11 = true;
    for (size_t i = 0; i < 8; ++i) {
        match_tls12 = match_tls12 && (random[24 + i] == downgrade_tls12[i]);
        match_tls11 = match_tls11 && (random[24 + i] == downgrade_tls11[i]);
    }
    return match_tls12 || match_tls11;
}

// A failed ServerHello must not leave ClientHello's provisional PSK
// binder state available to the key schedule or a later handshake attempt.
static void rollback_server_hello_psk_state(tls_session* session, tls_flow_t original_flow) {
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
    secrets.assign(tls_secret_t::resumption_early, binary_t());
    secrets.erase(tls_secret_t::resumption_binder_hash);
    secrets.erase(tls_secret_t::resumption_binder_key);
    secrets.erase(tls_secret_t::resumption_finished_key);
    secrets.erase(tls_secret_t::resumption_finished);
    secrets.assign(tls_secret_t::c_e_traffic, binary_t());
    secrets.assign(tls_secret_t::e_exp_master, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t());
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t());
    session->clear_early_data_ticket();
    session->set_offered_resumption_tickets(std::vector<tls_resumption_ticket>());

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

tls_handshake_server_hello::tls_handshake_server_hello(tls_session* session)
    : tls_handshake(tls_handshake_type_t::server_hello, session), _version(tls_version_t{}), _compression_method(0) {}

tls_handshake_server_hello::~tls_handshake_server_hello() {}

void tls_handshake_server_hello::set_version(tls_version_t version) { _version = version; }

void tls_handshake_server_hello::set_random(const binary_t& value) { _random = value; }

void tls_handshake_server_hello::set_session_id(const binary_t& value) { _session_id = value; }

tls_version_t tls_handshake_server_hello::get_version() { return _version; }

const binary_t& tls_handshake_server_hello::get_random() { return _random; }

const binary_t& tls_handshake_server_hello::get_session_id() { return _session_id; }

uint16 tls_handshake_server_hello::get_cipher_suite() {
    uint16 cs = 0;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    cs = protection.get_cipher_suite();
    return cs;
}

return_t tls_handshake_server_hello::set_cipher_suite(uint16 cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (tls_flag_support & hint->flags)) {
            auto test = session->get_keyvalue().get(session_debug_deprecated_ciphersuite);
            if (0 == test) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        auto& protection = session->get_tls_protection();
        // RFC 8446 4.1.4: once HRR selected a cipher suite, the final
        // ServerHello must use that same suite. A second HRR is handled by
        // the normal unexpected_message path and is not constrained here.
        if ((tls_flow_t::hello_retry_request == protection.get_flow()) && (false == is_hello_retry_request_random(_random)) && (cs != protection.get_cipher_suite())) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        protection.set_cipher_suite(cs);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_server_hello::set_cipher_suite(const char* cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cs) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (tls_flag_support & hint->flags)) {
            auto test = session->get_keyvalue().get(session_debug_deprecated_ciphersuite);
            if (0 == test) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        auto& protection = session->get_tls_protection();
        if ((tls_flow_t::hello_retry_request == protection.get_flow()) && (false == is_hello_retry_request_random(_random)) &&
            (hint->code != protection.get_cipher_suite())) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        protection.set_cipher_suite(hint->code);
    }
    __finally2 {}
    return ret;
}

uint8 tls_handshake_server_hello::get_compression_method() { return _compression_method; }

return_t tls_handshake_server_hello::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        auto session = get_session();

        auto session_status = session->get_session_status();
        if (0 == (session_status_client_hello & session_status)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        // TLS 1.3 ServerHello is only valid while the peer's handshake cursor
        // is at ClientHello. The aggregate ClientHello bit remains set after
        // ServerHello, so it cannot by itself reject a duplicate ServerHello
        // coalesced into the same plaintext Handshake record.
        bool is_tls13 = session->get_tls_protection().is_kindof_tls13();
        bool check_status = (tls_handshake_type_t::client_hello != session->get_session_info(from_client).get_status());
        if (is_tls13 && check_status) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::unexpected;
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_server_hello::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        original_flow = protection.get_flow();
        auto& secrets = protection.get_secrets();
        auto& kv = session->get_keyvalue();
        auto session_type = session->get_type();
        auto hspos = offsetof_header();
        auto size_header_body = get_size();
        auto tlsadvisor = tls_advisor::get_instance();
        bool activate_tls13_protection = false;
        auto ext_selected_psk = get_extensions().get(tls_extension_type_t::pre_shared_key);
        bool server_selected_psk = (nullptr != ext_selected_psk);
        bool server_hello_is_hrr = is_hello_retry_request_random(secrets.get(tls_secret_t::server_hello_random));
        if ((tls_io_operation_t::write == opdir) && (from_server == dir) && protection.is_kindof_tls13() && server_selected_psk) {
            // The server verified exactly one cached PSK binder while parsing
            // ClientHello. ServerHello must acknowledge that same wire identity;
            // otherwise the peer derives a different Early Secret and Finished
            // cannot authenticate the handshake.
            auto selected_psk = static_cast<tls_extension_server_psk*>(ext_selected_psk);
            uint16 selected_identity = selected_psk->get_selected_identity();
            uint16 verified_identity = t_narrow_cast(kv.get(session_server_psk_selected_identity));
            uint16 offered_identity_count = t_narrow_cast(kv.get(session_client_psk_identity_count));
            if ((selected_identity >= offered_identity_count) || (selected_identity != verified_identity)) {
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }
        if ((tls_io_operation_t::write == opdir) && (from_server == dir) && protection.is_kindof_tls13() && server_selected_psk && (false == server_hello_is_hrr)) {
            bool server_has_key_share = (nullptr != get_extensions().get(tls_extension_type_t::key_share));
            kv.set(session_server_psk_key_exchange_mode, server_has_key_share ? 1 : 0);
        }
        // EncryptedExtensions may confirm early data only when the selected PSK is identity zero.
        // Keep the ServerHello selection on the client session until that message is processed.
        if ((tls_io_operation_t::read == opdir) && (false == server_hello_is_hrr)) {
            kv.set(session_server_psk_selected_identity, 0xffff);
            kv.set(session_server_psk_key_exchange_mode, 0xffff);
        }

        {
            auto ext_version = get_extensions().get(tls_extension_type_t::supported_versions);
            if (nullptr == ext_version) {
                // TLS 1.2
                protection.set_tls_version(tls_version_t{} != _version ? _version : protection.get_lagacy_version());
            } else {
                // TLS 1.3 supported_versions extension
                // read/write member calls protection.set_tls_version
            }
            if (tls_io_operation_t::read == opdir) {
                // RFC 8446 4.2.1
                auto ver = protection.get_tls_version();

                // RFC 8446 4.2.1
                // A ServerHello supported_versions extension is only valid when TLS 1.3 or later is selected.
                // For TLS 1.2 and earlier, the selected version is carried in ServerHello.legacy_version
                // and the supported_versions extension MUST NOT be sent.
                if (ext_version && false == tlsadvisor->is_specof_tls13_or_later(ver)) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }

                // When supported_versions is absent, the legacy ServerHello version is used.
                // This is the normal TLS 1.2 (or earlier) negotiation path, including when
                // the ClientHello offered supported_versions.
                bool found = false;
                auto lambda = [&ver, &found](tls_version_t v, bool* b) -> void {
                    if (ver == v) {
                        *b = true;
                        found = true;
                    }
                };
                protection.get_protection_context().for_each_supported_versions(lambda);
                if (false == found) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }

                // RFC 8446 4.2.11: validate the selected PSK against the
                // latest ClientHello (ClientHello2 after HelloRetryRequest).
                if (ext_selected_psk) {
                    auto reject_psk_selection = [&]() -> void {
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                        session->reset_session_status();
                        ret = errorcode_t::handshake_failure;
                    };

                    // RFC 8446 4.1.3: HelloRetryRequest MUST NOT contain
                    // pre_shared_key. Its fixed random distinguishes HRR from
                    // an ordinary ServerHello before the handshake flow changes.
                    if (is_hello_retry_request_random(secrets.get(tls_secret_t::server_hello_random))) {
                        reject_psk_selection();
                        __leave2_trace(ret);
                    }

                    auto selected_psk = static_cast<tls_extension_server_psk*>(ext_selected_psk);
                    uint16 offered_identity_count = kv.get(session_client_psk_identity_count);
                    if ((false == protection.is_kindof_tls13()) || (0 == offered_identity_count) || (selected_psk->get_selected_identity() >= offered_identity_count)) {
                        reject_psk_selection();
                        __leave2_trace(ret);
                    }
                    // Do not publish selected_identity until every PSK
                    // selection constraint has been validated. A mode/hash
                    // mismatch is fatal and must not leave a provisional
                    // identity available to a later key-schedule call.

                    // A PSK selection is invalid unless the ClientHello offered
                    // psk_key_exchange_modes and the ServerHello key_share
                    // matches one of those offered modes.
                    uint8 offered_psk_modes = kv.get(session_client_psk_modes);
                    bool offered_psk_modes_extension = (0 != kv.get(session_client_psk_modes_present));
                    bool server_has_key_share = (nullptr != get_extensions().get(tls_extension_type_t::key_share));
                    bool mode_matches =
                        offered_psk_modes_extension && (server_has_key_share ? (0 != (offered_psk_modes & (1u << 1))) : (0 != (offered_psk_modes & (1u << 0))));

                    // TLS 1.3 cipher suites identify the hash used by the PSK
                    // binder. The selected suite must use that same hash.
                    const tls_cipher_suite_t* selected_suite = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());

                    // The selected_identity indexes the identities actually
                    // emitted in the latest ClientHello, not the unfiltered
                    // ticket cache. Restore the matching PSK before the key
                    // schedule consumes resumption_early.
                    std::vector<tls_resumption_ticket> offered_tickets = session->get_offered_resumption_tickets();
                    const tls_resumption_ticket* selected_ticket = nullptr;
                    bool hash_matches = (nullptr != selected_suite);
                    if ((false == offered_tickets.empty())) {
                        uint16 selected_identity = selected_psk->get_selected_identity();
                        if ((offered_tickets.size() != offered_identity_count) || (selected_identity >= offered_tickets.size())) {
                            reject_psk_selection();
                            __leave2_trace(ret);
                        }
                        selected_ticket = &offered_tickets[selected_identity];
                        const tls_cipher_suite_t* ticket_suite = tlsadvisor->hintof_cipher_suite(selected_ticket->cipher_suite);
                        const hint_digest_t* ticket_hash = ticket_suite ? crypto_advisor::get_instance()->hintof_digest(ticket_suite->mac) : nullptr;
                        hash_matches = hash_matches && (nullptr != ticket_suite) && (tls_13 == ticket_suite->spec) && (ticket_suite->mac == selected_suite->mac) &&
                                       (nullptr != ticket_hash) && (selected_ticket->psk.size() == ticket_hash->digest_size);
                    } else {
                        uint16 offered_psk_hash = kv.get(session_client_psk_hash);
                        hash_matches = hash_matches && (0 != offered_psk_hash) && (offered_psk_hash == static_cast<uint16>(selected_suite->mac));
                    }

                    if (false == mode_matches || false == hash_matches) {
                        reject_psk_selection();
                        __leave2_trace(ret);
                    }
                    if (selected_ticket) {
                        binary_t selected_early_secret;
                        ret = protection.calc_resumption_early_secret(selected_ticket->psk, selected_early_secret);
                        if (errorcode_t::success != ret) {
                            reject_psk_selection();
                            __leave2_trace(ret);
                        }
                        secrets.assign(tls_secret_t::resumption_early, std::move(selected_early_secret));
                    }

                    // Commit both peer-selected values only after the
                    // offered mode, suite/hash, and selected ticket are valid
                    // and the selected ticket's Early Secret is available.
                    kv.set(session_server_psk_key_exchange_mode, server_has_key_share ? 1 : 0);
                    kv.set(session_server_psk_selected_identity, selected_psk->get_selected_identity());
                }

                // A ServerHello without pre_shared_key declines the offered
                // resumption PSK. Do not carry the cached ticket's early secret
                // into the full-handshake key schedule. HRR is the exception:
                // ClientHello2 may offer the same PSK again.
                if ((tls_io_operation_t::read == opdir) && protection.is_kindof_tls13() && (false == server_selected_psk) && (false == server_hello_is_hrr)) {
                    // Any final TLS 1.3 ServerHello without pre_shared_key
                    // declines resumption, regardless of whether early data
                    // was offered. Clear both the cached PSK and any
                    // provisional identity before the non-PSK key schedule.
                    // Keep HRR flow until calc() consumes
                    // message_hash || HRR || ClientHello2.
                    kv.set(session_server_psk_selected_identity, 0xffff);
                    kv.set(session_server_psk_key_exchange_mode, 0xffff);
                    kv.set(session_server_psk_ticket_cipher_suite, 0);
                    session->clear_early_data_ticket();
                    auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
                    early_data_state.set(session_early_data_limit, 0);
                    early_data_state.set(session_early_data_accepted, 0);
                    if (tls_flow_t::zero_rtt == protection.get_flow()) {
                        protection.set_flow(tls_flow_t::one_rtt);
                    }
                    secrets.assign(tls_secret_t::resumption_early, binary_t());
                }

                // The offered-ticket copy is only needed until ServerHello
                // selects (or declines) PSK resumption.
                session->set_offered_resumption_tickets(std::vector<tls_resumption_ticket>());

                // RFC 9846 4.2.3: a TLS 1.3 client must reject the downgrade
                // sentinels when a ServerHello selects TLS 1.2 or an earlier version.
                auto tls13_hint = tlsadvisor->hintof_tls_version(tls_13);
                // A TLS 1.2-only supported_versions offer is still from a modern client; legacy ClientHello omits the extension.
                if ((session_type_t::tls == session_type) && kv.get(constexpr_session_client_supported_versions_key) && tls13_hint && tls13_hint->support &&
                    false == tlsadvisor->is_specof_tls13_or_later(ver) && is_tls_downgrade_sentinel(secrets.get(tls_secret_t::server_hello_random))) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
            }
        }

        // On the server, ClientHello binder verification may provisionally
        // select a PSK. The actual selection is signaled only by the final
        // ServerHello pre_shared_key extension; if it is absent, discard that
        // provisional state before calc() chooses the key schedule.
        if ((tls_io_operation_t::write == opdir) && protection.is_kindof_tls13() && (false == server_selected_psk) && (false == server_hello_is_hrr)) {
            kv.set(session_server_psk_selected_identity, 0xffff);
            kv.set(session_server_psk_key_exchange_mode, 0xffff);
            kv.set(session_server_psk_ticket_cipher_suite, 0);
            session->clear_early_data_ticket();
            auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
            early_data_state.set(session_early_data_limit, 0);
            early_data_state.set(session_early_data_accepted, 0);
            if (tls_flow_t::zero_rtt == protection.get_flow()) {
                protection.set_flow(tls_flow_t::one_rtt);
            }
            secrets.assign(tls_secret_t::resumption_early, binary_t());
        }

        {
            // calculates the hash of all handshake messages to this point (ClientHello and ServerHello).
            binary_t hello_hash;
            switch (protection.get_flow()) {
                case tls_flow_t::one_rtt: {
                    protection.reset_transcript_hash(session);

                    const binary_t& client_hello = secrets.get(tls_secret_t::client_hello);
                    protection.update_transcript_hash(session, client_hello.data(), client_hello.size());  // client_hello
                } break;
                case tls_flow_t::zero_rtt:
                case tls_flow_t::hello_retry_request: {
                    if (server_hello_is_hrr) {
                        protection.set_flow(tls_flow_t::hello_retry_request);
                    } else if (server_selected_psk) {
                        auto hs_finished = kv.get(session_handshake_finished);
                        bool after_hrr = (tls_flow_t::hello_retry_request == protection.get_flow());
                        // RFC 8446 4.2.10: early_data is not permitted after
                        // HelloRetryRequest, even when the final ServerHello
                        // selects the same PSK.
                        protection.set_flow((hs_finished && (false == after_hrr)) ? tls_flow_t::zero_rtt : tls_flow_t::one_rtt);
                    } else if (tls_flow_t::zero_rtt == protection.get_flow()) {
                        protection.set_flow(tls_flow_t::one_rtt);
                    }
                    // For a final ServerHello after HRR without PSK, retain
                    // hello_retry_request through calc() to preserve transcript
                    // hashing and use the zero-PSK early secret.

                    auto session_version = kv.get(session_tls_version);
                    auto version = protection.get_tls_version();

                    bool downgrade = (session_type_t::dtls == session_type) ? (session_version < version) : (session_version > version);
                    if (downgrade) {
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::protocol_version);
                        session->reset_session_status();
                        ret = errorcode_t::handshake_failure;
                    }
                } break;
                default:
                    break;
            }
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }

            protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);  // server_hello

            auto test = protection.calc(session, tls_handshake_type_t::server_hello, dir);
            if ((errorcode_t::success != test) && (errorcode_t::warn_retry != test)) {
                // A local ServerHello key-schedule failure is terminal. Do not
                // continue into HRR pending-record processing, which could
                // otherwise overwrite the original error with success.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                session->reset_session_status();
                ret = test;
                __leave2_trace(ret);
            }
            if ((errorcode_t::success == test) && (tls_flow_t::hello_retry_request == protection.get_flow()) && (false == server_hello_is_hrr) &&
                (false == server_selected_psk)) {
                protection.set_flow(tls_flow_t::one_rtt);
            }

            if ((errorcode_t::success == test) && (from_server == dir) && (tls_io_operation_t::write == opdir) && protection.is_kindof_tls13() &&
                (false == server_hello_is_hrr) && (tls_flow_t::zero_rtt == protection.get_flow())) {
                const auto& early_state = session->get_session_info(from_server).get_keyvalue();
                if ((0 != early_state.get(session_early_data_offered)) && (0 == early_state.get(session_early_data_limit))) {
                    // The server already knows 0-RTT is ineligible (e.g. the
                    // selected PSK was not identity zero or its parameters
                    // differ). Switch to handshake keys immediately so
                    // rejected records can be trial-decrypted after ServerHello.
                    protection.set_flow(tls_flow_t::one_rtt);
                }
            }

            // Do not advance either handshake cursor when key-schedule
            // calculation failed. warn_retry is different: it is the expected
            // signal that this ServerHello must be converted into HRR.
            if ((errorcode_t::success == test) || (errorcode_t::warn_retry == test)) {
                session->get_session_info(dir).set_status(get_type());
                session->get_session_info(from_client).set_status(get_type());
            }

            if (errorcode_t::warn_retry == test) {
                if (errorcode_t::warn_retry == ret) {
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        // CLIENT_RANDOM
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection,
                                          [&](basic_stream& dbs) -> void { dbs.println("* " ANSI_ESCAPE "1;33mHelloRetryRequest" ANSI_ESCAPE "0m"); });
                    }
#endif
                }

                // if warn_retry, do HRR

                // RFC 8446 2.1
                // If the client has not provided a sufficient "key_share" extension, the server corrects the mismatch with a
                // HelloRetryRequest and the client needs to restart the handshake with an appropriate "key_share" extension.

                protection.set_flow(tls_flow_t::hello_retry_request);
                if (tls_io_operation_t::read == opdir) {
                    // ClientHello2 is sent in a plaintext Handshake record.
                    // The client may still have 0-RTT write protection enabled
                    // for the client-to-server direction after ClientHello1.
                    // Retire that protection when HRR is accepted; early data
                    // is rejected and cannot continue past HelloRetryRequest.
                    session->get_session_info(from_client).reset_protection();
                    uint32 status = session->get_session_status();
                    if (session_status_hello_retry_request & status) {
                        // RFC 8446 4.1.4.  Hello Retry Request
                        // If a client receives a second HelloRetryRequest in the same connection
                        // (i.e., where the ClientHello was itself in response to a HelloRetryRequest),
                        // it MUST abort the handshake with an "unexpected_message" alert.
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                        session->reset_session_status();
                        ret = errorcode_t::handshake_failure;
                        __leave2_trace(ret);
                        // Leaving this entirely to the client is problematic.
                        // However, defensive handling on the server is also difficult to standardize,
                        // as the TLS specification does not define how a server should handle an attempt to generate a second HelloRetryRequest.
                    }
                }
                session->update_session_status(session_status_hello_retry_request);

                session->clear_session_status(session_status_client_hello);

                /**
                 *    RFC 8446 4.4.1.  The Transcript Hash
                 *
                 *       As an exception to this general rule, when the server responds to a
                 *       ClientHello with a HelloRetryRequest, the value of ClientHello1 is
                 *       replaced with a special synthetic handshake message of handshake type
                 *       "message_hash" containing Hash(ClientHello1).  I.e.,
                 *
                 *       Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
                 *           Hash(message_hash ||        // Handshake type
                 *                00 00 Hash.length  ||  // Handshake message length (bytes)
                 *                Hash(ClientHello1) ||  // Hash of ClientHello1
                 *                HelloRetryRequest  || ... || Mn)
                 */

                binary_t handshake_hash;

                protection.reset_transcript_hash(session);

                // client_hello
                const binary_t& client_hello = secrets.get(tls_secret_t::client_hello);
                protection.calc_transcript_hash(session, client_hello.data(), client_hello.size(), handshake_hash);
                uint32 hashsize = t_narrow_cast(handshake_hash.size());
                // uint8(FE) || uint24(hash.size) || hash
                binary_t synthetic_handshake_message;
                synthetic_handshake_message << uint8(tls_handshake_type_t::message_hash)  //
                                            << uint24_t(hashsize)                         //
                                            << handshake_hash;

                // RFC 9846 4.2.11.2: the synthetic message_hash payload uses
                // the HRR-selected suite hash, while the outer binder transcript
                // may need to be hashed with the PSK's associated hash. Preserve
                // the canonical transcript prefix so calc_context_hash() can
                // rebuild it with the requested algorithm.
                binary_t binder_transcript_prefix = synthetic_handshake_message;
                const byte_t* hrr_message = stream + hspos;
                if (protection.is_kindof_dtls()) {
                    // Keep the TLS-style handshake header and body, excluding
                    // DTLS 1.3 message_seq / fragment_offset / fragment_length.
                    constexpr size_t offset_reconstruction = 12;
                    binder_transcript_prefix.insert(binder_transcript_prefix.end(), hrr_message, hrr_message + sizeof(tls_handshake_t));
                    if (size_header_body > offset_reconstruction) {
                        binder_transcript_prefix.insert(binder_transcript_prefix.end(), hrr_message + offset_reconstruction, hrr_message + size_header_body);
                    }
                } else {
                    binder_transcript_prefix.insert(binder_transcript_prefix.end(), hrr_message, hrr_message + size_header_body);
                }
                secrets.assign(tls_secret_t::hello_retry_request_transcript_prefix, std::move(binder_transcript_prefix));

                protection.reset_transcript_hash(session);

                protection.update_transcript_hash(session, synthetic_handshake_message.data(), synthetic_handshake_message.size());

                // server_hello
                protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);

                secrets.erase(tls_secret_t::client_hello);
            } else {
                ret = test;
                activate_tls13_protection = (errorcode_t::success == test) && (session_type_t::tls == session_type) && protection.is_kindof_tls13();
            }
        }
        if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
            session->reset_recordno(from_server);
        }

        kv.set(session_tls_version, protection.get_tls_version());
        // A failed key-schedule calculation must not commit ServerHello to
        // the aggregate handshake status. HRR's warn_retry is a valid
        // ServerHello outcome and continues through the normal status path.
        if ((errorcode_t::success == ret) || (errorcode_t::warn_retry == ret)) {
            session->update_session_status(session_status_server_hello);
        }
        if ((tls_flow_t::hello_retry_request == protection.get_flow()) && (from_server == dir) && (tls_io_operation_t::write == opdir) &&
            (session_type_t::tls == session_type) && (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial))) {
            // HRR irrevocably rejects 0-RTT. Drain ClientHello1's already-buffered
            // application_data records now, while the HRR flow tells the record
            // reader to skip their external application_data content type.
            ret = session->get_secure_prosumer()->resume_pending_records(session, from_client);
        }
        if (activate_tls13_protection) {
            // Defer activation until the containing ServerHello record has been read/written.
            // On write, this keeps ServerHello itself in the clear; on read, it activates
            // the handshake traffic keys before the next record is processed.
            session->schedule(this);
        }
    }
    __finally2 {
        // A valid HRR is a non-fatal retry result; every other failed
        // ServerHello must discard provisional PSK state.
        if ((from_server == dir) && (errorcode_t::success != ret) && (errorcode_t::warn_retry != ret)) {
            rollback_server_hello_psk_state(get_session(), original_flow);
        }
    }
    return ret;
}

void tls_handshake_server_hello::run_scheduled(tls_direction_t dir) {
    (void)dir;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    if ((session_type_t::tls != session->get_type()) || (false == protection.is_kindof_tls13()) || (tls_flow_t::hello_retry_request == protection.get_flow())) {
        return;
    }

    // TLS 1.3 handshake traffic keys become active after ServerHello, independently
    // of the optional compatibility ChangeCipherSpec record. In 0-RTT, however,
    // the client direction may still be using its early traffic key until
    // EndOfEarlyData; preserve that direction's protection and sequence number.
    auto& client_info = session->get_session_info(from_client);
    bool client_early_data_active = (tls_flow_t::zero_rtt == protection.get_flow()) && client_info.apply_protection();
    if (false == client_early_data_active) {
        client_info.begin_protection();
        session->reset_recordno(from_client);
    }
    auto& server_info = session->get_session_info(from_server);
    server_info.begin_protection();
    session->reset_recordno(from_server);
}

return_t tls_handshake_server_hello::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            /* RFC 8446 4.1.3.  Server Hello */

            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            original_flow = protection.get_flow();
            auto& secrets = protection.get_secrets();
            auto& kv = session->get_keyvalue();
            const size_t body_end = offsetof_body() + get_body_size();
            if ((body_end > size) || (pos > body_end)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }
            auto legacy_version = protection.get_lagacy_version();
            uint16 version = 0;

            binary_t random;
            binary_t session_id;
            // uint8 session_ids = 0;
            uint16 cipher_suite = 0;
#if defined DEBUG
            uint8 compression_method = 0;
#endif
            uint16 extension_len = 0;

            binary_t bin_server_hello;

            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_version)         //
                   << new payload_member(binary_t(), constexpr_random)               //
                   << new payload_member(uint8(0), constexpr_session_id_len)         //
                   << new payload_member(binary_t(), constexpr_session_id)           //
                   << new payload_member(uint16(0), true, constexpr_cipher_suite)    //
                   << new payload_member(uint8(0), constexpr_compression_method)     //
                   << new payload_member(uint16(0), true, constexpr_extension_len);  //

                pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));

                pl.reserve(constexpr_random, 32);
                pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
                ret = pl.read(stream, body_end, pos);
                if (errorcode_t::success != ret) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                    session->reset_session_status();
                    ret = errorcode_t::bad_format;
                    __leave2_trace(ret);
                }

                // RFC 8446 4.1.1.  Cryptographic Negotiation
                // If PSK is being used, ... "pre_shared_key" extension indicating the selected key
                // When (EC)DHE is in use, ... "key_share" extension
                // When authenticating via a certificate, ... Certificate (Section 4.4.2) and CertificateVerify (Section 4.4.3)

                version = pl.t_value_of<uint16>(constexpr_version);

                pl.get_binary(constexpr_random, random);

                // RFC 8446 4.1.4: a second HelloRetryRequest is forbidden.
                // Check the fixed HRR random before parsing extensions: an invalid
                // key_share in the second HRR must not mask the required alert.
                if (is_hello_retry_request_random(random) && (session_status_hello_retry_request & session->get_session_status())) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }

                // session_ids = pl.t_value_of<uint8>(constexpr_session_id_len);
                pl.get_binary(constexpr_session_id, session_id);
                cipher_suite = pl.t_value_of<uint16>(constexpr_cipher_suite);
                // RFC 8446 4.1.4: a final ServerHello after HRR MUST retain
                // the exact cipher suite selected by the HelloRetryRequest.
                if ((tls_flow_t::hello_retry_request == protection.get_flow()) && (false == is_hello_retry_request_random(random)) &&
                    (cipher_suite != protection.get_cipher_suite())) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
#if defined DEBUG
                compression_method = pl.t_value_of<uint8>(constexpr_compression_method);
#endif
                extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
            }

            t_enum_type<tls_version_t> etversion(version);

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                    dbs.autoindent(1);
                    dbs.println(" > %s 0x%04x (%s)", constexpr_version, etversion, tlsadvisor->nameof_tls_version(etversion).c_str());
                    dbs.println(" > %s", constexpr_random);
                    if (random.size()) {
                        // dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
                        dbs.println("   %s", base16_encode(random).c_str());
                    }
                    dbs.println(" > %s", constexpr_session_id);
                    if (session_id.size()) {
                        dbs.println("   %s", base16_encode(session_id).c_str());
                    }
                    dbs.println(" > %s 0x%04x %s", constexpr_cipher_suite, cipher_suite, tlsadvisor->nameof_tls_cipher_suite(cipher_suite).c_str());
                    dbs.println(" > %s %i %s", constexpr_compression_method, compression_method, tlsadvisor->nameof_compression_method(compression_method).c_str());
                    dbs.println(" > %s 0x%02x(%i)", constexpr_extension_len, extension_len, extension_len);
                    dbs.autoindent(0);
                });
            }
#endif

            if ((pos > body_end) || (extension_len != (body_end - pos))) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            if (0 == extension_len) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }

            ret = get_extensions().read(this, dir, stream, body_end, pos);
            if (errorcode_t::no_more == ret) {
                // The ServerHello body is already complete and bounded by
                // body_end. A short trailing extension header is malformed
                // wire input, not an incomplete transport fragment.
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

            // RFC 8449: TLS 1.3 carries record_size_limit in EncryptedExtensions, not ServerHello.
            if (get_extensions().get(tls_extension_type_t::record_size_limit) && get_extensions().get(tls_extension_type_t::supported_versions) &&
                session->get_tls_protection().is_kindof_tls13()) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }

            // encrypt_then_mac
            {
                auto request_etm = kv.get(session_encrypt_then_mac);
                auto ext_etm = get_extensions().get(tls_extension_type_t::encrypt_then_mac);
                if (request_etm) {
                    // client_hello.get_extensions.has(etm extension) && server_hello.get_extensions.has(etm extension)
                    session->get_keyvalue().set(session_encrypt_then_mac, (request_etm && ext_etm) ? 1 : 0);
                } else {
                    if (ext_etm) {
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                        session->reset_session_status();
                        ret = errorcode_t::handshake_failure;
                        __leave2_trace(ret);
                    }
                }
            }
            // extended master secret
            {
                auto request_ems = kv.get(session_extended_master_secret);
                auto ext_ems = get_extensions().get(tls_extension_type_t::extended_master_secret);
                if (request_ems) {
                    // client_hello.get_extensions.has(ems extension) && server_hello.get_extensions.has(ems extension)
                    session->get_keyvalue().set(session_extended_master_secret, (request_ems && ext_ems) ? 1 : 0);
                } else {
                    if (ext_ems) {
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                        session->reset_session_status();
                        ret = errorcode_t::handshake_failure;
                        __leave2_trace(ret);
                    }
                }
            }

            // RFC 8446: the ServerHello cipher suite must be one of the
            // cipher suites offered in the corresponding ClientHello.
            if (protection.is_kindof_tls13()) {
                bool has_offered_cipher_suites = false;
                bool selected_cipher_suite_offered = false;
                protection.get_protection_context().for_each_cipher_suites([&](uint16 offered, bool* stop) -> void {
                    has_offered_cipher_suites = true;
                    if (offered == cipher_suite) {
                        selected_cipher_suite_offered = true;
                        *stop = true;
                    }
                });
                if (has_offered_cipher_suites && (false == selected_cipher_suite_offered)) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    __leave2_trace(ret);
                }
            }

            // cipher_suite
            ret = set_cipher_suite(cipher_suite);
            if (errorcode_t::success != ret) {
                // A peer-selected suite that cannot be resolved or enabled
                // must not be silently replaced by the session's prior suite.
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }

            // server_key_update
            secrets.assign(tls_secret_t::server_hello_random, std::move(random));

            _version = etversion;
        }
    }
    __finally2 {
        if ((from_server == dir) && (errorcode_t::success != ret) && (errorcode_t::no_more != ret)) {
            rollback_server_hello_psk_state(get_session(), original_flow);
        }
    }
    return ret;
}

return_t tls_handshake_server_hello::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_flow_t original_flow = tls_flow_t::one_rtt;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        original_flow = protection.get_flow();
        auto& secrets = protection.get_secrets();
        auto& kv = session->get_keyvalue();
        auto legacy_version = protection.get_lagacy_version();
        auto cs = get_cipher_suite();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);

        // RFC 8446: never emit a TLS 1.3 cipher suite that was not offered
        // by the peer. The ClientHello processing path populates this list.
        if (protection.is_kindof_tls13()) {
            bool has_offered_cipher_suites = false;
            bool selected_cipher_suite_offered = false;
            protection.get_protection_context().for_each_cipher_suites([&](uint16 offered, bool* stop) -> void {
                has_offered_cipher_suites = true;
                if (offered == cs) {
                    selected_cipher_suite_offered = true;
                    *stop = true;
                }
            });
            if (has_offered_cipher_suites && (false == selected_cipher_suite_offered)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        // RFC 8446 4.2.9 and 4.2.11: enforce the server-side selection
        // before serializing a ServerHello. The client performs the same
        // checks on receipt, but that cannot prevent this server from emitting
        // a selection that its peer did not offer.
        if (get_extensions().get(tls_extension_type_t::psk_key_exchange_modes)) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto ext_selected_psk = get_extensions().get(tls_extension_type_t::pre_shared_key);
        if (ext_selected_psk) {
            if ((false == protection.is_kindof_tls13()) || is_hello_retry_request_random(_random)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }

            auto selected_psk = static_cast<tls_extension_server_psk*>(ext_selected_psk);
            uint16 offered_identity_count = kv.get(session_client_psk_identity_count);
            uint16 selected_identity = selected_psk->get_selected_identity();
            uint16 validated_identity = t_narrow_cast(kv.get(session_server_psk_selected_identity));
            if ((0 == offered_identity_count) || (selected_identity >= offered_identity_count) || (selected_identity != validated_identity)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }

            uint8 offered_psk_modes = kv.get(session_client_psk_modes);
            bool offered_psk_modes_extension = (0 != kv.get(session_client_psk_modes_present));
            bool server_has_key_share = (nullptr != get_extensions().get(tls_extension_type_t::key_share));
            bool mode_matches = offered_psk_modes_extension && (server_has_key_share ? (0 != (offered_psk_modes & (1u << 1))) : (0 != (offered_psk_modes & (1u << 0))));
            if ((false == mode_matches)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }

            // The selected PSK's binder hash must match the hash of the
            // cipher suite that this ServerHello will actually negotiate.
            uint16 ticket_cipher_suite = t_narrow_cast(kv.get(session_server_psk_ticket_cipher_suite));
            const tls_cipher_suite_t* ticket_suite = tlsadvisor->hintof_cipher_suite(ticket_cipher_suite);
            if ((nullptr == hint) || (tls_13 != hint->spec) || (nullptr == ticket_suite) || (tls_13 != ticket_suite->spec) || (ticket_suite->mac != hint->mac)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        {
            // encrypt_then_mac
            auto request_etm = kv.get(session_encrypt_then_mac);
            if (request_etm) {
                if (tlsadvisor->is_kindof_cbc(cs)) {
                    auto ext_etm = get_extensions().get(tls_extension_type_t::encrypt_then_mac);
                    if (nullptr == ext_etm) {
                        get_extensions().add(tls_extension_type_t::encrypt_then_mac, dir, this, nullptr);
                    }
                }
            }
            auto ext_etm = get_extensions().get(tls_extension_type_t::encrypt_then_mac);
            // test session_conf_etm && client_hello.get_extensions.has(etm extension) && server_hello.get_extensions.has(etm extension)
            session->get_keyvalue().set(session_encrypt_then_mac, (request_etm && ext_etm) ? 1 : 0);
        }
        {
            // extended master secret
            auto request_ems = kv.get(session_extended_master_secret);
            if (tls_12 == hint->spec) {
                if (request_ems) {
                    auto ext_ems = get_extensions().get(tls_extension_type_t::extended_master_secret);
                    if (nullptr == ext_ems) {
                        get_extensions().add(tls_extension_type_t::extended_master_secret, dir, this, nullptr);
                    }
                }
            }
            auto ext_ems = get_extensions().get(tls_extension_type_t::extended_master_secret);
            // test session_conf_ems && client_hello.get_extensions.has(ems extension) && server_hello.get_extensions.has(ems extension)
            session->get_keyvalue().set(session_extended_master_secret, (request_ems && ext_ems) ? 1 : 0);
        }
        if (tls_12 == hint->spec) {
            // fatal:handshake_failure
            // avoid final_renegotiate:unsafe legacy renegotiation disabled
            auto ext_renego = get_extensions().get(tls_extension_type_t::renegotiation_info);
            if (nullptr == ext_renego) {
                get_extensions().add(tls_extension_type_t::renegotiation_info, dir, this, nullptr);
            }

            // TLS 1.2 server_hello
            // TLS 1.3 encrypted_extensions
            session->select_into_scheduled_extension(&get_extensions(), tls_extension_type_t::alpn);
        }

        // RFC 8449: TLS 1.3 record_size_limit responses belong in EncryptedExtensions.
        if (protection.is_kindof_tls13() && get_extensions().get(tls_extension_type_t::record_size_limit)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t extensions;
        ret = get_extensions().write(dir, extensions);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 8446
        // If there is no overlap between the received "supported_groups" and the groups supported by the server, then the
        // server MUST abort the handshake with a "handshake_failure" or an "insufficient_security" alert.
        auto ext_sg = get_extensions().get(tls_extension_type_t::supported_groups);
        if (ext_sg) {
            tls_extension_supported_groups* ext_sg_casted = (tls_extension_supported_groups*)ext_sg;
            if (0 == ext_sg_casted->numberof_groups()) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        if (32 != _random.size()) {
            // gmt_unix_time(4 bytes) + random(28 bytes)
            openssl_prng prng;
            binary_t random;
            time_t gmt_unix_time = time(nullptr);
            uint32 gmt = (uint32)gmt_unix_time;
            binary_append(random, gmt, hton32);
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);

            _random = std::move(random);

            _session_id = secrets.get(tls_secret_t::session_id);  // avoid routines:tls_process_server_hello:invalid session id
        }

        // RFC 9846 4.2.3: a TLS 1.3 server negotiating TLS 1.2 marks
        // ServerHello.random so a TLS 1.3 client can detect a downgrade.
        if ((session_type_t::tls == session->get_type()) && (tls_12 == hint->spec)) {
            auto tls13_hint = tlsadvisor->hintof_tls_version(tls_13);
            if (tls13_hint && tls13_hint->support) {
                static const byte_t downgrade_tls12[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
                for (size_t i = 0; i < 8; ++i) {
                    _random[24 + i] = downgrade_tls12[i];
                }
            }
        }

        {
            payload pl;
            pl << new payload_member(uint16(_version ? _version : legacy_version), true, constexpr_version)  //
               << new payload_member(_random, constexpr_random)                                              //
               << new payload_member(uint8(_session_id.size()), constexpr_session_id_len)                    //
               << new payload_member(_session_id, constexpr_session_id)                                      //
               << new payload_member(uint16(cs), true, constexpr_cipher_suite)                               //
               << new payload_member(uint8(0), constexpr_compression_method)                                 //
               << new payload_member(uint16(extensions.size()), true, constexpr_extension_len);              //

            pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));
            ret = pl.write(bin);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        secrets.assign(tls_secret_t::server_hello_random, _random);  // copy

        binary_append(bin, extensions);

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                dbs.println("> encrypt_then_mac %i", kv.get(session_encrypt_then_mac) ? 1 : 0);
                dbs.println("> extended master secret %i", kv.get(session_extended_master_secret));
            });
        }
#endif
    }
    __finally2 {
        // do_write_body can reject an inconsistent PSK selection before
        // do_postprocess() is entered. Retire the provisional binder state
        // here as well, so a failed ServerHello write cannot leave it usable.
        if ((from_server == dir) && get_session()->get_tls_protection().is_kindof_tls13() && (errorcode_t::success != ret) && (errorcode_t::warn_retry != ret)) {
            rollback_server_hello_psk_state(get_session(), original_flow);
        }
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
