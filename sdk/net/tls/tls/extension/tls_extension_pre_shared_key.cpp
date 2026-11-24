/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_pre_shared_key.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 *      RFC 4279 Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
 *      RFC 4785 Pre-Shared Key (PSK) Ciphersuites with NULL Encryption for Transport Layer Security (TLS)
 *      RFC 5487 Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
 *      RFC 5489 ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
 *
 *      RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_ke)
 *      RFC 8446 4.2.10.  Early Data Indication
 *      RFC 8446 4.2.11.  Pre-Shared Key Extension
 *
 *      struct {
 *          opaque identity<1..2^16-1>;
 *          uint32 obfuscated_ticket_age;
 *      } PskIdentity;
 *
 *      opaque PskBinderEntry<32..255>;
 *
 *      struct {
 *          PskIdentity identities<7..2^16-1>;
 *          PskBinderEntry binders<33..2^16-1>;
 *      } OfferedPsks;
 *
 *      struct {
 *          select (Handshake.msg_type) {
 *              case client_hello: OfferedPsks;
 *              case server_hello: uint16 selected_identity;
 *          };
 *      } PreSharedKeyExtension;
 *
 *      RFC 9257 Guidance for External Pre-Shared Key (PSK) Usage in TLS
 *
 *      RFC 8446 4.2.11.  Pre-Shared Key Extension
 *
 *          obfuscated_ticket_age
 *          For identities established externally, an obfuscated_ticket_age of 0 SHOULD be used, and servers MUST ignore the value.
 *
 *          For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to SHA-256 if no such algorithm is defined.
 *
 *          Prior to accepting PSK key establishment, the server MUST validate the corresponding binder value.
 *          If this value is not present or does not validate, the server MUST abort the handshake.
 *
 *          Clients MUST verify that the server's selected_identity is within the range supplied by the client, that the server selected a cipher suite
 *          indicating a Hash associated with the PSK, and that a server "key_share" extension is present if required by the ClientHello
 *          "psk_key_exchange_modes" extension.
 *          If these values are not consistent, the client MUST abort the handshake with an "illegal_parameter" alert.
 *
 *          If the server supplies an "early_data" extension, the client MUST verify that the server's selected_identity is 0.
 *          If any other value is returned, the client MUST abort the handshake with an "illegal_parameter" alert.
 *
 *          The "pre_shared_key" extension MUST be the last extension in the ClientHello (this facilitates implementation as described below).
 *          Servers MUST check that it is the last extension and otherwise fail the handshake with an "illegal_parameter" alert.
 *
 * Revision History
 * Date         Name                Description
 */

#include <chrono>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_psk_identities_len[] = "psk identities len";
constexpr char constexpr_psk_identity_len[] = "psk identity len";
constexpr char constexpr_psk_identity[] = "psk identity";
constexpr char constexpr_obfuscated_ticket_age[] = "obfuscated ticket age";
constexpr char constexpr_psk_binders_len[] = "psk binders len";
constexpr char constexpr_psk_binder_len[] = "psk binder len";
constexpr char constexpr_psk_binder[] = "psk binder";
constexpr char constexpr_selected_identity[] = "selected identity";

tls_extension_psk::tls_extension_psk(tls_handshake* handshake) : tls_extension(tls_extension_type_t::pre_shared_key, handshake) {}

tls_extension_psk::~tls_extension_psk() {}

tls_extension_client_psk::tls_extension_client_psk(tls_handshake* handshake)
    : tls_extension_psk(handshake),
      _psk_identities_len(0),
      _obfuscated_ticket_age(0),
      _psk_binders_len(0),
      _binder_list_offset(0),
      _identity_count(0),
      _suppressed(false) {}

tls_extension_client_psk::~tls_extension_client_psk() {}

void tls_extension_client_psk::retire_expired_tickets() {
    if (_expired_ticket_identities.empty()) {
        return;
    }

    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& secrets = protection.get_secrets();
    auto& kv = session->get_session_info(from_server).get_keyvalue();
    bool legacy_ticket_expired = false;
    for (const auto& expired_identity : _expired_ticket_identities) {
        legacy_ticket_expired = legacy_ticket_expired || (_expired_legacy_ticket_identity == expired_identity);
        session->remove_resumption_ticket(expired_identity);
    }
    if (legacy_ticket_expired) {
        auto remaining_tickets = session->get_resumption_tickets();
        if (remaining_tickets.empty()) {
            secrets.assign(tls_secret_t::new_session_ticket, binary_t());
            kv.set(session_ticket_lifetime, 0);
            kv.set(session_ticket_age_add, 0);
            kv.set(session_ticket_timestamp, 0);
        } else {
            const auto& latest_ticket = remaining_tickets.back();
            secrets.assign(tls_secret_t::new_session_ticket, latest_ticket.identity);
            kv.set(session_ticket_lifetime, latest_ticket.lifetime);
            kv.set(session_ticket_age_add, latest_ticket.age_add);
            kv.set(session_ticket_timestamp, latest_ticket.timestamp);
        }
    }
    _expired_ticket_identities.clear();
    _expired_legacy_ticket_identity.clear();
}

void tls_extension_client_psk::set_suppressed(bool suppressed) { _suppressed = suppressed; }

bool tls_extension_client_psk::is_suppressed() const { return _suppressed; }

return_t tls_extension_client_psk::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    _expired_ticket_identities.clear();
    _expired_legacy_ticket_identity.clear();
    __try2 {
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();

        auto& secrets = protection.get_secrets();
        session->get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
        session->get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0);
        auto& server_ticket_state = session->get_session_info(from_server).get_keyvalue();
        bool after_hrr = (tls_flow_t::hello_retry_request == protection.get_flow());
        uint64 early_data_offered = ((false == after_hrr) && (nullptr != get_handshake()->get_extensions().get(tls_extension_type_t::early_data))) ? 1 : 0;
        server_ticket_state.set(session_early_data_limit, 0);
        server_ticket_state.set(session_early_data_received, 0);
        if (false == after_hrr) {
            server_ticket_state.set(session_early_data_offered_initial, early_data_offered);
            server_ticket_state.set(session_early_data_discard_limit, 0);
            server_ticket_state.set(session_early_data_discarded, 0);
        }
        server_ticket_state.set(session_early_data_finished, 0);
        server_ticket_state.set(session_early_data_accepted, 0);
        server_ticket_state.set(session_early_data_offered, early_data_offered);

        // OfferedPsks contains two parallel vectors. Parse every entry and
        // retain the binder corresponding to the first identity we recognize.
        // Do not let a malformed later entry escape validation merely because
        // an earlier identity matched.
        struct psk_identity_entry {
            binary_t identity;
            uint32 obfuscated_ticket_age;
        };
        std::vector<psk_identity_entry> identities;
        std::vector<binary_t> binders;

        const size_t limit = endpos_extension();
        if ((nullptr == stream) || (pos > limit) || (limit > size)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        uint16 identities_length = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_psk_identities_len);
            ret = pl.read(stream, limit, pos);
            if (errorcode_t::success != ret) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            identities_length = pl.t_value_of<uint16>(constexpr_psk_identities_len);
            if ((identities_length < 7) || (identities_length > limit - pos)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        }

        const size_t identities_end = pos + identities_length;
        while (pos < identities_end) {
            psk_identity_entry entry;
            uint16 identity_length = 0;
            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_psk_identity_len) << new payload_member(binary_t(), constexpr_psk_identity)
                   << new payload_member(uint32(0), true, constexpr_obfuscated_ticket_age);
                pl.set_reference_value(constexpr_psk_identity, constexpr_psk_identity_len);
                ret = pl.read(stream, identities_end, pos);
                if (errorcode_t::success != ret) {
                    ret = errorcode_t::bad_format;
                    break;
                }
                identity_length = pl.t_value_of<uint16>(constexpr_psk_identity_len);
                if (0 == identity_length) {
                    ret = errorcode_t::bad_format;
                    break;
                }
                pl.get_binary(constexpr_psk_identity, entry.identity);
                entry.obfuscated_ticket_age = pl.t_value_of<uint32>(constexpr_obfuscated_ticket_age);
            }
            identities.emplace_back(std::move(entry));
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (pos != identities_end) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        uint16 binders_length = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_psk_binders_len);
            ret = pl.read(stream, limit, pos);
            if (errorcode_t::success != ret) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            binders_length = pl.t_value_of<uint16>(constexpr_psk_binders_len);
            if ((binders_length < 33) || (binders_length > limit - pos)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        }

        const size_t binders_end = pos + binders_length;
        while (pos < binders_end) {
            uint8 binder_length = 0;
            binary_t binder;
            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_psk_binder_len) << new payload_member(binary_t(), constexpr_psk_binder);
                pl.set_reference_value(constexpr_psk_binder, constexpr_psk_binder_len);
                ret = pl.read(stream, binders_end, pos);
                if (errorcode_t::success != ret) {
                    ret = errorcode_t::bad_format;
                    break;
                }
                binder_length = pl.t_value_of<uint8>(constexpr_psk_binder_len);
                if (binder_length < 32) {
                    ret = errorcode_t::bad_format;
                    break;
                }
                pl.get_binary(constexpr_psk_binder, binder);
            }
            binders.emplace_back(std::move(binder));
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if ((pos != binders_end) || (pos != limit) || (identities.size() != binders.size())) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        uint16 psk_identities_len = identities_length;
        uint16 psk_binders_len = binders_length;
        size_t selected_index = identities.size();
        uint32 obfuscated_ticket_age = 0;
        uint32 ticket_age = 0;
        uint32 selected_ticket_age_add = 0;
        uint32 selected_ticket_lifetime = 0;
        binary_t psk_identity;
        binary_t psk_binder;
        tls_resumption_ticket selected_ticket;
        bool selected_ticket_from_store = false;
        const binary_t& legacy_ticket = secrets.get(tls_secret_t::new_session_ticket);
        auto& kv = session->get_session_info(from_server).get_keyvalue();
        uint32 legacy_ticket_lifetime = t_narrow_cast(kv.get(session_ticket_lifetime));
        uint32 legacy_ticket_age_add = t_narrow_cast(kv.get(session_ticket_age_add));
        constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
        bool ticket_identity_offered = false;
        std::vector<binary_t> expired_ticket_identities;
        auto cached_tickets = session->get_resumption_tickets();
        // Expire the server's cached records independently of the identities
        // present in this ClientHello. After HRR, the client may have removed
        // hash-incompatible identities from ClientHello2, so those tickets
        // would otherwise never be visited by the selection loop below.
        uint64 ticket_check_now_ms =
            static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        for (const auto& candidate : cached_tickets) {
            uint32 bounded_lifetime = (candidate.lifetime > max_ticket_lifetime) ? max_ticket_lifetime : candidate.lifetime;
            uint64 lifetime_ms = static_cast<uint64>(bounded_lifetime) * 1000;
            bool ticket_timestamp_valid = (0 != candidate.timestamp) && (candidate.timestamp <= ticket_check_now_ms);
            uint64 server_ticket_age = ticket_timestamp_valid ? ticket_check_now_ms - candidate.timestamp : 0;
            if ((false == ticket_timestamp_valid) || (0 == bounded_lifetime) || (server_ticket_age > lifetime_ms)) {
                expired_ticket_identities.emplace_back(candidate.identity);
            }
        }
        // The compatibility singleton has no cache record to visit above.
        // Retire it on the same identity-independent schedule, even when
        // ClientHello omits that identity or offers only an unrelated PSK.
        if (cached_tickets.empty() && (false == legacy_ticket.empty())) {
            uint32 bounded_lifetime = (legacy_ticket_lifetime > max_ticket_lifetime) ? max_ticket_lifetime : legacy_ticket_lifetime;
            uint64 lifetime_ms = static_cast<uint64>(bounded_lifetime) * 1000;
            uint64 legacy_timestamp = kv.get(session_ticket_timestamp);
            bool legacy_timestamp_valid = (0 != legacy_timestamp) && (legacy_timestamp <= ticket_check_now_ms);
            uint64 legacy_ticket_age = legacy_timestamp_valid ? ticket_check_now_ms - legacy_timestamp : 0;
            if ((false == legacy_timestamp_valid) || (0 == bounded_lifetime) || (legacy_ticket_age > lifetime_ms)) {
                expired_ticket_identities.emplace_back(legacy_ticket);
            }
        }
        // Rejected-record skipping has its own ciphertext budget. Do not
        // substitute max_early_data_size here: that ticket field limits
        // plaintext application data and excludes record overhead/padding.
        server_ticket_state.set(session_early_data_discard_limit, session->get_early_data_discard_limit());
        // ClientHello2 carries pre_shared_key but not early_data. Preserve the
        // connection-wide rejected-record count accumulated while handling
        // ClientHello1's in-flight 0-RTT records.
        if (false == after_hrr) {
            server_ticket_state.set(session_early_data_discarded_records, 0);
        }

        // Search the offered identities in client preference order. Each
        // identity is paired with its own age metadata and independently
        // derived PSK; do not consult the most recently received ticket when
        // a different cached identity was offered.
        for (size_t i = 0; i < identities.size() && selected_index == identities.size(); ++i) {
            if ((false == cached_tickets.empty())) {
                for (const auto& candidate : cached_tickets) {
                    if (identities[i].identity != candidate.identity) {
                        continue;
                    }
                    ticket_identity_offered = true;
                    if (std::find(expired_ticket_identities.begin(), expired_ticket_identities.end(), candidate.identity) != expired_ticket_identities.end()) {
                        continue;
                    }
                    // Validate the ticket's original suite metadata before
                    // selecting it. The binder hash comes from that suite, not
                    // from the server's not-yet-negotiated cipher suite.
                    const tls_cipher_suite_t* candidate_suite = tls_advisor::get_instance()->hintof_cipher_suite(candidate.cipher_suite);
                    const hint_digest_t* candidate_hash =
                        (candidate_suite && (tls1_3 == candidate_suite->spec)) ? crypto_advisor::get_instance()->hintof_digest(candidate_suite->mac) : nullptr;
                    if ((nullptr == candidate_hash) || (candidate.psk.size() != candidate_hash->digest_size) || (candidate.psk.size() != binders[i].size())) {
                        continue;
                    }
                    // RFC 8446 4.1.2: after HRR, the selected cipher suite is
                    // fixed. A PSK whose hash differs from that suite cannot
                    // be selected for ClientHello2, even if its binder is
                    // otherwise valid under the ticket's original suite.
                    if (tls_flow_t::hello_retry_request == protection.get_flow()) {
                        const tls_cipher_suite_t* retry_suite = tls_advisor::get_instance()->hintof_cipher_suite(protection.get_cipher_suite());
                        if ((nullptr == retry_suite) || (tls1_3 != retry_suite->spec) || (retry_suite->mac != candidate_suite->mac)) {
                            continue;
                        }
                    }
                    uint32 candidate_age = identities[i].obfuscated_ticket_age - candidate.age_add;
                    selected_index = i;
                    obfuscated_ticket_age = identities[i].obfuscated_ticket_age;
                    ticket_age = candidate_age;
                    selected_ticket_age_add = candidate.age_add;
                    selected_ticket_lifetime = (candidate.lifetime > max_ticket_lifetime) ? max_ticket_lifetime : candidate.lifetime;
                    selected_ticket = candidate;
                    selected_ticket_from_store = true;
                    psk_identity = identities[i].identity;
                    psk_binder = binders[i];
                    break;
                }
            } else if ((false == legacy_ticket.empty())) {
                if (identities[i].identity != legacy_ticket) {
                    continue;
                }
                // The identity belongs to the legacy singleton ticket even
                // when HRR later makes its PSK hash-incompatible. Track that
                // match so the rejected legacy identity and its metadata are
                // retired together with the PSK below.
                ticket_identity_offered = true;
                // The legacy singleton ticket does not retain its original
                // cipher-suite identifier. During HRR, its PSK and binder
                // lengths still provide a safe compatibility check against
                // the already-selected suite hash; do not select a ticket
                // whose digest length cannot match that hash.
                if (tls_flow_t::hello_retry_request == protection.get_flow()) {
                    const tls_cipher_suite_t* retry_suite = tls_advisor::get_instance()->hintof_cipher_suite(protection.get_cipher_suite());
                    const hint_digest_t* retry_hash =
                        (retry_suite && (tls1_3 == retry_suite->spec)) ? crypto_advisor::get_instance()->hintof_digest(retry_suite->mac) : nullptr;
                    const binary_t& legacy_psk = secrets.get(tls_secret_t::resumption_early);
                    if ((nullptr == retry_hash) || (legacy_psk.size() != retry_hash->digest_size) || (binders[i].size() != retry_hash->digest_size)) {
                        continue;
                    }
                }
                uint32 bounded_lifetime = (legacy_ticket_lifetime > max_ticket_lifetime) ? max_ticket_lifetime : legacy_ticket_lifetime;
                uint64 lifetime_ms = static_cast<uint64>(bounded_lifetime) * 1000;
                uint32 candidate_age = identities[i].obfuscated_ticket_age - legacy_ticket_age_add;
                uint64 legacy_timestamp = kv.get(session_ticket_timestamp);
                uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                bool legacy_timestamp_valid = (0 != legacy_timestamp) && (legacy_timestamp <= now_ms);
                uint64 server_ticket_age = legacy_timestamp_valid ? now_ms - legacy_timestamp : 0;
                if ((false == legacy_timestamp_valid) || (0 == bounded_lifetime) || (server_ticket_age > lifetime_ms)) {
                    continue;
                }
                selected_index = i;
                obfuscated_ticket_age = identities[i].obfuscated_ticket_age;
                ticket_age = candidate_age;
                selected_ticket_age_add = legacy_ticket_age_add;
                selected_ticket_lifetime = bounded_lifetime;
                psk_identity = identities[i].identity;
                psk_binder = binders[i];
                break;
            }
        }

        // Keep expired ticket metadata available until ClientHello postprocessing
        // validates ClientHello2's PSK identity ordering against ClientHello1.
        // The records are retired from the cache after that validation.
        _expired_ticket_identities = std::move(expired_ticket_identities);
        _expired_legacy_ticket_identity = secrets.get(tls_secret_t::new_session_ticket);

        bool psk_identity_matched = (selected_index < identities.size());
        bool binder_verified = false;
        if ((false == psk_identity_matched)) {
            // ClientHello2 must retain the HRR transcript even when the
            // server cannot resume the offered PSK.
            if (tls_flow_t::hello_retry_request != protection.get_flow()) {
                protection.set_flow(tls_flow_t::one_rtt);
                session->get_keyvalue().set(session_tls_version, 0);
            }
            secrets.assign(tls_secret_t::resumption_early, binary_t());
            if (ticket_identity_offered && session->get_resumption_tickets().empty()) {
                secrets.assign(tls_secret_t::new_session_ticket, binary_t());
                secrets.assign(tls_secret_t::resumption_early, binary_t());
                kv.set(session_ticket_lifetime, 0);
                kv.set(session_ticket_age_add, 0);
                kv.set(session_ticket_timestamp, 0);
            }
#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    dbs.println("   > ticket age %u ms", ticket_age);
                    dbs.println("   > ticket age add 0x%08x", selected_ticket_age_add);
                    dbs.println("   > ticket lifetime %u sec (effective %u sec)", selected_ticket_lifetime, selected_ticket_lifetime);
                    dbs.println("   > ticket usable false");
                    dbs.println("   > selected PSK identity %u", static_cast<uint32>(selected_index));
                });
            }
#endif
        } else {
#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    dbs.println("   > ticket age %u ms", ticket_age);
                    dbs.println("   > ticket age add 0x%08x", selected_ticket_age_add);
                    dbs.println("   > ticket lifetime %u sec (effective %u sec)", selected_ticket_lifetime, selected_ticket_lifetime);
                    dbs.println("   > ticket usable true");
                    dbs.println("   > selected PSK identity %u", static_cast<uint32>(selected_index));
                });
            }
#endif
        }

        if (psk_identity_matched) {
            uint16 ticket_cipher_suite = selected_ticket_from_store ? selected_ticket.cipher_suite : protection.get_cipher_suite();
            if (0 == ticket_cipher_suite) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            session->get_keyvalue().set(session_server_psk_ticket_cipher_suite, ticket_cipher_suite);
            // Before HRR, the ticket's original suite supplies the
            // provisional early-data/binder hash. After HRR, the cipher suite
            // is already fixed by the server and must remain unchanged; the
            // compatibility check above guarantees that its hash matches the
            // selected ticket's hash.
            if ((tls_flow_t::hello_retry_request != protection.get_flow()) && (protection.get_cipher_suite() != ticket_cipher_suite)) {
                protection.set_cipher_suite(ticket_cipher_suite);
            }

            if (selected_ticket_from_store) {
                binary_t ticket_early_secret;
                ret = protection.calc_resumption_early_secret(selected_ticket.psk, ticket_early_secret);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                secrets.assign(tls_secret_t::resumption_early, std::move(ticket_early_secret));
            }
            size_t content_header_size = protection.is_kindof_tls() ? RTL_FIELD_SIZE(tls_content_t, tls) : RTL_FIELD_SIZE(tls_content_t, dtls);
            auto tlsadvisor = tls_advisor::get_instance();
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
            if (nullptr == hint_tls_alg) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            auto advisor = crypto_advisor::get_instance();
            const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
            if ((nullptr == hint_mac) || (psk_binder.size() != hint_mac->digest_size)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }

            // The transcript hash ends immediately before the binders vector
            // length, independent of which identity's binder is selected.
            size_t binders_length_offset = limit - binders_length - sizeof(uint16);
            // Keep the legacy payload-relative offset convention: the absolute stream position is four bytes beyond the extension-body-relative position.
            size_t binder_hash_offset = binders_length_offset - 4;
            binary_t context_resumption_binder_hash;
            ret = protection.calc_context_hash(session, hint_tls_alg->mac, stream + content_header_size, binder_hash_offset - 1, context_resumption_binder_hash);
            if (errorcode_t::success != ret) {
                ret = errorcode_t::handshake_failure;
                __leave2;
            }

            ret = protection.calc_psk(session, context_resumption_binder_hash, psk_binder);
            if (errorcode_t::success != ret) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decrypt_error);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2;
            }
            binder_verified = true;
            session->get_keyvalue().set(session_server_psk_selected_identity, t_narrow_cast(selected_index));
            // RFC 8446 4.2.10: early data can only use the first offered PSK identity.
            // Tickets without an advertised allowance remain valid for 1-RTT resumption.
            constexpr uint64 early_data_age_tolerance_ms = 10000;
            uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
            uint64 selected_ticket_timestamp = selected_ticket_from_store ? selected_ticket.timestamp : kv.get(session_ticket_timestamp);
            bool ticket_timestamp_valid = (0 != selected_ticket_timestamp) && (selected_ticket_timestamp <= now_ms);
            uint64 server_ticket_age = ticket_timestamp_valid ? now_ms - selected_ticket_timestamp : 0;
            uint64 reported_age_delta = ticket_timestamp_valid ? ((server_ticket_age > ticket_age) ? (server_ticket_age - ticket_age) : (ticket_age - server_ticket_age))
                                                               : early_data_age_tolerance_ms + 1;
            bool early_data_age_valid = ticket_timestamp_valid && (reported_age_delta <= early_data_age_tolerance_ms);
            // ALPN is negotiated while parsing the ClientHello and queued for
            // EncryptedExtensions. Temporarily inspect that selected value,
            // then put the extension back in the scheduled list for serialization.
            binary_t negotiated_alpn;
            tls_extensions scheduled_extensions;
            session->select_into_scheduled_extension(&scheduled_extensions, tls_extension_type_t::application_layer_protocol_negotiation);
            auto scheduled_alpn = static_cast<tls_extension_alpn*>(scheduled_extensions.get(tls_extension_type_t::application_layer_protocol_negotiation));
            if (scheduled_alpn) {
                negotiated_alpn = scheduled_alpn->get_protocols();
                session->schedule_extension(scheduled_alpn);
            }
            // At ClientHello parsing time the server cipher suite may not
            // have been selected yet. Recognize the ticket's allowance here;
            // EncryptedExtensions performs the final suite/ALPN acceptance
            // check after ServerHello negotiation.
            bool early_data_ticket_metadata_match =
                selected_ticket_from_store && (selected_ticket.version == static_cast<uint16>(tls1_3)) && (selected_ticket.alpn == negotiated_alpn);
            bool early_data_acceptable = (tls_flow_t::hello_retry_request != protection.get_flow()) && (0 == selected_index) && selected_ticket_from_store &&
                                         (0 != server_ticket_state.get(session_early_data_offered)) && early_data_age_valid && early_data_ticket_metadata_match &&
                                         (0 != selected_ticket.max_early_data_size);
            // Keep the dedicated early-data ticket only when 0-RTT is actually
            // eligible. HRR still permits PSK resumption, but ClientHello2 cannot
            // carry early_data and must not retain the selected ticket for 0-RTT.
            if (early_data_acceptable) {
                session->set_early_data_ticket(selected_ticket);
            } else {
                session->clear_early_data_ticket();
            }
            server_ticket_state.set(session_early_data_limit, early_data_acceptable ? selected_ticket.max_early_data_size : 0);
            // ClientHello2 remains in the HRR transcript flow after its binder
            // has been verified; the final ServerHello selects the PSK.
            if (tls_flow_t::hello_retry_request != protection.get_flow()) {
                protection.set_flow(tls_flow_t::zero_rtt);
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                dbs.println("   > %s 0x%04x(%i)", constexpr_psk_identities_len, psk_identities_len, psk_identities_len);
                dbs.println("   > %s 0x%04x(%i)", constexpr_psk_binders_len, psk_binders_len, psk_binders_len);
                dbs.println("   > PSK identities %u, binders %u", static_cast<uint32>(identities.size()), static_cast<uint32>(binders.size()));
                dbs.println("   > %s %s", constexpr_psk_binder, base16_encode(psk_binder).c_str());
                dbs.println("   > PSK identity accepted %s", psk_identity_matched ? "true" : "false");
                dbs.println("   > PSK binder verified %s", binder_verified ? "true" : "false");
                dbs.println("   > TLS flow %i", static_cast<int>(protection.get_flow()));
            });
        }
#endif

        _psk_identities_len = psk_identities_len;
        _identity_count = t_narrow_cast(identities.size());
        _identities.clear();
        for (const auto& identity : identities) {
            _identities.emplace_back(identity.identity);
        }
        _psk_identity = std::move(psk_identity);
        _obfuscated_ticket_age = obfuscated_ticket_age;
        _psk_binders_len = psk_binders_len;
        _psk_binder = std::move(psk_binder);
    }
    __finally2 {
        // A failed PSK parse must not leave a ticket-derived secret or
        // provisional selection available to a later handshake step.
        if ((errorcode_t::success != ret) && (errorcode_t::no_more != ret)) {
            auto session = get_handshake()->get_session();
            session->reset_session_status();
            auto& protection = session->get_tls_protection();
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
            session->clear_early_data_ticket();
            auto& early_data_state = session->get_session_info(from_server).get_keyvalue();
            early_data_state.set(session_early_data_offered, 0);
            early_data_state.set(session_early_data_offered_initial, 0);
            early_data_state.set(session_early_data_limit, 0);
            early_data_state.set(session_early_data_accepted, 0);
            if ((tls_flow_t::zero_rtt == protection.get_flow()) || (tls_flow_t::hello_retry_request == protection.get_flow())) {
                protection.set_flow(tls_flow_t::one_rtt);
            }
            // ClientHello postprocessing will not run after an extension
            // parser failure, so retire any expired records discovered here.
            retire_expired_tickets();
        }
    }
    if (errorcode_t::bad_format == ret) {
        // RFC 8446: malformed handshake extension vectors are decoding
        // failures, not merely local parser errors. Terminate the handshake
        // with the corresponding fatal alert.
        auto session = get_handshake()->get_session();
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
        session->reset_session_status();
    }
    return ret;
}

return_t tls_extension_client_psk::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_client != dir) {
            ret = errorcode_t::bad_request;
            __leave2_trace(ret);
        }

        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        auto tlsadvisor = tls_advisor::get_instance();
        auto advisor = crypto_advisor::get_instance();

        constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        binary_t identities;
        binary_t binders;
        std::vector<binary_t> binder_psks;
        std::vector<binary_t> offered_identities;
        std::vector<tls_resumption_ticket> offered_tickets;
        std::vector<tls_resumption_ticket> tickets = session->get_resumption_tickets();
        const binary_t current_server_name = session->get_client_server_name();

        // A resumption binder uses the hash of the cipher suite that
        // established its ticket, not an as-yet-unnegotiated suite on a new
        // client connection. The first usable ticket selects the provisional
        // suite for the early-data key schedule; each offered ticket retains
        // its own suite so its binder can use the corresponding hash.
        const tls_cipher_suite_t* hint_tls_alg = nullptr;
        if ((false == tickets.empty())) {
            for (const auto& ticket : tickets) {
                if (ticket.server_name != current_server_name) {
                    continue;
                }
                uint32 lifetime = (ticket.lifetime > max_ticket_lifetime) ? max_ticket_lifetime : ticket.lifetime;
                uint64 lifetime_ms = static_cast<uint64>(lifetime) * 1000;
                const tls_cipher_suite_t* ticket_suite = tlsadvisor->hintof_cipher_suite(ticket.cipher_suite);
                const hint_digest_t* ticket_hash = (ticket_suite && (tls1_3 == ticket_suite->spec)) ? advisor->hintof_digest(ticket_suite->mac) : nullptr;
                // RFC 8446 4.1.4: after HRR, the client SHOULD offer only PSKs
                // whose hash matches the cipher suite selected by the server.
                // Keep that exact suite for the final ServerHello; a ticket may
                // have been established with another AEAD suite using the same
                // hash, but it must not replace the HRR selection.
                const tls_cipher_suite_t* provisional_suite = ticket_suite;
                if (tls_flow_t::hello_retry_request == protection.get_flow()) {
                    const tls_cipher_suite_t* retry_suite = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
                    if ((nullptr == retry_suite) || (tls1_3 != retry_suite->spec) || (nullptr == ticket_suite) || (retry_suite->mac != ticket_suite->mac)) {
                        continue;
                    }
                    provisional_suite = retry_suite;
                }
                bool offered_hash_compatible = false;
                auto client_hello = static_cast<tls_handshake_client_hello*>(get_handshake());
                if (ticket_suite && client_hello) {
                    for (uint16 offered_code : client_hello->get_cipher_suites()) {
                        const tls_cipher_suite_t* offered_suite = tlsadvisor->hintof_cipher_suite(offered_code);
                        if (offered_suite && (tls1_3 == offered_suite->spec) && (offered_suite->mac == ticket_suite->mac)) {
                            offered_hash_compatible = true;
                            break;
                        }
                    }
                }
                const size_t minimum_psk_extension_size =
                    (nullptr != ticket_hash) ? (sizeof(uint16) * 3 + ticket.identity.size() + sizeof(uint32) + sizeof(uint8) + ticket_hash->digest_size) : 0;
                if ((false == ticket.identity.empty()) && (ticket.identity.size() <= 0xffff) && (0 != lifetime) && (0 != ticket.timestamp) &&
                    (ticket.timestamp <= now_ms) && (now_ms - ticket.timestamp <= lifetime_ms) && (ticket.version == static_cast<uint16>(tls1_3)) && ticket_hash &&
                    offered_hash_compatible && (ticket.psk.size() == ticket_hash->digest_size) && (minimum_psk_extension_size <= 0xffff)) {
                    hint_tls_alg = provisional_suite;
                    break;
                }
            }
        } else {
            hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
        }
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2_trace(ret);
        }
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac || 0 == hint_mac->digest_size || hint_mac->digest_size > 255) {
            ret = errorcode_t::not_supported;
            __leave2_trace(ret);
        }
        if (protection.get_cipher_suite() != hint_tls_alg->code) {
            protection.set_cipher_suite(hint_tls_alg->code);
        }

        if ((false == tickets.empty())) {
            for (const auto& ticket : tickets) {
                if (ticket.server_name != current_server_name) {
                    continue;
                }
                uint32 lifetime = (ticket.lifetime > max_ticket_lifetime) ? max_ticket_lifetime : ticket.lifetime;
                uint64 lifetime_ms = static_cast<uint64>(lifetime) * 1000;
                const tls_cipher_suite_t* ticket_suite = tlsadvisor->hintof_cipher_suite(ticket.cipher_suite);
                const hint_digest_t* ticket_hash = (ticket_suite && (tls1_3 == ticket_suite->spec)) ? advisor->hintof_digest(ticket_suite->mac) : nullptr;
                // Keep ClientHello2's emitted identities aligned with the HRR-selected hash.
                if (tls_flow_t::hello_retry_request == protection.get_flow()) {
                    const tls_cipher_suite_t* retry_suite = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
                    if ((nullptr == retry_suite) || (tls1_3 != retry_suite->spec) || (nullptr == ticket_suite) || (retry_suite->mac != ticket_suite->mac)) {
                        continue;
                    }
                }
                bool offered_hash_compatible = false;
                auto client_hello = static_cast<tls_handshake_client_hello*>(get_handshake());
                if (ticket_suite && client_hello) {
                    for (uint16 offered_code : client_hello->get_cipher_suites()) {
                        const tls_cipher_suite_t* offered_suite = tlsadvisor->hintof_cipher_suite(offered_code);
                        if (offered_suite && (tls1_3 == offered_suite->spec) && (offered_suite->mac == ticket_suite->mac)) {
                            offered_hash_compatible = true;
                            break;
                        }
                    }
                }
                if (ticket.identity.empty() || (ticket.identity.size() > 0xffff) || (0 == lifetime) || (0 == ticket.timestamp) || (ticket.timestamp > now_ms) ||
                    (now_ms - ticket.timestamp > lifetime_ms) || (ticket.version != static_cast<uint16>(tls1_3)) || (nullptr == ticket_hash) ||
                    (false == offered_hash_compatible) || (ticket.psk.size() != ticket_hash->digest_size)) {
                    continue;
                }

                // Keep each appended identity/binder pair within the complete
                // pre_shared_key extension's 16-bit body-length limit. Later
                // cached tickets may still fit even when an earlier one does not.
                const size_t identity_entry_size = sizeof(uint16) + ticket.identity.size() + sizeof(uint32);
                const size_t binder_entry_size = sizeof(uint8) + ticket_hash->digest_size;
                const size_t projected_identity_size = identities.size() + identity_entry_size;
                const size_t projected_binder_size = binders.size() + binder_entry_size;
                const size_t projected_extension_body_size = sizeof(uint16) + projected_identity_size + sizeof(uint16) + projected_binder_size;
                if ((projected_identity_size > 0xffff) || (projected_binder_size > 0xffff) || (projected_extension_body_size > 0xffff)) {
                    continue;
                }

                uint64 age_ms = now_ms - ticket.timestamp;
                uint32 age = t_narrow_cast(age_ms);
                uint32 obfuscated_ticket_age = static_cast<uint32>(age + ticket.age_add);
                payload identity;
                identity << new payload_member(uint16(ticket.identity.size()), true, constexpr_psk_identity_len)
                         << new payload_member(ticket.identity, constexpr_psk_identity)
                         << new payload_member(obfuscated_ticket_age, true, constexpr_obfuscated_ticket_age);
                identity.set_reference_value(constexpr_psk_identity, constexpr_psk_identity_len);
                identity.write(identities);
                offered_identities.emplace_back(ticket.identity);

                binders.push_back(t_narrow_cast(ticket_hash->digest_size));
                binders.insert(binders.end(), ticket_hash->digest_size, 0);
                binder_psks.emplace_back(ticket.psk);
                offered_tickets.emplace_back(ticket);
            }
        } else {
            // Compatibility path for callers that still populate the legacy singleton ticket fields.
            const binary_t& psk_identity = secrets.get(tls_secret_t::new_session_ticket);
            const binary_t& psk = secrets.get(tls_secret_t::resumption_early);
            auto& ticket_kv = session->get_session_info(from_server).get_keyvalue();
            uint32 lifetime = t_narrow_cast(ticket_kv.get(session_ticket_lifetime));
            lifetime = (lifetime > max_ticket_lifetime) ? max_ticket_lifetime : lifetime;
            uint64 lifetime_ms = static_cast<uint64>(lifetime) * 1000;
            uint64 timestamp = ticket_kv.get(session_ticket_timestamp);
            uint32 age_add = t_narrow_cast(ticket_kv.get(session_ticket_age_add));
            if ((false == current_server_name.empty()) || (true == psk_identity.empty()) || (psk_identity.size() > 0xffff) || (true == psk.empty()) ||
                (psk.size() != hint_mac->digest_size) || (0 == lifetime) || (0 == timestamp) || (timestamp > now_ms) || (now_ms - timestamp > lifetime_ms)) {
                ret = errorcode_t::bad_request;
                __leave2_trace(ret);
            }
            const size_t legacy_identity_entry_size = sizeof(uint16) + psk_identity.size() + sizeof(uint32);
            const size_t legacy_binder_entry_size = sizeof(uint8) + hint_mac->digest_size;
            const size_t legacy_extension_body_size = sizeof(uint16) + legacy_identity_entry_size + sizeof(uint16) + legacy_binder_entry_size;
            if (legacy_extension_body_size > 0xffff) {
                ret = errorcode_t::bad_format;
                __leave2_trace(ret);
            }

            uint32 age = t_narrow_cast(now_ms - timestamp);
            uint32 obfuscated_ticket_age = age + age_add;
            payload identity;
            identity << new payload_member(uint16(psk_identity.size()), true, constexpr_psk_identity_len) << new payload_member(psk_identity, constexpr_psk_identity)
                     << new payload_member(obfuscated_ticket_age, true, constexpr_obfuscated_ticket_age);
            identity.set_reference_value(constexpr_psk_identity, constexpr_psk_identity_len);
            identity.write(identities);
            offered_identities.emplace_back(psk_identity);

            binders.push_back(t_narrow_cast(hint_mac->digest_size));
            binders.insert(binders.end(), hint_mac->digest_size, 0);
            binder_psks.emplace_back(psk);
        }
        session->set_offered_resumption_tickets(offered_tickets);
        if ((tls_flow_t::zero_rtt == protection.get_flow()) && (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_limit)) &&
            get_handshake()->get_extensions().get(tls_extension_type_t::early_data) && (false == offered_tickets.empty())) {
            // early_data always uses identity zero. Retain that exact ticket's
            // negotiated parameters for EncryptedExtensions validation.
            session->set_early_data_ticket(offered_tickets.front());
        } else {
            session->clear_early_data_ticket();
        }

        if (binder_psks.empty() || identities.empty() || (identities.size() > 0xffff) || (binders.size() > 0xffff)) {
            ret = errorcode_t::bad_request;
            __leave2_trace(ret);
        }

        size_t extension_body_len = sizeof(uint16) + identities.size() + sizeof(uint16) + binders.size();
        if (extension_body_len > 0xffff) {
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

        uint16 psk_identities_len = t_narrow_cast(identities.size());
        uint16 psk_binders_len = t_narrow_cast(binders.size());
        payload pl;
        pl << new payload_member(psk_identities_len, true, constexpr_psk_identities_len) << new payload_member(identities, constexpr_psk_identity)
           << new payload_member(psk_binders_len, true, constexpr_psk_binders_len) << new payload_member(binders, constexpr_psk_binder);
        _binder_list_offset = pl.offset_of(constexpr_psk_binders_len);
        pl.write(bin);

        _psk_identities_len = psk_identities_len;
        _identity_count = t_narrow_cast(binder_psks.size());
        _identities = std::move(offered_identities);
        _psk_identity.clear();
        _obfuscated_ticket_age = 0;
        _psk_binders_len = psk_binders_len;
        _psk_binder = std::move(binders);
        _binder_psks = std::move(binder_psks);
    }
    __finally2 {}
    return ret;
}

size_t tls_extension_client_psk::get_binder_list_offset() const { return _binder_list_offset; }
const std::vector<binary_t>& tls_extension_client_psk::get_binder_psks() const { return _binder_psks; }
uint16 tls_extension_client_psk::get_identity_count() const { return _identity_count; }
const std::vector<binary_t>& tls_extension_client_psk::get_identities() const { return _identities; }

tls_extension_server_psk::tls_extension_server_psk(tls_handshake* handshake) : tls_extension_psk(handshake), _selected_identity(0) {}

tls_extension_server_psk::~tls_extension_server_psk() {}

uint16 tls_extension_server_psk::get_selected_identity() const { return _selected_identity; }

void tls_extension_server_psk::set_selected_identity(uint16 selected_identity) { _selected_identity = selected_identity; }

return_t tls_extension_server_psk::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        const size_t limit = endpos_extension();
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        if ((nullptr == stream) || (pos > limit) || (limit > size)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        uint16 selected_identity = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_selected_identity);
            ret = pl.read(stream, limit, pos);
            if ((errorcode_t::success != ret) || (pos != limit)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            selected_identity = pl.t_value_of<uint16>(constexpr_selected_identity);
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension,
                              [&](basic_stream& dbs) -> void { dbs.println("   > %s %i", constexpr_selected_identity, selected_identity); });
        }
#endif

        {
            //
            _selected_identity = selected_identity;
        }
    }
    __finally2 {}
    if (errorcode_t::bad_format == ret) {
        // A malformed selected_identity vector is a malformed handshake
        // extension and therefore requires a fatal decode_error alert.
        auto session = get_handshake()->get_session();
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
        session->reset_session_status();
    }
    return ret;
}

return_t tls_extension_server_psk::do_write_body(tls_direction_t dir, binary_t& bin) {
    if (from_server != dir) {
        return errorcode_t::bad_request;
    }

    payload pl;
    pl << new payload_member(uint16(_selected_identity), true, constexpr_selected_identity);
    pl.write(bin);
    return errorcode_t::success;
}

}  // namespace net
}  // namespace hotplace
