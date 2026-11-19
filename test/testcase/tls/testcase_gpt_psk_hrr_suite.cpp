/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk_hrr_suite.cpp
 * @author GPT
 * @desc   TLS 1.3 cipher-suite and PSK-hash continuity across HelloRetryRequest.
 */

#include <algorithm>
#include <chrono>
#include <utility>

#include "testcase_gpt_common.hpp"

static void test_tls13_hrr_rejects_psk_with_incompatible_hash() {
    // Scenario under test: TLS 1.3 HRR does not select a PSK with a different cipher-suite hash.
    // Action: parse a structurally valid SHA-384 PSK offer during a SHA-256 HRR.
    // Expected: consume the complete pre_shared_key extension.
    _test_case.begin("TLS 1.3 HRR does not select a PSK with a different cipher-suite hash");

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& protection = server.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);  // HRR selected TLS_AES_128_GCM_SHA256
    protection.set_flow(tls_flow_t::hello_retry_request);

    tls_resumption_ticket sha384_ticket;
    sha384_ticket.identity = binary_t{0xa1, 0xb2, 0xc3};
    sha384_ticket.psk = binary_t(48, 0x5a);
    sha384_ticket.cipher_suite = 0x1302;  // ticket was established with SHA-384
    sha384_ticket.lifetime = 3600;
    sha384_ticket.age_add = 0x10203040;
    sha384_ticket.timestamp =
        static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - 25;
    server.store_resumption_ticket(sha384_ticket);

    tls_handshake_client_hello hello(&server);
    tls_extension_client_psk psk(&hello);

    // A structurally valid OfferedPsks with one SHA-384-sized binder. The
    // binder need not be verified: HRR's SHA-256 suite must reject the ticket
    // before it can become the selected identity.
    binary_t wire = {
        0x00, 0x29,                                            // pre_shared_key extension
        0x00, 0x3e,                                            // extension body length: 62
        0x00, 0x09,                                            // identities vector length
        0x00, 0x03, 0xa1, 0xb2, 0xc3, 0x00, 0x00, 0x00, 0x19,  // obfuscated_ticket_age
        0x00, 0x31,                                            // binders vector length: 49
        0x30                                                   // binder length: 48
    };
    wire.insert(wire.end(), 48, 0x00);

    size_t pos = 0;
    return_t ret = psk.read(from_client, wire.data(), wire.size(), pos);
    _test_case.test(ret, __FUNCTION__, "parse a structurally valid SHA-384 PSK offer during a SHA-256 HRR");
    _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete pre_shared_key extension");
    _test_case.assert(0xffff == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "do not select a SHA-384 ticket after HRR fixed the handshake hash to SHA-256");
    _test_case.assert(0x1301 == protection.get_cipher_suite(), __FUNCTION__, "preserve the cipher suite selected by HelloRetryRequest");

    // Exercise the compatibility path used by callers that still populate
    // the legacy singleton ticket fields. Its SHA-384-sized PSK must also be
    // declined when HRR has fixed the handshake hash to SHA-256.
    tls_session legacy_server;
    legacy_server.set_type(session_type_t::tls);
    auto& legacy_protection = legacy_server.get_tls_protection();
    legacy_protection.set_tls_version(tls_13);
    legacy_protection.set_cipher_suite(0x1301);
    legacy_protection.set_flow(tls_flow_t::hello_retry_request);
    auto& legacy_secrets = legacy_protection.get_secrets();
    legacy_secrets.assign(tls_secret_t::new_session_ticket, sha384_ticket.identity);
    legacy_secrets.assign(tls_secret_t::resumption_early, sha384_ticket.psk);
    auto& legacy_ticket_kv = legacy_server.get_session_info(from_server).get_keyvalue();
    legacy_ticket_kv.set(session_ticket_lifetime, sha384_ticket.lifetime);
    legacy_ticket_kv.set(session_ticket_age_add, sha384_ticket.age_add);
    legacy_ticket_kv.set(session_ticket_timestamp, sha384_ticket.timestamp);

    tls_handshake_client_hello legacy_hello(&legacy_server);
    tls_extension_client_psk legacy_psk(&legacy_hello);
    pos = 0;
    ret = legacy_psk.read(from_client, wire.data(), wire.size(), pos);
    _test_case.test(ret, __FUNCTION__, "decline a legacy SHA-384 singleton PSK after SHA-256 HRR");
    _test_case.assert(0xffff == legacy_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "do not select a legacy singleton PSK with an incompatible HRR hash");
    _test_case.assert(0x1301 == legacy_protection.get_cipher_suite(), __FUNCTION__, "preserve the HRR cipher suite when declining a legacy singleton PSK");
    _test_case.assert(tls_flow_t::hello_retry_request == legacy_protection.get_flow(), __FUNCTION__,
                      "retain the HRR transcript flow when declining a legacy singleton PSK");
    _test_case.assert(legacy_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "retire the hash-incompatible legacy singleton ticket identity");
    _test_case.assert(legacy_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "clear the rejected legacy singleton PSK");
    _test_case.assert(0 == legacy_ticket_kv.get(session_ticket_lifetime), __FUNCTION__, "clear the rejected legacy singleton ticket lifetime");
    _test_case.assert(0 == legacy_ticket_kv.get(session_ticket_age_add), __FUNCTION__, "clear the rejected legacy singleton ticket age_add");
    _test_case.assert(0 == legacy_ticket_kv.get(session_ticket_timestamp), __FUNCTION__, "clear the rejected legacy singleton ticket timestamp");

    // Expiration of the legacy singleton must not depend on whether its
    // identity appears in the current ClientHello. Offer an unrelated
    // identity and verify the expired singleton is retired after validation.
    {
        tls_session expired_legacy_server;
        expired_legacy_server.set_type(session_type_t::tls);
        auto& expired_legacy_protection = expired_legacy_server.get_tls_protection();
        expired_legacy_protection.set_tls_version(tls_13);
        expired_legacy_protection.set_cipher_suite(0x1301);
        auto& expired_legacy_secrets = expired_legacy_protection.get_secrets();
        const binary_t expired_legacy_identity{0xde, 0xad, 0xbe};
        expired_legacy_secrets.assign(tls_secret_t::new_session_ticket, expired_legacy_identity);
        expired_legacy_secrets.assign(tls_secret_t::resumption_early, binary_t(32, 0x44));
        auto& expired_legacy_kv = expired_legacy_server.get_session_info(from_server).get_keyvalue();
        expired_legacy_kv.set(session_ticket_lifetime, 1);
        expired_legacy_kv.set(session_ticket_age_add, 0x55667788);
        const uint64 expired_now_ms =
            static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        expired_legacy_kv.set(session_ticket_timestamp, expired_now_ms - 2000);

        tls_handshake_client_hello unrelated_hello(&expired_legacy_server);
        tls_extension_client_psk unrelated_psk(&unrelated_hello);
        pos = 0;
        ret = unrelated_psk.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "parse an unrelated PSK identity while an expired legacy singleton ticket is cached");
        if (errorcode_t::success == ret) {
            unrelated_psk.retire_expired_tickets();
        }
        _test_case.assert(expired_legacy_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                          "retire an expired legacy singleton even when ClientHello offers a different identity");
        _test_case.assert(expired_legacy_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                          "clear the PSK associated with an expired unoffered legacy ticket");
        _test_case.assert(0 == expired_legacy_kv.get(session_ticket_lifetime), __FUNCTION__, "clear the expired unoffered legacy ticket lifetime");
        _test_case.assert(0 == expired_legacy_kv.get(session_ticket_age_add), __FUNCTION__, "clear the expired unoffered legacy ticket age_add");
        _test_case.assert(0 == expired_legacy_kv.get(session_ticket_timestamp), __FUNCTION__, "clear the expired unoffered legacy ticket timestamp");
    }

    // Client-side integration: a SHA-256 cached ticket cannot be offered
    // after HRR selects the SHA-384 suite, even though ClientHello1 offered
    // both hashes. ClientHello2 must omit PSK and early_data, but retain its
    // HRR transcript flow and the original psk_key_exchange_modes.
    tls_session incompatible_client;
    incompatible_client.set_type(session_type_t::tls);
    auto& incompatible_protection = incompatible_client.get_tls_protection();
    incompatible_protection.set_tls_version(tls_13);
    incompatible_protection.set_cipher_suite(0x1302);
    incompatible_protection.set_flow(tls_flow_t::hello_retry_request);
    // The ClientHello2 writer regenerates the key share from the group
    // requested by HRR, replacing any key share added to the template.
    incompatible_client.get_session_info(from_server)
        .get_keyvalue()
        .set(session_key_share_group, static_cast<unsigned long long>(tls_advisor::get_instance()->valueof_group("x25519")));
    incompatible_client.get_keyvalue().set(session_tls_version, tls_13);
    incompatible_client.get_keyvalue().set(session_handshake_finished, 1);
    incompatible_client.update_session_status(session_status_server_finished);
    incompatible_client.update_session_status(session_status_client_finished);
    incompatible_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    incompatible_client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

    const binary_t legacy_sha256_identity{0xa1, 0xb2, 0xc3};
    tls_resumption_ticket incompatible_ticket;
    incompatible_ticket.identity = legacy_sha256_identity;
    incompatible_ticket.psk = binary_t(32, 0x33);
    incompatible_ticket.cipher_suite = 0x1301;
    incompatible_ticket.lifetime = 3600;
    incompatible_ticket.age_add = 0x10203040;
    incompatible_ticket.timestamp =
        static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - 25;
    incompatible_ticket.max_early_data_size = 4096;
    incompatible_client.store_resumption_ticket(incompatible_ticket);
    // Model the ticket and identity snapshot retained from ClientHello1.
    incompatible_client.set_offered_resumption_tickets(std::vector<tls_resumption_ticket>{incompatible_ticket});
    incompatible_protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x33));

    binary_t original_identity_snapshot{0x00, 0x03, 0xa1, 0xb2, 0xc3};
    incompatible_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, original_identity_snapshot);
    const tls_cipher_suite_t* original_psk_suite = tls_advisor::get_instance()->hintof_cipher_suite(0x1301);
    _test_case.assert(nullptr != original_psk_suite, __FUNCTION__, "resolve the original SHA-256 PSK cipher suite");
    if (nullptr == original_psk_suite) {
        return;
    }
    const uint16 original_psk_hash = static_cast<uint16>(original_psk_suite->mac);
    incompatible_client.get_keyvalue().set(session_client_psk_hash, original_psk_hash);

    tls_handshake_client_hello modes_template(&incompatible_client);
    tls_extension_psk_key_exchange_modes expected_modes(&modes_template);
    expected_modes.add(0);  // psk_ke
    expected_modes.add(1);  // psk_dhe_ke
    binary_t expected_modes_wire;
    ret = expected_modes.write(from_client, expected_modes_wire);
    _test_case.test(ret, __FUNCTION__, "encode the original PSK key-exchange modes for the HRR continuity check");
    if (errorcode_t::success != ret) {
        return;
    }
    incompatible_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, expected_modes_wire);

    auto incompatible_client_hello = new tls_handshake_client_hello(&incompatible_client);
    incompatible_client_hello->add_ciphersuite(0x1301);
    incompatible_client_hello->add_ciphersuite(0x1302);
    auto incompatible_versions = new tls_extension_client_supported_versions(incompatible_client_hello);
    incompatible_versions->add(tls_13);
    incompatible_client_hello->get_extensions().add(incompatible_versions);
    auto incompatible_groups = new tls_extension_supported_groups(incompatible_client_hello);
    incompatible_groups->add("x25519");
    incompatible_client_hello->get_extensions().add(incompatible_groups);
    auto incompatible_key_share = new tls_extension_client_key_share(incompatible_client_hello);
    incompatible_client_hello->get_extensions().add(incompatible_key_share);
    auto incompatible_modes = new tls_extension_psk_key_exchange_modes(incompatible_client_hello);
    incompatible_modes->add(0);
    incompatible_modes->add(1);
    incompatible_client_hello->get_extensions().add(incompatible_modes);
    incompatible_client_hello->get_extensions().add(new tls_extension_early_data(incompatible_client_hello));
    auto incompatible_psk = new tls_extension_client_psk(incompatible_client_hello);
    incompatible_client_hello->get_extensions().add(incompatible_psk);

    auto incompatible_tlsadvisor = tls_advisor::get_instance();
    ret = incompatible_key_share->add(static_cast<tls_group_t>(incompatible_tlsadvisor->valueof_group("x25519")));
    _test_case.test(ret, __FUNCTION__, "generate the ClientHello2 key share requested by HRR");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incompatible_client_hello_record(&incompatible_client);
    incompatible_client_hello_record << incompatible_client_hello;
    binary_t incompatible_client_hello_wire;
    ret = incompatible_client_hello_record.write(from_client, incompatible_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 after SHA-384 HRR with only a SHA-256 cached ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(tls_flow_t::hello_retry_request == incompatible_protection.get_flow(), __FUNCTION__,
                      "preserve HRR flow when all cached PSKs have an incompatible hash");
    _test_case.assert(incompatible_psk->is_suppressed(), __FUNCTION__, "mark the incompatible ClientHello2 PSK extension as omitted");
    _test_case.assert(0 == incompatible_client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                      "record zero PSK identities for the serialized ClientHello2");
    _test_case.assert(incompatible_client.get_offered_resumption_tickets().empty(), __FUNCTION__, "clear ClientHello1's cached ticket offer when ClientHello2 omits PSK");
    _test_case.assert(0 == incompatible_client.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not record early_data as offered after HRR");

    auto clienthello2_has_extension = [](const binary_t& wire, uint16 target) -> bool {
        if ((wire.size() < 9 + 2 + 32 + 1) || (0x16 != wire[0]) || (0x01 != wire[5])) {
            return false;
        }
        size_t pos = 9 + 2 + 32;
        uint8 session_id_length = wire[pos++];
        if (session_id_length > wire.size() - pos) return false;
        pos += session_id_length;
        if (wire.size() - pos < 2) return false;
        uint16 cipher_suites_length = test_read_u16(wire, pos);
        pos += 2;
        if (cipher_suites_length > wire.size() - pos) return false;
        pos += cipher_suites_length;
        if (pos >= wire.size()) return false;
        uint8 compression_length = wire[pos++];
        if (compression_length > wire.size() - pos) return false;
        pos += compression_length;
        if (wire.size() - pos < 2) return false;
        uint16 extensions_length = test_read_u16(wire, pos);
        pos += 2;
        if (extensions_length != wire.size() - pos) return false;
        size_t end = pos + extensions_length;
        while (pos + 4 <= end) {
            uint16 type = test_read_u16(wire, pos);
            uint16 length = test_read_u16(wire, pos + 2);
            pos += 4;
            if (length > end - pos) return false;
            if (type == target) return true;
            pos += length;
        }
        return false;
    };
    _test_case.assert(false == clienthello2_has_extension(incompatible_client_hello_wire, 0x0029), __FUNCTION__,
                      "omit pre_shared_key entirely when no ticket matches the HRR-selected hash");
    _test_case.assert(false == clienthello2_has_extension(incompatible_client_hello_wire, 0x002a), __FUNCTION__,
                      "omit early_data together with pre_shared_key after HRR");
    _test_case.assert(true == clienthello2_has_extension(incompatible_client_hello_wire, 0x002d), __FUNCTION__,
                      "retain psk_key_exchange_modes unchanged in ClientHello2");

    // The peer must accept the PSK-free ClientHello2 while retaining the
    // HRR transcript and recognizing that the original ticket was removed
    // solely because its hash differs from the selected suite.
    tls_session incompatible_server;
    incompatible_server.set_type(session_type_t::tls);
    auto& incompatible_server_protection = incompatible_server.get_tls_protection();
    incompatible_server_protection.set_tls_version(tls_13);
    incompatible_server_protection.set_cipher_suite(0x1302);
    incompatible_server_protection.set_flow(tls_flow_t::hello_retry_request);
    incompatible_server.get_keyvalue().set(session_tls_version, tls_13);
    incompatible_server.get_keyvalue().set(session_client_psk_identity_count, 1);
    incompatible_server.get_keyvalue().set(session_client_psk_modes_present, 1);
    incompatible_server.get_keyvalue().set(session_client_psk_modes, 0x03);
    incompatible_server.get_keyvalue().set(session_client_psk_hash, original_psk_hash);
    incompatible_server.update_session_status(session_status_server_finished);
    incompatible_server.update_session_status(session_status_client_finished);
    incompatible_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    incompatible_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    incompatible_server.store_resumption_ticket(incompatible_ticket);
    incompatible_server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, original_identity_snapshot);
    incompatible_server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, expected_modes_wire);
    incompatible_server_protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x33));

    tls_records incompatible_server_records;
    ret = incompatible_server_records.read(&incompatible_server, from_client, incompatible_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "accept the PSK-free ClientHello2 after the SHA-384 HRR selection");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::hello_retry_request == incompatible_server_protection.get_flow(), __FUNCTION__,
                          "preserve HRR flow while processing ClientHello2 without PSK");
        _test_case.assert(0 == incompatible_server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                          "record that the peer offered no PSK identities in ClientHello2");
        _test_case.assert(incompatible_server.get_offered_resumption_tickets().empty(), __FUNCTION__,
                          "discard the original ticket offer when the peer omits pre_shared_key");
        _test_case.assert(0xffff == incompatible_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "do not retain a selected PSK identity after ClientHello2 omits PSK");

        // Complete the PSK-free HRR exchange. The final ServerHello must
        // derive a zero-PSK Early Secret and combine it with the fresh
        // ClientHello2 key share on both peers.
        auto incompatible_server_hello = new tls_handshake_server_hello(&incompatible_server);
        ret = incompatible_server_hello->set_cipher_suite(0x1302);
        _test_case.test(ret, __FUNCTION__, "select the SHA-384 suite fixed by HRR for the PSK-free full handshake");
        if (errorcode_t::success == ret) {
            auto incompatible_server_versions = new tls_extension_server_supported_versions(incompatible_server_hello);
            incompatible_server_versions->set(tls_13);
            incompatible_server_hello->get_extensions().add(incompatible_server_versions);

            auto incompatible_server_key_share = new tls_extension_server_key_share(incompatible_server_hello);
            ret = incompatible_server_key_share->add_keyshare();
            _test_case.test(ret, __FUNCTION__, "generate the server DHE share for the PSK-free ClientHello2");
            if (errorcode_t::success == ret) {
                incompatible_server_hello->get_extensions().add(incompatible_server_key_share);
                _test_case.assert(nullptr == incompatible_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                                  "do not select PSK in the final ServerHello after a PSK-free ClientHello2");

                tls_record_handshake incompatible_server_hello_record(&incompatible_server);
                incompatible_server_hello_record << incompatible_server_hello;
                binary_t incompatible_server_hello_wire;
                ret = incompatible_server_hello_record.write(from_server, incompatible_server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "serialize the final non-PSK ServerHello after the hash-incompatible HRR");
                if (errorcode_t::success == ret) {
                    auto& server_protection = incompatible_server.get_tls_protection();
                    auto& server_secrets = server_protection.get_secrets();
                    _test_case.assert(server_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                      "discard the SHA-256 cached PSK before the SHA-384 non-PSK key schedule");
                    _test_case.assert(tls_flow_t::one_rtt == server_protection.get_flow(), __FUNCTION__,
                                      "finish the HRR transcript transition after deriving the non-PSK ServerHello");

                    binary_t expected_zero_psk_early_secret;
                    ret = server_protection.calc_resumption_early_secret(binary_t(48, 0), expected_zero_psk_early_secret);
                    _test_case.test(ret, __FUNCTION__, "independently derive the SHA-384 zero-PSK Early Secret");
                    if (errorcode_t::success == ret) {
                        _test_case.assert(expected_zero_psk_early_secret == server_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                          "use a 48-byte zero PSK for the SHA-384 non-PSK Early Secret");

                        tls_records incompatible_client_serverhello_records;
                        ret = incompatible_client_serverhello_records.read(&incompatible_client, from_server, incompatible_server_hello_wire);
                        _test_case.test(ret, __FUNCTION__, "accept the final non-PSK ServerHello after the PSK-free ClientHello2");
                        if (errorcode_t::success == ret) {
                            auto& client_protection = incompatible_client.get_tls_protection();
                            auto& client_secrets = client_protection.get_secrets();
                            _test_case.assert(client_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                              "discard the client's SHA-256 ticket PSK after the SHA-384 HRR");
                            _test_case.assert(expected_zero_psk_early_secret == client_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                              "derive the same SHA-384 zero-PSK Early Secret on the client");
                            _test_case.assert(server_secrets.get(tls_secret_t::shared_secret) == client_secrets.get(tls_secret_t::shared_secret), __FUNCTION__,
                                              "derive matching DHE shared secrets from the PSK-free ClientHello2");
                            _test_case.assert(server_secrets.get(tls_secret_t::handshake) == client_secrets.get(tls_secret_t::handshake), __FUNCTION__,
                                              "derive matching handshake secrets for the PSK-free HRR exchange");
                            _test_case.assert(server_secrets.get(tls_secret_t::c_hs_traffic) == client_secrets.get(tls_secret_t::c_hs_traffic), __FUNCTION__,
                                              "derive matching client handshake traffic secrets without PSK");
                            _test_case.assert(server_secrets.get(tls_secret_t::s_hs_traffic) == client_secrets.get(tls_secret_t::s_hs_traffic), __FUNCTION__,
                                              "derive matching server handshake traffic secrets without PSK");
                        }
                    }
                }
            }
        }
    }

    // A mixed cache must retain only tickets whose binder hash matches the
    // suite selected by HRR. The compatible ticket may follow an incompatible
    // ticket in the cache; its emitted selected_identity must be renumbered to
    // zero in ClientHello2 rather than preserving its old cache index.
    {
        tls_session mixed_client;
        mixed_client.set_type(session_type_t::tls);
        auto& mixed_protection = mixed_client.get_tls_protection();
        mixed_protection.set_tls_version(tls_13);
        mixed_protection.set_cipher_suite(0x1302);
        mixed_protection.set_flow(tls_flow_t::hello_retry_request);

        // Model the transcript state after a SHA-384 HelloRetryRequest.
        // calc_context_hash() uses this canonical prefix when calculating
        // the ClientHello2 binder with each retained ticket's hash.
        const binary_t mixed_client_hello1_hash(48, 0x66);
        const binary_t mixed_hello_retry_request = {0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0xaa, 0xbb};
        binary_t mixed_transcript_prefix;
        mixed_transcript_prefix << uint8(tls_handshake_type_t::message_hash) << uint24_t(mixed_client_hello1_hash.size()) << mixed_client_hello1_hash;
        mixed_transcript_prefix.insert(mixed_transcript_prefix.end(), mixed_hello_retry_request.begin(), mixed_hello_retry_request.end());
        ret = mixed_protection.reset_transcript_hash(&mixed_client);
        _test_case.test(ret, __FUNCTION__, "reset the mixed-cache transcript for HRR");
        ret = mixed_protection.update_transcript_hash(&mixed_client, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
        _test_case.test(ret, __FUNCTION__, "seed the mixed-cache transcript with message_hash and HelloRetryRequest");
        mixed_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);

        // ClientHello2 replaces the template key share with a fresh share
        // for the group requested by HRR.
        mixed_client.get_session_info(from_server)
            .get_keyvalue()
            .set(session_key_share_group, static_cast<unsigned long long>(tls_advisor::get_instance()->valueof_group("x25519")));
        mixed_client.get_keyvalue().set(session_tls_version, tls_13);
        mixed_client.get_keyvalue().set(session_handshake_finished, 1);
        mixed_client.update_session_status(session_status_server_finished);
        mixed_client.update_session_status(session_status_client_finished);
        mixed_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        mixed_client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        const uint64 mixed_now_ms =
            static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        tls_resumption_ticket mixed_sha256_ticket;
        mixed_sha256_ticket.identity = binary_t{0x31, 0x32, 0x33};
        mixed_sha256_ticket.psk = binary_t(32, 0x44);
        mixed_sha256_ticket.cipher_suite = 0x1301;
        mixed_sha256_ticket.lifetime = 3600;
        mixed_sha256_ticket.timestamp = mixed_now_ms - 25;
        tls_resumption_ticket mixed_unknown_sha384_ticket;
        mixed_unknown_sha384_ticket.identity = binary_t{0x51, 0x52, 0x53};
        mixed_unknown_sha384_ticket.psk = binary_t(48, 0x56);
        mixed_unknown_sha384_ticket.cipher_suite = 0x1302;
        mixed_unknown_sha384_ticket.lifetime = 3600;
        mixed_unknown_sha384_ticket.timestamp = mixed_now_ms - 25;
        tls_resumption_ticket mixed_sha384_ticket;
        mixed_sha384_ticket.identity = binary_t{0x41, 0x42, 0x43};
        mixed_sha384_ticket.psk = binary_t(48, 0x55);
        mixed_sha384_ticket.cipher_suite = 0x1302;
        mixed_sha384_ticket.lifetime = 3600;
        mixed_sha384_ticket.timestamp = mixed_now_ms - 25;
        tls_resumption_ticket mixed_sha256_ticket_late = mixed_sha256_ticket;
        mixed_sha256_ticket_late.identity = binary_t{0x61, 0x62, 0x63};
        mixed_client.store_resumption_ticket(mixed_sha256_ticket);
        mixed_client.store_resumption_ticket(mixed_unknown_sha384_ticket);
        mixed_client.store_resumption_ticket(mixed_sha384_ticket);
        mixed_client.store_resumption_ticket(mixed_sha256_ticket_late);

        // Model the ordered identities retained from ClientHello1. The first
        // and last tickets are hash-incompatible with the HRR suite. The
        // unknown SHA-384 identity remains in ClientHello2 ahead of the
        // server-known SHA-384 ticket, which must therefore be selected as
        // wire identity index one.
        const binary_t mixed_original_identity_snapshot = {0x00, 0x03, 0x31, 0x32, 0x33, 0x00, 0x03, 0x51, 0x52, 0x53,
                                                           0x00, 0x03, 0x41, 0x42, 0x43, 0x00, 0x03, 0x61, 0x62, 0x63};
        mixed_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, mixed_original_identity_snapshot);
        tls_handshake_client_hello mixed_modes_template(&mixed_client);
        tls_extension_psk_key_exchange_modes mixed_expected_modes(&mixed_modes_template);
        mixed_expected_modes.add(0);
        mixed_expected_modes.add(1);
        binary_t mixed_expected_modes_wire;
        ret = mixed_expected_modes.write(from_client, mixed_expected_modes_wire);
        _test_case.test(ret, __FUNCTION__, "encode the original PSK modes for a mixed-hash ticket cache");
        if (errorcode_t::success == ret) {
            mixed_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, mixed_expected_modes_wire);

            auto mixed_hello = new tls_handshake_client_hello(&mixed_client);
            mixed_hello->add_ciphersuite(0x1301);
            mixed_hello->add_ciphersuite(0x1302);
            auto mixed_versions = new tls_extension_client_supported_versions(mixed_hello);
            mixed_versions->add(tls_13);
            mixed_hello->get_extensions().add(mixed_versions);
            auto mixed_groups = new tls_extension_supported_groups(mixed_hello);
            mixed_groups->add("x25519");
            mixed_hello->get_extensions().add(mixed_groups);
            auto mixed_key_share = new tls_extension_client_key_share(mixed_hello);
            mixed_hello->get_extensions().add(mixed_key_share);
            auto mixed_modes = new tls_extension_psk_key_exchange_modes(mixed_hello);
            mixed_modes->add(0);
            mixed_modes->add(1);
            mixed_hello->get_extensions().add(mixed_modes);
            mixed_hello->get_extensions().add(new tls_extension_early_data(mixed_hello));
            auto mixed_psk = new tls_extension_client_psk(mixed_hello);
            mixed_hello->get_extensions().add(mixed_psk);

            auto mixed_tlsadvisor = tls_advisor::get_instance();
            ret = mixed_key_share->add(static_cast<tls_group_t>(mixed_tlsadvisor->valueof_group("x25519")));
            _test_case.test(ret, __FUNCTION__, "generate a fresh ClientHello2 key share for the mixed-hash ticket cache");
            if (errorcode_t::success == ret) {
                tls_record_handshake mixed_hello_record(&mixed_client);
                mixed_hello_record << mixed_hello;
                binary_t mixed_hello_wire;
                ret = mixed_hello_record.write(from_client, mixed_hello_wire);
                _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with mixed SHA-256 and SHA-384 cached tickets");
                if (errorcode_t::success == ret) {
                    const auto& mixed_identities = mixed_psk->get_identities();
                    const auto mixed_offered_tickets = mixed_client.get_offered_resumption_tickets();
                    _test_case.assert(tls_flow_t::hello_retry_request == mixed_protection.get_flow(), __FUNCTION__,
                                      "retain HRR flow when compatible tickets remain after filtering");
                    _test_case.assert(2 == mixed_psk->get_identity_count(), __FUNCTION__,
                                      "retain both SHA-384 identities after filtering the incompatible SHA-256 tickets");
                    _test_case.assert((2 == mixed_identities.size()) && (mixed_unknown_sha384_ticket.identity == mixed_identities[0]) &&
                                          (mixed_sha384_ticket.identity == mixed_identities[1]),
                                      __FUNCTION__, "preserve the unknown SHA-384 identity before the server-known compatible ticket");
                    _test_case.assert((2 == mixed_offered_tickets.size()) && (mixed_unknown_sha384_ticket.identity == mixed_offered_tickets[0].identity) &&
                                          (mixed_sha384_ticket.identity == mixed_offered_tickets[1].identity),
                                      __FUNCTION__, "align the offered-ticket snapshot with both filtered ClientHello2 identities");
                    _test_case.assert(true == clienthello2_has_extension(mixed_hello_wire, 0x0029), __FUNCTION__,
                                      "retain pre_shared_key when at least one ticket matches the HRR-selected hash");
                    _test_case.assert(false == clienthello2_has_extension(mixed_hello_wire, 0x002a), __FUNCTION__,
                                      "omit early_data from ClientHello2 even when a compatible PSK remains");

                    // Scenario under test: ClientHello2 may omit an identity whose ticket
                    // hash remains compatible with the HRR-selected cipher suite. The server
                    // remembers an additional SHA-384 identity from ClientHello1, but the
                    // ClientHello2 writer legitimately omits it while preserving order.
                    {
                        tls_session invalid_order_server;
                        invalid_order_server.set_type(session_type_t::tls);
                        auto& invalid_order_protection = invalid_order_server.get_tls_protection();
                        invalid_order_protection.set_tls_version(tls_13);
                        invalid_order_protection.set_cipher_suite(0x1302);
                        invalid_order_protection.set_flow(tls_flow_t::hello_retry_request);
                        invalid_order_server.get_session_info(from_client).begin_protection();
                        invalid_order_server.get_keyvalue().set(session_tls_version, tls_13);
                        invalid_order_server.update_session_status(session_status_server_finished);
                        invalid_order_server.update_session_status(session_status_client_finished);
                        invalid_order_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                        invalid_order_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

                        tls_resumption_ticket omitted_compatible_sha384_ticket;
                        omitted_compatible_sha384_ticket.identity = binary_t{0x71, 0x72, 0x73};
                        omitted_compatible_sha384_ticket.psk = binary_t(48, 0x57);
                        omitted_compatible_sha384_ticket.version = static_cast<uint16>(tls_13);
                        omitted_compatible_sha384_ticket.cipher_suite = 0x1302;
                        omitted_compatible_sha384_ticket.lifetime = 3600;
                        omitted_compatible_sha384_ticket.timestamp = mixed_now_ms - 25;

                        tls_resumption_ticket expired_mixed_sha256_ticket = mixed_sha256_ticket;
                        expired_mixed_sha256_ticket.lifetime = 1;
                        expired_mixed_sha256_ticket.timestamp = mixed_now_ms - 5000;
                        tls_resumption_ticket expired_mixed_sha256_ticket_late = mixed_sha256_ticket_late;
                        expired_mixed_sha256_ticket_late.lifetime = 1;
                        expired_mixed_sha256_ticket_late.timestamp = mixed_now_ms - 5000;

                        invalid_order_server.store_resumption_ticket(expired_mixed_sha256_ticket);
                        invalid_order_server.store_resumption_ticket(mixed_sha384_ticket);
                        invalid_order_server.store_resumption_ticket(omitted_compatible_sha384_ticket);
                        invalid_order_server.store_resumption_ticket(expired_mixed_sha256_ticket_late);

                        const binary_t invalid_order_identity_snapshot = {
                            0x00, 0x03, 0x31, 0x32, 0x33,  // expired SHA-256 identity (removable)
                            0x00, 0x03, 0x51, 0x52, 0x53,  // unknown compatible SHA-384 identity
                            0x00, 0x03, 0x41, 0x42, 0x43,  // selected SHA-384 identity
                            0x00, 0x03, 0x71, 0x72, 0x73,  // omitted but compatible SHA-384 identity
                            0x00, 0x03, 0x61, 0x62, 0x63   // expired SHA-256 identity (removable)
                        };
                        invalid_order_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, invalid_order_identity_snapshot);
                        invalid_order_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, mixed_expected_modes_wire);
                        invalid_order_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);
                        ret = invalid_order_protection.reset_transcript_hash(&invalid_order_server);
                        _test_case.test(ret, __FUNCTION__, "reset the invalid-order server transcript for HRR");
                        ret = invalid_order_protection.update_transcript_hash(&invalid_order_server, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
                        _test_case.test(ret, __FUNCTION__, "seed the invalid-order server transcript with message_hash and HelloRetryRequest");

                        // ClientHello2 omits one hash-compatible SHA-384 identity but
                        // preserves the relative order of the identities it retains.
                        // RFC 8446 does not require the client to retain every compatible
                        // PSK, so this offer must be accepted rather than treated as an
                        // identity-order violation.
                        tls_records omission_records;
                        return_t omission_ret = omission_records.read(&invalid_order_server, from_client, mixed_hello_wire);
                        _test_case.test(omission_ret, __FUNCTION__, "accept ClientHello2 when it omits one hash-compatible SHA-384 identity");
                        if (errorcode_t::success == omission_ret) {
                            _test_case.assert(2 == invalid_order_server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                                              "record the two PSK identities retained in ClientHello2");
                            _test_case.assert(1 == invalid_order_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                              "select the server-known SHA-384 ticket at its ClientHello2 wire index one");
                            _test_case.assert(0x1302 == invalid_order_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                              "retain the selected SHA-384 ticket cipher suite after compatible identity omission");
                            auto& omission_secrets = invalid_order_protection.get_secrets();
                            binary_t expected_omission_early_secret;
                            ret = invalid_order_protection.calc_resumption_early_secret(binary_t(48, 0x55), expected_omission_early_secret);
                            _test_case.test(ret, __FUNCTION__, "derive the expected Early Secret for the retained SHA-384 identity");
                            if (errorcode_t::success == ret) {
                                _test_case.assert(expected_omission_early_secret == omission_secrets.get(tls_secret_t::resumption_early), __FUNCTION__,
                                                  "derive the PSK Early Secret from the retained identity rather than the omitted ticket");
                            }
                            _test_case.assert(invalid_order_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                                              "do not retain an early-data ticket after HRR ClientHello2");
                        }
                        auto omission_remaining_tickets = invalid_order_server.get_resumption_tickets();
                        _test_case.assert(2 == omission_remaining_tickets.size(), __FUNCTION__,
                                          "retire expired hash-incompatible tickets while accepting compatible identity omission");
                    }

                    // A genuine identity reordering must be rejected only after
                    // the reordered ClientHello2's binders have been verified.
                    // Use an isolated client so this negative test cannot mutate
                    // the mixed-cache client used by the following ServerHello test.
                    {
                        tls_session reordered_client;
                        reordered_client.set_type(session_type_t::tls);
                        auto& reordered_client_protection = reordered_client.get_tls_protection();
                        reordered_client_protection.set_tls_version(tls_13);
                        reordered_client_protection.set_cipher_suite(0x1302);
                        reordered_client_protection.set_flow(tls_flow_t::hello_retry_request);
                        ret = reordered_client_protection.reset_transcript_hash(&reordered_client);
                        _test_case.test(ret, __FUNCTION__, "reset the reordered ClientHello2 client transcript");
                        ret = reordered_client_protection.update_transcript_hash(&reordered_client, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
                        _test_case.test(ret, __FUNCTION__, "seed the reordered ClientHello2 client transcript with message_hash and HRR");
                        reordered_client_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);
                        reordered_client.get_session_info(from_server)
                            .get_keyvalue()
                            .set(session_key_share_group, static_cast<unsigned long long>(tls_advisor::get_instance()->valueof_group("x25519")));
                        reordered_client.get_keyvalue().set(session_tls_version, tls_13);
                        reordered_client.get_keyvalue().set(session_handshake_finished, 1);
                        reordered_client.update_session_status(session_status_server_finished);
                        reordered_client.update_session_status(session_status_client_finished);
                        reordered_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                        reordered_client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

                        // The local writer enforces the HRR ordered-subset rule.
                        // Temporarily model the deliberately reordered identities
                        // as its local ClientHello1 snapshot so it can calculate
                        // genuine binders; restore the peer's actual ClientHello1
                        // order immediately after serialization for server validation.
                        const binary_t reordered_identity_snapshot = {0x00, 0x03, 0x41, 0x42, 0x43, 0x00, 0x03, 0x51, 0x52, 0x53};
                        reordered_client_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, reordered_identity_snapshot);
                        reordered_client_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, mixed_expected_modes_wire);

                        // Reverse the two compatible identities retained from
                        // ClientHello1. The normal writer computes a valid binder
                        // for each ticket in this deliberately invalid order.
                        reordered_client.store_resumption_ticket(mixed_sha384_ticket);
                        reordered_client.store_resumption_ticket(mixed_unknown_sha384_ticket);

                        auto reordered_hello = new tls_handshake_client_hello(&reordered_client);
                        reordered_hello->add_ciphersuite(0x1301);
                        reordered_hello->add_ciphersuite(0x1302);
                        auto reordered_versions = new tls_extension_client_supported_versions(reordered_hello);
                        reordered_versions->add(tls_13);
                        reordered_hello->get_extensions().add(reordered_versions);
                        auto reordered_groups = new tls_extension_supported_groups(reordered_hello);
                        reordered_groups->add("x25519");
                        reordered_hello->get_extensions().add(reordered_groups);
                        auto reordered_key_share = new tls_extension_client_key_share(reordered_hello);
                        reordered_hello->get_extensions().add(reordered_key_share);
                        auto reordered_modes = new tls_extension_psk_key_exchange_modes(reordered_hello);
                        reordered_modes->add(0);
                        reordered_modes->add(1);
                        reordered_hello->get_extensions().add(reordered_modes);
                        reordered_hello->get_extensions().add(new tls_extension_early_data(reordered_hello));
                        auto reordered_psk = new tls_extension_client_psk(reordered_hello);
                        reordered_hello->get_extensions().add(reordered_psk);

                        ret = reordered_key_share->add(static_cast<tls_group_t>(tls_advisor::get_instance()->valueof_group("x25519")));
                        _test_case.test(ret, __FUNCTION__, "generate the reordered ClientHello2 key share");
                        if (errorcode_t::success == ret) {
                            tls_record_handshake reordered_hello_record(&reordered_client);
                            reordered_hello_record << reordered_hello;
                            binary_t reordered_hello_wire;
                            ret = reordered_hello_record.write(from_client, reordered_hello_wire);
                            reordered_client_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, mixed_original_identity_snapshot);
                            _test_case.test(ret, __FUNCTION__, "serialize reordered ClientHello2 with freshly calculated valid PSK binders");
                            if (errorcode_t::success == ret) {
                                const auto& reordered_identities = reordered_psk->get_identities();
                                const auto reordered_offered_tickets = reordered_client.get_offered_resumption_tickets();
                                _test_case.assert((2 == reordered_identities.size()) && (mixed_sha384_ticket.identity == reordered_identities[0]) &&
                                                      (mixed_unknown_sha384_ticket.identity == reordered_identities[1]),
                                                  __FUNCTION__, "emit the selected identity before the earlier unknown ClientHello1 identity");
                                _test_case.assert((2 == reordered_offered_tickets.size()) && (mixed_sha384_ticket.identity == reordered_offered_tickets[0].identity) &&
                                                      (mixed_unknown_sha384_ticket.identity == reordered_offered_tickets[1].identity),
                                                  __FUNCTION__, "align both generated binders with the deliberately reordered identities");

                                tls_session reordered_server;
                                reordered_server.set_type(session_type_t::tls);
                                auto& reordered_server_protection = reordered_server.get_tls_protection();
                                reordered_server_protection.set_tls_version(tls_13);
                                reordered_server_protection.set_cipher_suite(0x1302);
                                reordered_server_protection.set_flow(tls_flow_t::hello_retry_request);
                                reordered_server.get_session_info(from_client).begin_protection();
                                reordered_server.get_keyvalue().set(session_tls_version, tls_13);
                                reordered_server.update_session_status(session_status_server_finished);
                                reordered_server.update_session_status(session_status_client_finished);
                                reordered_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                                reordered_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
                                // The unknown identity is intentionally not in
                                // the server cache. The selected identity is
                                // known, allowing its binder to be verified.
                                reordered_server.store_resumption_ticket(mixed_sha384_ticket);
                                auto& reordered_server_secrets = reordered_server_protection.get_secrets();
                                reordered_server_secrets.assign(tls_secret_t::client_hello_psk_identities, mixed_original_identity_snapshot);
                                reordered_server_secrets.assign(tls_secret_t::client_hello_psk_modes, mixed_expected_modes_wire);
                                reordered_server_secrets.assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);
                                ret = reordered_server_protection.reset_transcript_hash(&reordered_server);
                                _test_case.test(ret, __FUNCTION__, "reset the reordered ClientHello2 server transcript");
                                ret =
                                    reordered_server_protection.update_transcript_hash(&reordered_server, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
                                _test_case.test(ret, __FUNCTION__, "seed the reordered ClientHello2 server transcript with message_hash and HRR");

                                tls_records reordered_server_records;
                                return_t reordered_server_ret = reordered_server_records.read(&reordered_server, from_client, reordered_hello_wire);
                                _test_case.assert(errorcode_t::handshake_failure == reordered_server_ret, __FUNCTION__,
                                                  "reject ClientHello2 when it reorders two identities from ClientHello1");
                                size_t reordered_illegal_parameter_count = 0;
                                size_t reordered_decrypt_error_count = 0;
                                reordered_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                                    if (tls_alertlevel_t::fatal == level) {
                                        if (tls_alertdesc_t::illegal_parameter == desc) {
                                            ++reordered_illegal_parameter_count;
                                        } else if (tls_alertdesc_t::decrypt_error == desc) {
                                            ++reordered_decrypt_error_count;
                                        }
                                    }
                                });
                                _test_case.assert(1 == reordered_illegal_parameter_count, __FUNCTION__,
                                                  "report fatal illegal_parameter for the identity-order violation");
                                _test_case.assert(0 == reordered_decrypt_error_count, __FUNCTION__, "verify the reordered PSK binder before rejecting identity order");
                                _test_case.assert(0 == reordered_server.get_session_status(), __FUNCTION__, "reset handshake status after the identity-order violation");
                                _test_case.assert(false == reordered_server.get_session_info(from_client).apply_protection(), __FUNCTION__,
                                                  "disable residual client-direction protection after identity-order rejection");
                                _test_case.assert(0xffff == reordered_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                                  "roll back the provisionally selected ClientHello2 identity");
                                _test_case.assert(0 == reordered_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                                  "clear the provisionally selected ticket suite after identity-order rejection");
                                _test_case.assert(reordered_server_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                                  "clear the verified PSK Early Secret after identity-order rejection");
                                _test_case.assert(reordered_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                                                  "clear the provisional early-data ticket after identity-order rejection");
                                _test_case.assert(tls_flow_t::one_rtt == reordered_server_protection.get_flow(), __FUNCTION__,
                                                  "leave HRR flow after rejecting reordered ClientHello2");
                            }
                        }
                    }

                    // A different post-binder validation failure must perform the same
                    // rollback. Here ClientHello2 changes psk_key_exchange_modes:
                    // its PSK binder is valid, but the extension differs from ClientHello1.
                    {
                        tls_session invalid_modes_server;
                        invalid_modes_server.set_type(session_type_t::tls);
                        auto& invalid_modes_protection = invalid_modes_server.get_tls_protection();
                        invalid_modes_protection.set_tls_version(tls_13);
                        invalid_modes_protection.set_cipher_suite(0x1302);
                        invalid_modes_protection.set_flow(tls_flow_t::hello_retry_request);
                        invalid_modes_server.get_session_info(from_client).begin_protection();
                        invalid_modes_server.get_keyvalue().set(session_tls_version, tls_13);
                        invalid_modes_server.update_session_status(session_status_server_finished);
                        invalid_modes_server.update_session_status(session_status_client_finished);
                        invalid_modes_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                        invalid_modes_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

                        tls_resumption_ticket expired_modes_sha256_ticket = mixed_sha256_ticket;
                        expired_modes_sha256_ticket.lifetime = 1;
                        expired_modes_sha256_ticket.timestamp = mixed_now_ms - 5000;
                        tls_resumption_ticket expired_modes_sha256_ticket_late = mixed_sha256_ticket_late;
                        expired_modes_sha256_ticket_late.lifetime = 1;
                        expired_modes_sha256_ticket_late.timestamp = mixed_now_ms - 5000;
                        invalid_modes_server.store_resumption_ticket(expired_modes_sha256_ticket);
                        invalid_modes_server.store_resumption_ticket(mixed_sha384_ticket);
                        invalid_modes_server.store_resumption_ticket(expired_modes_sha256_ticket_late);

                        invalid_modes_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, mixed_original_identity_snapshot);
                        tls_handshake_client_hello original_modes_template(&invalid_modes_server);
                        tls_extension_psk_key_exchange_modes original_modes(&original_modes_template);
                        original_modes.add(0);
                        binary_t original_modes_wire;
                        ret = original_modes.write(from_client, original_modes_wire);
                        _test_case.test(ret, __FUNCTION__, "encode the original single-mode ClientHello1 PSK offer");
                        invalid_modes_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, original_modes_wire);
                        invalid_modes_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);
                        ret = invalid_modes_protection.reset_transcript_hash(&invalid_modes_server);
                        _test_case.test(ret, __FUNCTION__, "reset the changed-modes server transcript for HRR");
                        ret = invalid_modes_protection.update_transcript_hash(&invalid_modes_server, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
                        _test_case.test(ret, __FUNCTION__, "seed the changed-modes server transcript with message_hash and HelloRetryRequest");

                        tls_records invalid_modes_records;
                        return_t invalid_modes_ret = invalid_modes_records.read(&invalid_modes_server, from_client, mixed_hello_wire);
                        _test_case.assert(errorcode_t::handshake_failure == invalid_modes_ret, __FUNCTION__,
                                          "reject ClientHello2 when psk_key_exchange_modes differs from ClientHello1");
                        size_t invalid_modes_alert_count = 0;
                        invalid_modes_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                                ++invalid_modes_alert_count;
                            }
                        });
                        _test_case.assert(1 == invalid_modes_alert_count, __FUNCTION__, "report exactly one fatal illegal_parameter for changed PSK key-exchange modes");
                        _test_case.assert(0 == invalid_modes_server.get_session_status(), __FUNCTION__,
                                          "reset handshake status after the changed PSK key-exchange modes");
                        _test_case.assert(false == invalid_modes_server.get_session_info(from_client).apply_protection(), __FUNCTION__,
                                          "disable residual client-direction protection after ClientHello2 PSK-mode failure");
                        _test_case.assert(0xffff == invalid_modes_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                          "clear the provisionally selected identity after the modes mismatch");
                        _test_case.assert(0 == invalid_modes_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                          "clear the provisionally selected ticket suite after the modes mismatch");
                        _test_case.assert(0xffff == invalid_modes_server.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                                          "clear the provisionally selected key-exchange mode after the modes mismatch");
                        auto& invalid_modes_secrets = invalid_modes_protection.get_secrets();
                        _test_case.assert(invalid_modes_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                          "clear the selected PSK Early Secret after the modes mismatch");
                        _test_case.assert(invalid_modes_secrets.get(tls_secret_t::resumption_binder_key).empty(), __FUNCTION__,
                                          "clear the PSK binder key after the modes mismatch");
                        _test_case.assert(invalid_modes_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                                          "clear the provisional early-data ticket after the modes mismatch");
                        _test_case.assert(tls_flow_t::one_rtt == invalid_modes_protection.get_flow(), __FUNCTION__,
                                          "leave HRR flow after rejecting the changed ClientHello2");
                        _test_case.assert(1 == invalid_modes_server.get_resumption_tickets().size(), __FUNCTION__,
                                          "retire expired incompatible tickets after post-binder ClientHello2 rejection");
                    }

                    // Verify the filtered ClientHello2 at the peer as well.
                    // The server retains its expired SHA-256 tickets around the valid SHA-384
                    // ticket, while ClientHello2 retains an unknown SHA-384 identity
                    // before the known one. The server must select wire index one.
                    tls_session mixed_server;
                    mixed_server.set_type(session_type_t::tls);
                    auto& mixed_server_protection = mixed_server.get_tls_protection();
                    mixed_server_protection.set_tls_version(tls_13);
                    mixed_server_protection.set_cipher_suite(0x1302);
                    mixed_server_protection.set_flow(tls_flow_t::hello_retry_request);
                    mixed_server.get_keyvalue().set(session_tls_version, tls_13);
                    mixed_server.update_session_status(session_status_server_finished);
                    mixed_server.update_session_status(session_status_client_finished);
                    mixed_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                    mixed_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
                    tls_resumption_ticket expired_mixed_sha256_ticket = mixed_sha256_ticket;
                    expired_mixed_sha256_ticket.timestamp = mixed_now_ms - (static_cast<uint64>(expired_mixed_sha256_ticket.lifetime) * 1000 + 1000);
                    tls_resumption_ticket expired_mixed_sha256_ticket_late = mixed_sha256_ticket_late;
                    expired_mixed_sha256_ticket_late.timestamp = mixed_now_ms - (static_cast<uint64>(expired_mixed_sha256_ticket_late.lifetime) * 1000 + 1000);
                    // Deliberately place an expired ticket on each side of the
                    // valid ticket. Selection must follow ClientHello2's wire
                    // order, not this server-cache order.
                    mixed_server.store_resumption_ticket(expired_mixed_sha256_ticket);
                    mixed_server.store_resumption_ticket(mixed_sha384_ticket);
                    mixed_server.store_resumption_ticket(expired_mixed_sha256_ticket_late);
                    // The server's ClientHello1 processing records the original
                    // ordered PSK identities. Restore that state before parsing
                    // ClientHello2 so the HRR filter can validate its subsequence.
                    mixed_server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, mixed_original_identity_snapshot);
                    mixed_server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, mixed_expected_modes_wire);
                    mixed_server_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mixed_transcript_prefix);
                    ret = mixed_server_protection.reset_transcript_hash(&mixed_server);
                    _test_case.test(ret, __FUNCTION__, "reset the mixed-cache server transcript for the final ServerHello");
                    ret = mixed_server_protection.update_transcript_hash(&mixed_server, mixed_transcript_prefix.data(), mixed_transcript_prefix.size());
                    _test_case.test(ret, __FUNCTION__, "seed the mixed-cache server transcript with message_hash and HelloRetryRequest");

                    tls_records mixed_server_records;
                    ret = mixed_server_records.read(&mixed_server, from_client, mixed_hello_wire);
                    _test_case.test(ret, __FUNCTION__, "validate the filtered mixed-cache ClientHello2 binder on the server");
                    if (errorcode_t::success == ret) {
                        _test_case.assert(2 == mixed_server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                                          "parse both retained identities from the filtered ClientHello2");
                        _test_case.assert(1 == mixed_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                          "map the server-known SHA-384 ticket to ClientHello2 wire identity one, not its cache index");
                        _test_case.assert(0x1302 == mixed_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                          "retain the selected SHA-384 ticket's original cipher suite");
                        auto mixed_server_remaining_tickets = mixed_server.get_resumption_tickets();
                        _test_case.assert(1 == mixed_server_remaining_tickets.size(), __FUNCTION__,
                                          "prune both expired SHA-256 tickets surrounding the valid cache entry after HRR");
                        if (1 == mixed_server_remaining_tickets.size()) {
                            _test_case.assert(mixed_sha384_ticket.identity == mixed_server_remaining_tickets.front().identity, __FUNCTION__,
                                              "retain the valid SHA-384 ticket selected by filtered ClientHello2 identity one");
                        }
                        binary_t expected_mixed_early_secret;
                        ret = mixed_server_protection.calc_resumption_early_secret(binary_t(48, 0x55), expected_mixed_early_secret);
                        _test_case.test(ret, __FUNCTION__, "independently derive the SHA-384 early secret from the retained ticket PSK");
                        if (errorcode_t::success == ret) {
                            _test_case.assert(expected_mixed_early_secret == mixed_server_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                                              "derive the early secret from the SHA-384 ticket selected at filtered identity one");
                        }
                        _test_case.assert(tls_flow_t::hello_retry_request == mixed_server_protection.get_flow(), __FUNCTION__,
                                          "retain HRR flow after validating the filtered ClientHello2 binder");

                        // Complete the final ServerHello with the nonzero
                        // selected_identity. This checks that the client uses
                        // its offered-ticket snapshot at wire index one when
                        // deriving the PSK+DHE key schedule.
                        auto mixed_server_hello = new tls_handshake_server_hello(&mixed_server);
                        ret = mixed_server_hello->set_cipher_suite(0x1302);
                        _test_case.test(ret, __FUNCTION__, "select the SHA-384 suite for the mixed-cache PSK handshake");
                        if (errorcode_t::success == ret) {
                            auto mixed_server_versions = new tls_extension_server_supported_versions(mixed_server_hello);
                            mixed_server_versions->set(tls_13);
                            mixed_server_hello->get_extensions().add(mixed_server_versions);

                            auto mixed_server_key_share = new tls_extension_server_key_share(mixed_server_hello);
                            ret = mixed_server_key_share->add_keyshare();
                            _test_case.test(ret, __FUNCTION__, "generate the server DHE share for the nonzero PSK identity");
                            if (errorcode_t::success == ret) {
                                mixed_server_hello->get_extensions().add(mixed_server_key_share);
                                auto mixed_server_psk = new tls_extension_server_psk(mixed_server_hello);
                                mixed_server_psk->set_selected_identity(1);
                                mixed_server_hello->get_extensions().add(mixed_server_psk);

                                tls_record_handshake mixed_server_hello_record(&mixed_server);
                                mixed_server_hello_record << mixed_server_hello;
                                binary_t mixed_server_hello_wire;
                                ret = mixed_server_hello_record.write(from_server, mixed_server_hello_wire);
                                _test_case.test(ret, __FUNCTION__, "derive and serialize ServerHello selecting filtered identity one");
                                if (errorcode_t::success == ret) {
                                    _test_case.assert(1 == mixed_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                                      "retain selected_identity one through the server PSK+DHE key schedule");
                                    _test_case.assert(!mixed_server_protection.get_secrets().get(tls_secret_t::shared_secret).empty(), __FUNCTION__,
                                                      "use the ClientHello2 key share with the selected PSK");

                                    tls_records mixed_client_server_hello_records;
                                    ret = mixed_client_server_hello_records.read(&mixed_client, from_server, mixed_server_hello_wire);
                                    _test_case.test(ret, __FUNCTION__, "accept the ServerHello selecting the second filtered PSK identity");
                                    if (errorcode_t::success == ret) {
                                        auto& mixed_client_protection = mixed_client.get_tls_protection();
                                        auto& server_secrets = mixed_server_protection.get_secrets();
                                        auto& client_secrets = mixed_client_protection.get_secrets();
                                        _test_case.assert(1 == mixed_client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                                          "retain selected_identity one on the client");
                                        _test_case.assert(expected_mixed_early_secret == client_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                                          "restore the second offered ticket's PSK for the client Early Secret");
                                        _test_case.assert(server_secrets.get(tls_secret_t::early_secret) == client_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                                          "derive matching PSK Early Secrets for selected identity one");
                                        _test_case.assert(server_secrets.get(tls_secret_t::shared_secret) == client_secrets.get(tls_secret_t::shared_secret),
                                                          __FUNCTION__, "derive matching DHE shared secrets for selected identity one");
                                        _test_case.assert(server_secrets.get(tls_secret_t::handshake) == client_secrets.get(tls_secret_t::handshake), __FUNCTION__,
                                                          "derive matching PSK+DHE handshake secrets for selected identity one");
                                        _test_case.assert(server_secrets.get(tls_secret_t::c_hs_traffic) == client_secrets.get(tls_secret_t::c_hs_traffic), __FUNCTION__,
                                                          "derive matching client handshake traffic secrets for selected identity one");
                                        _test_case.assert(server_secrets.get(tls_secret_t::s_hs_traffic) == client_secrets.get(tls_secret_t::s_hs_traffic), __FUNCTION__,
                                                          "derive matching server handshake traffic secrets for selected identity one");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

static void test_tls13_hrr_preserves_selected_cipher_suite_with_same_hash_ticket() {
    // Scenario under test: TLS 1.3 HRR preserves its selected cipher suite when a ticket uses another suite with the same hash.
    // Action: prepare the SHA-256 transcript hash.
    // Expected: retain the compatible cached ticket in ClientHello2.
    _test_case.begin("TLS 1.3 HRR preserves its selected cipher suite when a ticket uses another suite with the same hash");

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "prepare the SHA-256 transcript hash");
    if (errorcode_t::success != ret) {
        return;
    }

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket ticket;
    ticket.identity = binary_t{0x71, 0x72, 0x73};
    ticket.psk = binary_t(32, 0x44);
    ticket.version = static_cast<uint16>(tls_13);
    ticket.cipher_suite = 0x1303;  // TLS_CHACHA20_POLY1305_SHA256
    ticket.lifetime = 3600;
    ticket.age_add = 0x10203040;
    ticket.timestamp = now_ms - 25;

    // ClientHello2 must retain the exact suite selected by HRR, even though
    // the cached ticket was established with a different AEAD using SHA-256.
    tls_session client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls_13);
    client_protection.set_cipher_suite(0x1301);  // HRR selected AES-128-GCM-SHA256
    client_protection.set_flow(tls_flow_t::hello_retry_request);
    client_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    client.store_resumption_ticket(ticket);

    tls_handshake_client_hello client_hello(&client);
    client_hello.add_ciphersuite(0x1301);
    auto client_modes = new tls_extension_psk_key_exchange_modes(&client_hello);
    client_modes->add(1);  // psk_dhe_ke
    client_hello.get_extensions().add(client_modes);
    auto client_psk = new tls_extension_client_psk(&client_hello);
    client_hello.get_extensions().add(client_psk);

    binary_t psk_extension_wire;
    ret = client_psk->write(from_client, psk_extension_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a SHA-256-compatible PSK extension after HRR");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client_psk->get_identity_count(), __FUNCTION__, "retain the compatible cached ticket in ClientHello2");
    _test_case.assert(0x1301 == client_protection.get_cipher_suite(), __FUNCTION__, "do not replace the HRR-selected AES-128-GCM suite with the ticket's ChaCha20 suite");

    // The server may select this PSK because the ticket hash matches the HRR
    // suite. Its binder is deliberately left as the writer's placeholder so
    // parsing reaches binder verification and fails; suite state must still
    // remain fixed even on that terminal negative path.
    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls_13);
    server_protection.set_cipher_suite(0x1301);
    server_protection.set_flow(tls_flow_t::hello_retry_request);
    server_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    // Model the transcript state immediately after HRR. The PSK parser hashes
    // the complete ClientHello prefix (after the TLS record header), so a bare
    // extension buffer cannot exercise binder verification correctly.
    binary_t client_hello1_hash(32, 0x66);
    binary_t transcript_prefix;
    transcript_prefix << uint8(tls_handshake_type_t::message_hash) << uint24_t(client_hello1_hash.size()) << client_hello1_hash;
    const binary_t hrr_message = {0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0xaa, 0xbb};
    transcript_prefix.insert(transcript_prefix.end(), hrr_message.begin(), hrr_message.end());
    ret = server_protection.reset_transcript_hash(&server);
    _test_case.test(ret, __FUNCTION__, "reset the server transcript for the synthetic HRR");
    ret = server_protection.update_transcript_hash(&server, transcript_prefix.data(), transcript_prefix.size());
    _test_case.test(ret, __FUNCTION__, "seed the server transcript with message_hash and HRR");
    server_protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, transcript_prefix);
    server.store_resumption_ticket(ticket);

    // Wrap the extension in a complete TLS record and ClientHello prefix. The
    // binder transcript ends immediately before the binders vector length;
    // this lets the parser reach calc_psk() and reject the zero placeholder
    // with decrypt_error rather than failing while reconstructing the hash.
    binary_t client_hello_record = {0x16, 0x03, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // ClientHello handshake header
                                    0x03, 0x03};                                           // legacy_version
    client_hello_record.insert(client_hello_record.end(), 32, 0x42);                       // random
    client_hello_record.insert(client_hello_record.end(), {0x00,                           // legacy_session_id length
                                                           0x00, 0x02, 0x13, 0x01,         // cipher_suites
                                                           0x01, 0x00,                     // compression methods
                                                           0x00, 0x00});                   // extensions length
    const size_t extension_offset = client_hello_record.size();
    client_hello_record.insert(client_hello_record.end(), psk_extension_wire.begin(), psk_extension_wire.end());
    const size_t handshake_length = client_hello_record.size() - 9;
    client_hello_record[6] = static_cast<byte_t>((handshake_length >> 16) & 0xff);
    client_hello_record[7] = static_cast<byte_t>((handshake_length >> 8) & 0xff);
    client_hello_record[8] = static_cast<byte_t>(handshake_length & 0xff);
    const size_t record_length = client_hello_record.size() - 5;
    client_hello_record[3] = static_cast<byte_t>((record_length >> 8) & 0xff);
    client_hello_record[4] = static_cast<byte_t>(record_length & 0xff);
    const size_t extensions_length = client_hello_record.size() - extension_offset;
    client_hello_record[extension_offset - 2] = static_cast<byte_t>((extensions_length >> 8) & 0xff);
    client_hello_record[extension_offset - 1] = static_cast<byte_t>(extensions_length & 0xff);

    tls_handshake_client_hello server_hello(&server);
    tls_extension_client_psk server_psk(&server_hello);
    size_t pos = extension_offset;
    ret = server_psk.read(from_client, client_hello_record.data(), client_hello_record.size(), pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject the zero placeholder binder after selecting the matching ticket");
    _test_case.assert(0x1301 == server_protection.get_cipher_suite(), __FUNCTION__, "preserve the HRR-selected suite while validating a same-hash ticket binder");
    _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "clear provisional ticket cipher-suite metadata after binder verification fails");
    _test_case.assert(0xffff == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "do not commit a selected identity when binder verification fails");

    size_t decrypt_error_count = 0;
    server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decrypt_error == desc)) {
            ++decrypt_error_count;
        }
    });
    _test_case.assert(1 == decrypt_error_count, __FUNCTION__, "report exactly one fatal decrypt_error for the placeholder binder");
}

static void test_tls13_hrr_final_server_hello_reuses_selected_cipher_suite() {
    // Scenario under test: TLS 1.3 final ServerHello after HRR must reuse the selected cipher suite.
    // Expected: refuse a final ServerHello suite different from the HRR selection.
    _test_case.begin("TLS 1.3 final ServerHello after HRR must reuse the selected cipher suite");

    // The server API must not allow a final ServerHello to replace the suite
    // selected by HRR. Set a normal ServerHello random before choosing the
    // suite; a second HRR remains a separate unexpected_message case.
    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls_13);
    server_protection.set_cipher_suite(0x1301);
    server_protection.set_flow(tls_flow_t::hello_retry_request);
    tls_handshake_server_hello server_hello(&server);
    server_hello.set_random(binary_t(32, 0x42));
    return_t ret = server_hello.set_cipher_suite(0x1303);
    _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse a final ServerHello suite different from the HRR selection");
    _test_case.assert(0x1301 == server_protection.get_cipher_suite(), __FUNCTION__, "preserve the server's HRR-selected cipher suite");
    ret = server_hello.set_cipher_suite("TLS_CHACHA20_POLY1305_SHA256");
    _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse a different named cipher suite after HRR as well");
    _test_case.assert(0x1301 == server_protection.get_cipher_suite(), __FUNCTION__, "keep the HRR suite after both setter overloads reject a change");

    // A peer that sends a different final suite must be rejected before the
    // rest of the ServerHello extensions can mask the required alert.
    tls_session client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls_13);
    client_protection.set_cipher_suite(0x1301);
    client_protection.set_flow(tls_flow_t::hello_retry_request);
    client.update_session_status(session_status_client_hello);
    client.update_session_status(session_status_hello_retry_request);
    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

    // TLS record + ServerHello with a normal random, suite 0x1303, and an
    // empty extension vector. The suite mismatch must be diagnosed first.
    binary_t server_hello_wire = {0x16, 0x03, 0x03, 0x00, 0x2c, 0x02, 0x00, 0x00, 0x28, 0x03, 0x03};
    server_hello_wire.insert(server_hello_wire.end(), 32, 0x42);
    server_hello_wire.insert(server_hello_wire.end(), {0x00, 0x13, 0x03, 0x00, 0x00, 0x00});

    tls_records records;
    ret = records.read(&client, from_server, server_hello_wire);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject a final ServerHello that changes the HRR-selected suite");
    _test_case.assert(0x1301 == client_protection.get_cipher_suite(), __FUNCTION__, "do not commit the mismatched final suite");

    size_t illegal_parameter_count = 0;
    client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++illegal_parameter_count;
        }
    });
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for the suite change after HRR");
}

void testcase_gpt_psk_hrr_suite() {
    test_tls13_hrr_rejects_psk_with_incompatible_hash();
    test_tls13_hrr_preserves_selected_cipher_suite_with_same_hash_ticket();
    test_tls13_hrr_final_server_hello_reuses_selected_cipher_suite();
}
