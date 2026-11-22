/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk_offer.cpp
 * @author GPT
 * @desc   TLS 1.3 PSK offer, selection, and ticket-age tests.
 */

#include <algorithm>
#include <chrono>

#include "testcase_gpt_common.hpp"

static void test_tls13_server_psk_selected_identity_encoding() {
    // Scenario under test: TLS 1.3 ServerHello PSK selected_identity encoding.
    // Action: read a two-byte selected_identity.
    // Expected: reject selected_identity bodies that are not exactly two bytes.
    _test_case.begin("TLS 1.3 ServerHello PSK selected_identity encoding");

    tls_session session;
    session.set_type(session_type_t::tls);
    tls_handshake_server_hello server_hello(&session);

    const std::array<binary_t, 3> malformed = {
        binary_t{0x00, 0x29, 0x00, 0x00},
        binary_t{0x00, 0x29, 0x00, 0x01, 0x00},
        binary_t{0x00, 0x29, 0x00, 0x03, 0x00, 0x00, 0x00},
    };
    for (const auto& wire : malformed) {
        tls_extension_server_psk extension(&server_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_server, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject selected_identity bodies that are not exactly two bytes");
    }

    {
        const binary_t wire = {0x00, 0x29, 0x00, 0x02, 0x00, 0x01};
        tls_extension_server_psk extension(&server_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read a two-byte selected_identity");
        if (errorcode_t::success == ret) {
            _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete selected_identity extension");
            _test_case.assert(1 == extension.get_selected_identity(), __FUNCTION__, "decode selected_identity as a big-endian index");
        }
    }

    {
        const binary_t wire = {0x00, 0x29, 0x00, 0x02, 0x00, 0x00};
        tls_extension_server_psk extension(&server_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_client, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ServerHello PSK extension from the client direction");
    }
}

static return_t prepare_tls13_psk_offer_client(tls_session& client, uint8 offered_mode, bool offer_unknown_suite, uint32 ticket_age_add, uint32 ticket_lifetime,
                                               const binary_t& ticket, const binary_t& resumption_psk) {
    client.set_type(session_type_t::tls);
    auto& protection = client.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    client.get_keyvalue().set(session_tls_version, tls1_3);
    client.update_session_status(session_status_server_finished);
    client.update_session_status(session_status_client_finished);
    client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto& ticket_kv = client.get_session_info(from_server).get_keyvalue();
    ticket_kv.set(session_ticket_lifetime, ticket_lifetime);
    ticket_kv.set(session_ticket_age_add, ticket_age_add);
    ticket_kv.set(session_ticket_timestamp, now_ms - 25);
    protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
    protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    digest.digest("sha256", empty, empty_hash);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);
    client_hello->add_ciphersuite(0x1302);
    client_hello->add_ciphersuite(0x1303);
    if (offer_unknown_suite) {
        client_hello->add_ciphersuite(0xdead);
    }
    auto supported_versions = new tls_extension_client_supported_versions(client_hello);
    supported_versions->add(tls1_3);
    client_hello->get_extensions().add(supported_versions);
    auto psk_modes = new tls_extension_psk_key_exchange_modes(client_hello);
    psk_modes->add(offered_mode);
    client_hello->get_extensions().add(psk_modes);
    auto psk = new tls_extension_client_psk(client_hello);
    client_hello->get_extensions().add(psk);
    tls_record_handshake record(&client);
    record << client_hello;
    binary_t client_hello_wire;
    return record.write(from_client, client_hello_wire);
}

static binary_t make_tls13_psk_server_hello(uint16 selected_identity, uint16 cipher_suite, bool hello_retry_request) {
    binary_t body;
    body.insert(body.end(), {0x03, 0x03});  // legacy_version
    if (hello_retry_request) {
        const byte_t hrr_random[32] = {
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
            0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        };
        body.insert(body.end(), hrr_random, hrr_random + 32);
    } else {
        body.insert(body.end(), 32, 0);  // random
    }
    body.push_back(0);  // legacy_session_id_echo length
    body.push_back(static_cast<byte_t>(cipher_suite >> 8));
    body.push_back(static_cast<byte_t>(cipher_suite));  // cipher_suite
    body.push_back(0);                                  // legacy_compression_method
    body.insert(body.end(), {0x00, 0x0c,                // extensions length
                             0x00, 0x2b, 0x00, 0x02,    // supported_versions
                             0x03, 0x04,                // TLS 1.3
                             0x00, 0x29, 0x00, 0x02,    // pre_shared_key
                             static_cast<byte_t>(selected_identity >> 8), static_cast<byte_t>(selected_identity)});

    binary_t handshake;
    handshake.push_back(static_cast<byte_t>(tls_handshake_type_t::server_hello));
    uint32 body_size = t_narrow_cast(body.size());
    handshake.push_back(static_cast<byte_t>(body_size >> 16));
    handshake.push_back(static_cast<byte_t>(body_size >> 8));
    handshake.push_back(static_cast<byte_t>(body_size));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

static void test_tls13_server_psk_selected_identity_range_cases(const char* function_name, uint32 ticket_age_add, uint32 ticket_lifetime, const binary_t& ticket,
                                                                const binary_t& resumption_psk) {
    // Scenario under test: TLS 1.3 ServerHello selected_identity range and structural validation.
    // Action: test one- and two-identity boundaries, key-exchange mode mismatch, HRR prohibition, truncated extensions, and unknown suites.
    // Expected: reject invalid selections and malformed ServerHello without committing provisional PSK state.
    return_t ret = errorcode_t::success;
    auto verify_case = [&](uint16 offered_count, uint16 selected_identity, uint8 offered_mode, uint16 cipher_suite, bool hello_retry_request,
                           bool expect_illegal_parameter, const char* description) {
        tls_session client;
        return_t ret = prepare_tls13_psk_offer_client(client, offered_mode, false, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
        _test_case.test(ret, function_name, "prepare a ClientHello with a PSK offer");
        if (errorcode_t::success != ret) {
            return;
        }

        client.get_keyvalue().set(session_client_psk_identity_count, offered_count);
        binary_t server_hello_wire = make_tls13_psk_server_hello(selected_identity, cipher_suite, hello_retry_request);
        tls_handshake_server_hello server_hello(&client);
        size_t pos = 0;
        ret = server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), pos);

        size_t illegal_parameter_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(expect_illegal_parameter ? (1 == illegal_parameter_count) : (0 == illegal_parameter_count), function_name, description);
        if (expect_illegal_parameter) {
            _test_case.assert(errorcode_t::success != ret, function_name, "reject an out-of-range selected_identity");
        } else if (errorcode_t::success == ret) {
            _test_case.assert(server_hello_wire.size() == pos, function_name, "consume the complete valid ServerHello");
        }
    };

    verify_case(1, 0, 0, 0x1301, false, false, "accept selected_identity zero for a one-identity psk_ke offer");
    verify_case(1, 1, 0, 0x1301, false, true, "reject selected_identity equal to the one-identity offer count");
    verify_case(1, 0, 1, 0x1301, false, true, "reject PSK selection without key_share when only psk_dhe_ke was offered");
    verify_case(1, 0, 0, 0x1302, false, true, "reject PSK selection when the selected cipher suite hash differs from the PSK hash");
    // The two-identity parser/count path is covered by the multi-identity
    // ClientHello test; set the recorded count here to isolate the SH boundary.
    verify_case(2, 1, 0, 0x1301, false, false, "accept the last valid index for a two-identity offer");
    verify_case(0, 0, 0, 0x1301, false, true, "reject a PSK selection when the recorded offer count is zero");
    verify_case(1, 0, 1, 0x1301, true, true, "reject pre_shared_key in HelloRetryRequest");

    // A complete ServerHello whose extension block ends with only one byte
    // of a new extension header is malformed, not a successfully parsed prefix.
    {
        tls_session truncated_client;
        ret = prepare_tls13_psk_offer_client(truncated_client, 0, false, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
        _test_case.test(ret, function_name, "prepare a client for a truncated ServerHello extension vector");
        if (errorcode_t::success == ret) {
            binary_t truncated_wire = make_tls13_psk_server_hello(0, 0x1301, false);
            const size_t extension_length_offset = 4 + 2 + 32 + 1 + 2 + 1;
            truncated_wire[extension_length_offset + 1] = 0x0d;
            truncated_wire.push_back(0x00);
            uint32 truncated_body_size = t_narrow_cast(truncated_wire.size() - 4);
            truncated_wire[1] = static_cast<byte_t>(truncated_body_size >> 16);
            truncated_wire[2] = static_cast<byte_t>(truncated_body_size >> 8);
            truncated_wire[3] = static_cast<byte_t>(truncated_body_size);

            tls_handshake_server_hello truncated_reader(&truncated_client);
            size_t truncated_pos = 0;
            ret = truncated_reader.read(from_server, truncated_wire.data(), truncated_wire.size(), truncated_pos);
            size_t decode_error_count = test_count_fatal_alert(truncated_client, from_server, tls_alertdesc_t::decode_error);
            _test_case.assert(errorcode_t::bad_format == ret, function_name, "reject a complete ServerHello with a truncated trailing extension header");
            _test_case.assert(1 == decode_error_count, function_name, "report exactly one fatal decode_error for the truncated ServerHello extension header");
            _test_case.assert(0xffff == truncated_client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                              "do not commit the PSK selected_identity when ServerHello parsing fails");
            _test_case.assert(truncated_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                              "roll back the provisional PSK Early Secret when ServerHello parsing fails");
        }
    }

    // A suite can be present in the recorded ClientHello offer yet still be
    // unknown to this implementation. Do not ignore the setter failure and
    // continue the key schedule with the session's previous cipher suite.
    {
        tls_session unknown_suite_client;
        ret = prepare_tls13_psk_offer_client(unknown_suite_client, 0, true, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
        _test_case.test(ret, function_name, "prepare a client for an unknown selected cipher-suite test");
        if (errorcode_t::success == ret) {
            binary_t unknown_suite_wire = make_tls13_psk_server_hello(0, 0xdead, false);
            tls_handshake_server_hello unknown_suite_reader(&unknown_suite_client);
            size_t unknown_suite_pos = 0;
            ret = unknown_suite_reader.read(from_server, unknown_suite_wire.data(), unknown_suite_wire.size(), unknown_suite_pos);

            size_t illegal_parameter_count = test_count_fatal_alert(unknown_suite_client, from_server, tls_alertdesc_t::illegal_parameter);
            _test_case.assert(errorcode_t::handshake_failure == ret, function_name,
                              "reject a ServerHello cipher suite that cannot be resolved by the local implementation");
            _test_case.assert(1 == illegal_parameter_count, function_name, "report exactly one fatal illegal_parameter for an unusable selected cipher suite");
            _test_case.assert(0xffff == unknown_suite_client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                              "do not commit PSK selection after rejecting the unusable cipher suite");
            _test_case.assert(unknown_suite_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                              "roll back the provisional PSK Early Secret after rejecting the unusable cipher suite");
        }
    }
}

static void test_tls13_server_psk_selected_identity_hash_compatibility(const char* function_name, uint32 ticket_age_add, uint32 ticket_lifetime, const binary_t& ticket,
                                                                       const binary_t& resumption_psk) {
    // Scenario under test: TLS 1.3 ServerHello selected_identity must match the selected ticket's cipher-suite hash.
    // Action: select a SHA-384 identity from a mixed-hash offer, test same-hash suite changes, and test a mismatched hash.
    // Expected: accept compatible ticket/hash combinations and reject an identity whose PSK hash differs from ServerHello.
    // A mixed-hash offer must validate the selected identity's suite hash,
    // rather than comparing every selection with the first ticket's hash.
    tls_session mixed_hash_client;
    return_t mixed_prepare = prepare_tls13_psk_offer_client(mixed_hash_client, 0, false, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
    _test_case.test(mixed_prepare, function_name, "prepare a client for mixed-hash ServerHello selection");
    if (errorcode_t::success == mixed_prepare) {
        const uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        tls_resumption_ticket sha256_ticket;
        sha256_ticket.identity = {0x01};
        sha256_ticket.psk = binary_t(32, 0x11);
        sha256_ticket.lifetime = ticket_lifetime;
        sha256_ticket.timestamp = now_ms;
        sha256_ticket.cipher_suite = 0x1301;
        tls_resumption_ticket sha256_ticket_second = sha256_ticket;
        sha256_ticket_second.identity = {0x02};
        sha256_ticket_second.cipher_suite = 0x1303;
        tls_resumption_ticket sha384_ticket;
        sha384_ticket.identity = {0x03};
        sha384_ticket.psk = binary_t(48, 0x33);
        sha384_ticket.lifetime = ticket_lifetime;
        sha384_ticket.timestamp = now_ms;
        sha384_ticket.cipher_suite = 0x1302;
        mixed_hash_client.set_offered_resumption_tickets({sha256_ticket, sha256_ticket_second, sha384_ticket});
        mixed_hash_client.get_keyvalue().set(session_client_psk_identity_count, 3);

        binary_t mixed_hash_server_hello_wire = make_tls13_psk_server_hello(2, 0x1302, false);
        tls_handshake_server_hello mixed_hash_server_hello(&mixed_hash_client);
        size_t mixed_hash_pos = 0;
        return_t mixed_ret = mixed_hash_server_hello.read(from_server, mixed_hash_server_hello_wire.data(), mixed_hash_server_hello_wire.size(), mixed_hash_pos);
        _test_case.test(mixed_ret, function_name, "accept ServerHello selecting the SHA-384 identity from a mixed-hash offer");
        if (errorcode_t::success == mixed_ret) {
            _test_case.assert(mixed_hash_server_hello_wire.size() == mixed_hash_pos, function_name, "consume the complete mixed-hash ServerHello");
            _test_case.assert(2 == mixed_hash_client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                              "retain the selected SHA-384 identity index");
            _test_case.assert(48 == mixed_hash_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).size(), function_name,
                              "restore the selected SHA-384 ticket before the key schedule");
        }

        // A ticket may resume under a different AEAD suite when the hash is unchanged.
        tls_session same_hash_different_suite_client;
        return_t same_hash_prepare = prepare_tls13_psk_offer_client(same_hash_different_suite_client, 0, false, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
        _test_case.test(same_hash_prepare, function_name, "prepare a client for same-hash cipher-suite resumption");
        if (errorcode_t::success == same_hash_prepare) {
            same_hash_different_suite_client.set_offered_resumption_tickets({sha256_ticket});
            same_hash_different_suite_client.get_keyvalue().set(session_client_psk_identity_count, 1);
            binary_t same_hash_server_hello_wire = make_tls13_psk_server_hello(0, 0x1303, false);
            tls_handshake_server_hello same_hash_server_hello(&same_hash_different_suite_client);
            size_t same_hash_pos = 0;
            return_t same_hash_ret = same_hash_server_hello.read(from_server, same_hash_server_hello_wire.data(), same_hash_server_hello_wire.size(), same_hash_pos);
            _test_case.test(same_hash_ret, function_name, "accept a SHA-256 ticket with a different SHA-256 cipher suite");
            if (errorcode_t::success == same_hash_ret) {
                _test_case.assert(same_hash_server_hello_wire.size() == same_hash_pos, function_name, "consume the complete same-hash ServerHello");
                _test_case.assert(0x1303 == same_hash_different_suite_client.get_tls_protection().get_cipher_suite(), function_name,
                                  "retain the newly negotiated ChaCha20-Poly1305 suite");
                _test_case.assert(32 == same_hash_different_suite_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).size(), function_name,
                                  "restore the SHA-256 ticket PSK for the negotiated suite");
            }
        }

        tls_session mismatched_hash_client;
        return_t mismatch_prepare = prepare_tls13_psk_offer_client(mismatched_hash_client, 0, false, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
        _test_case.test(mismatch_prepare, function_name, "prepare a second client for mixed-hash suite mismatch validation");
        if (errorcode_t::success == mismatch_prepare) {
            mismatched_hash_client.set_offered_resumption_tickets({sha256_ticket, sha256_ticket_second, sha384_ticket});
            mismatched_hash_client.get_keyvalue().set(session_client_psk_identity_count, 3);
            binary_t mismatched_hash_server_hello_wire = make_tls13_psk_server_hello(2, 0x1301, false);
            tls_handshake_server_hello mismatched_hash_server_hello(&mismatched_hash_client);
            size_t mismatched_hash_pos = 0;
            return_t mismatch_ret =
                mismatched_hash_server_hello.read(from_server, mismatched_hash_server_hello_wire.data(), mismatched_hash_server_hello_wire.size(), mismatched_hash_pos);
            size_t illegal_parameter_count = test_count_fatal_alert(mismatched_hash_client, from_server, tls_alertdesc_t::illegal_parameter);
            _test_case.assert(errorcode_t::success != mismatch_ret, function_name, "reject a SHA-384 PSK selected with a SHA-256 cipher suite");
            _test_case.assert(1 == illegal_parameter_count, function_name, "report exactly one fatal illegal_parameter for the mixed-hash mismatch");
        }
    }
}

static void test_tls13_server_psk_selected_identity_range() {
    // Scenario under test: TLS 1.3 ServerHello selected_identity range and cipher-suite hash validation.
    // Action: exercise selection bounds, malformed ServerHello, and mixed-hash ticket compatibility.
    // Expected: commit only a valid selected identity and restore the matching ticket PSK.
    _test_case.begin("TLS 1.3 ServerHello PSK selected_identity range");

    constexpr uint32 ticket_age_add = 0x50607080;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0xaa, 0xbb, 0xcc};
    const binary_t resumption_psk(32, 0x11);
    test_tls13_server_psk_selected_identity_range_cases(__FUNCTION__, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
    test_tls13_server_psk_selected_identity_hash_compatibility(__FUNCTION__, ticket_age_add, ticket_lifetime, ticket, resumption_psk);
}

template <typename Configure>
static void test_tls13_psk_offer_retires_expired_earlier_identity(const binary_t& wire, const tls_resumption_ticket& ticket1, const tls_resumption_ticket& ticket2,
                                                                  const binary_t& identity2, uint64 now_ms, Configure configure) {
    // Scenario: TLS 1.3 retires an expired earlier PSK identity while selecting a later ticket.
    // Action: offer an expired first ticket followed by a valid second ticket.
    // Expected: retire the expired ticket and retain the selected later ticket in the compatibility view.
    _test_case.begin("TLS 1.3 retires an expired earlier PSK identity while selecting a later ticket");
    // An expired earlier identity must be retired even when a later
    // offered identity is selected successfully.
    {
        tls_resumption_ticket expired_ticket = ticket1;
        expired_ticket.timestamp = now_ms - (static_cast<uint64>(expired_ticket.lifetime) * 1000 + 1);

        tls_session expiry_cleanup_server;
        configure(expiry_cleanup_server);
        expiry_cleanup_server.get_tls_protection().set_cipher_suite(0);
        expiry_cleanup_server.store_resumption_ticket(expired_ticket);
        expiry_cleanup_server.store_resumption_ticket(ticket2);
        auto& expiry_secrets = expiry_cleanup_server.get_tls_protection().get_secrets();
        expiry_secrets.assign(tls_secret_t::new_session_ticket, expired_ticket.identity);
        auto& expiry_kv = expiry_cleanup_server.get_session_info(from_server).get_keyvalue();
        expiry_kv.set(session_ticket_lifetime, expired_ticket.lifetime);
        expiry_kv.set(session_ticket_age_add, expired_ticket.age_add);
        expiry_kv.set(session_ticket_timestamp, expired_ticket.timestamp);

        tls_records expiry_cleanup_records;
        return_t expiry_cleanup_ret = expiry_cleanup_records.read(&expiry_cleanup_server, from_client, wire);
        _test_case.test(expiry_cleanup_ret, __FUNCTION__, "select a later valid identity while retiring an earlier expired ticket");
        if (errorcode_t::success == expiry_cleanup_ret) {
            auto remaining_tickets = expiry_cleanup_server.get_resumption_tickets();
            _test_case.assert(1 == remaining_tickets.size(), __FUNCTION__, "remove the expired first identity despite successful later resumption");
            if (1 == remaining_tickets.size()) {
                _test_case.assert(identity2 == remaining_tickets.front().identity, __FUNCTION__, "retain the later valid ticket record");
            }
            _test_case.assert(1 == expiry_cleanup_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "select the second offered identity after rejecting the expired first identity");
            _test_case.assert(identity2 == expiry_secrets.get(tls_secret_t::new_session_ticket), __FUNCTION__,
                              "promote the remaining valid ticket into the compatibility view");
            _test_case.assert(ticket2.lifetime == expiry_kv.get(session_ticket_lifetime), __FUNCTION__,
                              "refresh compatibility lifetime metadata from the remaining ticket");
            _test_case.assert(ticket2.age_add == expiry_kv.get(session_ticket_age_add), __FUNCTION__, "refresh compatibility age_add metadata from the remaining ticket");
            _test_case.assert(ticket2.timestamp == expiry_kv.get(session_ticket_timestamp), __FUNCTION__,
                              "refresh compatibility timestamp metadata from the remaining ticket");
        }
    }
}

template <typename Configure>
static void test_tls13_psk_offer_ticket_age_mismatch(const binary_t& wire, const tls_resumption_ticket& ticket1, uint64 now_ms, Configure configure) {
    // Scenario: TLS 1.3 retains PSK resumption when the early-data ticket age mismatches.
    // Action: compare a matching ticket age with a delayed server issuance timestamp.
    // Expected: retain PSK resumption but revoke the early-data allowance for the mismatch.
    _test_case.begin("TLS 1.3 retains PSK resumption when the early-data ticket age mismatches");
    // The server must compare the client-reported age with its own issuance
    // timestamp for 0-RTT, while retaining PSK resumption on an age mismatch.
    {
        tls_session age_match_server;
        configure(age_match_server);
        age_match_server.get_tls_protection().set_cipher_suite(0);
        age_match_server.store_resumption_ticket(ticket1);
        tls_records age_match_records;
        return_t age_match_ret = age_match_records.read(&age_match_server, from_client, wire);
        _test_case.test(age_match_ret, __FUNCTION__, "resume with a first-identity ticket whose reported age matches server issuance time");
        if (errorcode_t::success == age_match_ret) {
            _test_case.assert(0 == age_match_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "select the first PSK identity for the age-match case");
            uint64 age_match_early_data_limit = age_match_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit);
            _test_case.assert(4096 == age_match_early_data_limit, __FUNCTION__, "recognize the early-data allowance when ticket age matches");
        }

        tls_resumption_ticket delayed_ticket = ticket1;
        delayed_ticket.timestamp = now_ms - 20000;
        tls_session age_mismatch_server;
        configure(age_mismatch_server);
        age_mismatch_server.get_tls_protection().set_cipher_suite(0);
        age_mismatch_server.store_resumption_ticket(delayed_ticket);
        tls_records age_mismatch_records;
        return_t age_mismatch_ret = age_mismatch_records.read(&age_mismatch_server, from_client, wire);
        _test_case.test(age_mismatch_ret, __FUNCTION__, "retain PSK resumption when the reported ticket age differs from server issuance time");
        if (errorcode_t::success == age_mismatch_ret) {
            _test_case.assert(0 == age_mismatch_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "keep the first PSK identity selected despite an early-data age mismatch");
            _test_case.assert(0 == age_mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                              "reject only early data when the reported ticket age exceeds the tolerance");
            _test_case.assert(tls_flow_t::zero_rtt == age_mismatch_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "preserve PSK resumption after declining early data");
        }
    }
}

template <typename Configure>
static void test_tls13_psk_offer_verifies_sha384_binder(const binary_t& wire, const tls_resumption_ticket& ticket3, Configure configure) {
    // Scenario: TLS 1.3 verifies a later SHA-384 PSK binder independently.
    // Action: process the mixed-hash ClientHello on a server that stores only the SHA-384 ticket.
    // Expected: select identity two and derive the Early Secret from the SHA-384 ticket.
    _test_case.begin("TLS 1.3 verifies a later SHA-384 PSK binder independently");
    return_t ret = errorcode_t::success;
    // The third offered ticket uses SHA-384. Verify its binder independently
    // on a server that has only that identity in its ticket store.
    tls_session sha384_server;
    configure(sha384_server);
    sha384_server.get_tls_protection().set_cipher_suite(0);
    sha384_server.store_resumption_ticket(ticket3);
    tls_records sha384_records;
    ret = sha384_records.read(&sha384_server, from_client, wire);
    _test_case.test(ret, __FUNCTION__, "verify the SHA-384 binder for a later mixed-hash PSK identity");
    if (errorcode_t::success == ret) {
        _test_case.assert(2 == sha384_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "select the SHA-384 ticket at its matching identity index");
        _test_case.assert(0x1302 == sha384_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "retain the selected ticket's SHA-384 cipher suite");
        binary_t expected_sha384_early_secret;
        return_t sha384_secret_ret = sha384_server.get_tls_protection().calc_resumption_early_secret(ticket3.psk, expected_sha384_early_secret);
        _test_case.test(sha384_secret_ret, __FUNCTION__, "derive the expected SHA-384 ticket early secret");
        if (errorcode_t::success == sha384_secret_ret) {
            _test_case.assert(expected_sha384_early_secret == sha384_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                              "verify the selected SHA-384 PSK independently of the first SHA-256 identity");
        }
    }
}

template <typename Configure>
static void test_tls13_psk_offer_omits_hash_incompatible_ticket(const tls_resumption_ticket& ticket1, const tls_resumption_ticket& ticket3, Configure configure) {
    // Scenario: TLS 1.3 omits a cached PSK ticket with no matching offered cipher-suite hash.
    // Action: offer only a SHA-256 cipher suite while the cache contains SHA-256 and SHA-384 tickets.
    // Expected: serialize only the compatible SHA-256 identity.
    _test_case.begin("TLS 1.3 omits a cached PSK ticket with no matching offered cipher-suite hash");
    return_t ret = errorcode_t::success;
    // A ticket whose hash has no matching ClientHello cipher suite must not
    // be emitted merely because another ticket is usable.
    tls_session restricted_client;
    configure(restricted_client);
    restricted_client.get_tls_protection().set_cipher_suite(0);
    restricted_client.store_resumption_ticket(ticket1);
    restricted_client.store_resumption_ticket(ticket3);
    tls_handshake_client_hello restricted_hello(&restricted_client);
    restricted_hello.add_ciphersuite(0x1301);
    tls_extension_client_psk restricted_psk(&restricted_hello);
    binary_t restricted_psk_wire;
    ret = restricted_psk.write(from_client, restricted_psk_wire);
    _test_case.test(ret, __FUNCTION__, "serialize only PSK tickets compatible with the offered cipher-suite hashes");
    if (errorcode_t::success == ret) {
        _test_case.assert(1 == restricted_psk.get_identity_count(), __FUNCTION__, "omit the SHA-384 ticket when no SHA-384 suite was offered");
        auto restricted_tickets = restricted_client.get_offered_resumption_tickets();
        _test_case.assert((restricted_tickets.size() == 1) && (0x1301 == restricted_tickets.front().cipher_suite), __FUNCTION__,
                          "retain the matching SHA-256 suite metadata for the emitted identity");
    }
}

template <typename Configure>
static void test_tls13_psk_offer_rejects_mismatched_server_identity(const binary_t& wire, const tls_resumption_ticket& ticket2, Configure configure) {
    // Scenario: TLS 1.3 rejects a ServerHello selected_identity that differs from the verified binder identity.
    // Action: verify identity one, then alter the composed ServerHello to select identity zero.
    // Expected: reject the inconsistent selection and roll back provisional PSK state.
    _test_case.begin("TLS 1.3 rejects a ServerHello selected_identity that differs from the verified binder identity");
    tls_session mismatched_server;
    configure(mismatched_server);
    mismatched_server.get_tls_protection().set_cipher_suite(0);
    mismatched_server.store_resumption_ticket(ticket2);
    tls_records mismatched_records;
    binary_t mismatched_client_hello_wire = wire;
    return_t mismatched_ret = mismatched_records.read(&mismatched_server, from_client, mismatched_client_hello_wire);
    _test_case.test(mismatched_ret, __FUNCTION__, "verify the binder for the second offered identity before testing ServerHello consistency");
    if (errorcode_t::success == mismatched_ret) {
        _test_case.assert(1 == mismatched_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "record wire identity one as the PSK whose binder was verified");

        tls_handshake* mismatched_server_hello = nullptr;
        mismatched_ret = tls_composer::construct_server_hello(&mismatched_server_hello, &mismatched_server, nullptr);
        _test_case.test(mismatched_ret, __FUNCTION__, "construct a ServerHello for the verified second identity");
        if ((errorcode_t::success == mismatched_ret) && (nullptr != mismatched_server_hello)) {
            auto mismatched_psk = static_cast<tls_extension_server_psk*>(mismatched_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key));
            _test_case.assert(nullptr != mismatched_psk, __FUNCTION__, "include the verified PSK selection in ServerHello");
            if (nullptr != mismatched_psk) {
                _test_case.assert(1 == mismatched_psk->get_selected_identity(), __FUNCTION__, "initially select the same identity whose binder was verified");
                mismatched_psk->set_selected_identity(0);

                binary_t mismatched_server_hello_wire;
                mismatched_ret = mismatched_server_hello->write(from_server, mismatched_server_hello_wire);
                _test_case.assert(errorcode_t::success != mismatched_ret, __FUNCTION__,
                                  "reject ServerHello when selected_identity differs from the verified binder identity");
                _test_case.assert(0xffff == mismatched_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                  "roll back the verified identity after rejecting inconsistent ServerHello");
                _test_case.assert(0xffff == mismatched_server.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                                  "roll back the PSK key-exchange mode after rejecting inconsistent ServerHello");
                _test_case.assert(0 == mismatched_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                  "clear provisional ticket cipher-suite metadata after rejecting inconsistent ServerHello");
                _test_case.assert(mismatched_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                  "clear the verified ticket Early Secret after rejecting inconsistent ServerHello");
                _test_case.assert(tls_flow_t::one_rtt == mismatched_server.get_tls_protection().get_flow(), __FUNCTION__,
                                  "leave no provisional resumption flow after rejecting inconsistent ServerHello");
                _test_case.assert(mismatched_server.get_offered_resumption_tickets().empty(), __FUNCTION__,
                                  "discard the offered-ticket snapshot after rejecting inconsistent ServerHello");
            }
            mismatched_server_hello->release();
        } else if (nullptr != mismatched_server_hello) {
            mismatched_server_hello->release();
        }
    }
}

static void test_tls13_psk_offer_client_restores_selected_ticket_psk(tls_session& server, tls_session& client, const binary_t& psk2) {
    // Scenario: TLS 1.3 client restores the selected ticket PSK when processing ServerHello.
    // Action: compose a ServerHello selecting identity one and process it on the client.
    // Expected: restore the PSK associated with the verified identity and derive matching shared and early secrets.
    _test_case.begin("TLS 1.3 client restores the selected ticket PSK when processing ServerHello");
    return_t ret = errorcode_t::success;
    // The client's ServerHello processing must restore the PSK associated
    // with selected_identity=1, even though binder generation iterated over
    // both cached tickets and restored the prior secret afterward.
    // Construct the ServerHello through the production composer so cipher-suite,
    // version, and key-share selection are negotiated from the parsed ClientHello.
    tls_handshake* server_hello = nullptr;
    ret = tls_composer::construct_server_hello(&server_hello, &server, nullptr);
    _test_case.test(ret, __FUNCTION__, "construct ServerHello through the TLS composer");
    if ((errorcode_t::success != ret) || (nullptr == server_hello)) {
        return;
    }

    // construct_server_hello() performs the server-side negotiation from the
    // ClientHello offer before creating the ServerHello. Validate the negotiated
    // key-share state only after this production handshake path has run.
    auto negotiated_keyshare_group = server.get_tls_protection().get_protection_context().get0_keyshare_group();
    _test_case.assert(tls_group_t::unknown != negotiated_keyshare_group, __FUNCTION__, "populate the server key-share context during ClientHello negotiation");

    uint16 selected_cipher_suite = static_cast<tls_handshake_server_hello*>(server_hello)->get_cipher_suite();
    _test_case.assert(0x1301 == selected_cipher_suite, __FUNCTION__, "select the SHA-256 cipher suite associated with the cached tickets");
    if (0x1301 != selected_cipher_suite) {
        server_hello->release();
        return;
    }

    auto server_versions = server_hello->get_extensions().get(tls_extension_type_t::supported_versions);
    auto server_key_share = server_hello->get_extensions().get(tls_extension_type_t::key_share);
    auto server_psk = server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key);
    _test_case.assert(nullptr != server_versions, __FUNCTION__, "register supported_versions through the ServerHello composer");
    _test_case.assert(nullptr != server_key_share, __FUNCTION__, "register key_share through the ServerHello composer");
    _test_case.assert(nullptr != server_psk, __FUNCTION__, "register the selected PSK identity through the ServerHello composer");
    if ((nullptr == server_versions) || (nullptr == server_key_share) || (nullptr == server_psk)) {
        server_hello->release();
        return;
    }

    auto selected_server_psk = static_cast<tls_extension_server_psk*>(server_psk);
    _test_case.assert(1 == selected_server_psk->get_selected_identity(), __FUNCTION__, "select the second identity offered by the client");

    // Serialize the complete ServerHello through the production handshake
    // writer. This exercises do_preprocess(), extension serialization, and
    // the server key schedule instead of assembling a synthetic wire message.
    binary_t server_hello_wire;
    ret = server_hello->write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the composer-built ServerHello with its selected PSK identity");
    // Direct handshake serialization bypasses tls_record::do_postprocess().
    // Complete the containing-record boundary so the deferred TLS 1.3
    // protection activation releases its scheduled handshake reference.
    server.run_scheduled(from_server);
    server_hello->release();
    if (errorcode_t::success != ret) {
        return;
    }

    binary_t server_shared_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(!server_shared_secret.empty(), __FUNCTION__, "derive the server-side shared secret from the negotiated key_share");

    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    tls_handshake_server_hello server_hello_reader(&client);
    size_t server_hello_pos = 0;
    ret = server_hello_reader.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept ServerHello selecting the second cached ticket");
    _test_case.assert(server_hello_wire.size() == server_hello_pos, __FUNCTION__, "consume the complete composer-generated ServerHello");
    _test_case.assert(1 == client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "retain the selected identity for subsequent EncryptedExtensions early-data validation");

    binary_t client_shared_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(!client_shared_secret.empty(), __FUNCTION__, "derive the client-side shared secret from the ServerHello key_share");
    _test_case.assert(server_shared_secret == client_shared_secret, __FUNCTION__, "derive the same DHE shared secret on both peers");

    binary_t expected_client_early_secret;
    return_t expected_ret = client.get_tls_protection().calc_resumption_early_secret(psk2, expected_client_early_secret);
    _test_case.test(expected_ret, __FUNCTION__, "derive the expected early secret for selected_identity one");
    _test_case.assert(expected_client_early_secret == client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                      "restore the second ticket PSK before the client key schedule");
}

template <typename Configure>
static void test_tls13_psk_offer_clears_state_on_suite_failure(const binary_t& wire, const tls_resumption_ticket& ticket1, Configure configure) {
    // Scenario: TLS 1.3 clears PSK and early-data state when cipher-suite negotiation fails.
    // Action: verify the offered PSK binder and then remove every negotiable cipher suite.
    // Expected: fail ServerHello construction and clear provisional PSK and early-data state.
    _test_case.begin("TLS 1.3 clears PSK and early-data state when cipher-suite negotiation fails");
    // If no cipher suite can be negotiated, terminate the handshake
    // without retaining the binder-selected PSK or early-data state.
    {
        tls_session no_suite_server;
        configure(no_suite_server);
        no_suite_server.get_tls_protection().set_cipher_suite(0);
        no_suite_server.store_resumption_ticket(ticket1);
        tls_records no_suite_records;
        return_t no_suite_ret = no_suite_records.read(&no_suite_server, from_client, wire);
        _test_case.test(no_suite_ret, __FUNCTION__, "verify the PSK binder before forcing cipher-suite negotiation failure");
        if (errorcode_t::success == no_suite_ret) {
            auto& no_suite_protection = no_suite_server.get_tls_protection();
            _test_case.assert(tls_flow_t::zero_rtt == no_suite_protection.get_flow(), __FUNCTION__, "select the PSK before attempting cipher-suite negotiation");
            _test_case.assert(0 == no_suite_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                              "derive the selected ticket early secret before forcing negotiation failure");

            no_suite_protection.get_protection_context().clear_cipher_suites();
            tls_handshake* no_suite_server_hello = nullptr;
            no_suite_ret = tls_composer::construct_server_hello(&no_suite_server_hello, &no_suite_server, nullptr);
            _test_case.assert(errorcode_t::success != no_suite_ret, __FUNCTION__, "fail the handshake when no cipher suite is available");
            _test_case.assert(nullptr == no_suite_server_hello, __FUNCTION__, "do not construct ServerHello without a negotiated cipher suite");
            _test_case.assert(tls_flow_t::one_rtt == no_suite_protection.get_flow(), __FUNCTION__, "leave no stale PSK resumption flow after negotiation failure");
            _test_case.assert(no_suite_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                              "clear the selected ticket early secret after negotiation failure");
            _test_case.assert(0xffff == no_suite_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "clear the selected identity after negotiation failure");
            _test_case.assert(0 == no_suite_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                              "clear the ticket cipher-suite metadata after negotiation failure");
            _test_case.assert(0 == no_suite_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                              "clear the early-data allowance after negotiation failure");
        }
    }
}

template <typename Configure>
static void test_tls13_psk_offer_hrr_declines_incompatible_ticket_hash(const binary_t& wire, const tls_resumption_ticket& ticket1, Configure configure) {
    // Scenario: TLS 1.3 declines an HRR-incompatible PSK while preserving the transcript prefix.
    // Action: verify the initial binder, enter HRR flow, and prefer a cipher suite with a different ticket hash.
    // Expected: omit pre_shared_key, clear provisional PSK state, and retain the HRR transcript flow.
    _test_case.begin("TLS 1.3 declines an HRR-incompatible PSK while preserving the transcript prefix");
    // A PSK hash mismatch in ClientHello2 must decline resumption without
    // discarding the HelloRetryRequest transcript prefix.
    {
        tls_session hrr_mismatch_server;
        configure(hrr_mismatch_server);
        hrr_mismatch_server.get_tls_protection().set_cipher_suite(0);
        hrr_mismatch_server.store_resumption_ticket(ticket1);
        tls_records hrr_mismatch_records;
        return_t hrr_mismatch_ret = hrr_mismatch_records.read(&hrr_mismatch_server, from_client, wire);
        _test_case.test(hrr_mismatch_ret, __FUNCTION__, "verify the PSK binder before simulating the HRR continuation");
        if (errorcode_t::success == hrr_mismatch_ret) {
            auto& hrr_mismatch_protection = hrr_mismatch_server.get_tls_protection();
            hrr_mismatch_protection.set_flow(tls_flow_t::hello_retry_request);
            hrr_mismatch_server.update_session_status(session_status_hello_retry_request);

            auto& hrr_mismatch_context = hrr_mismatch_protection.get_protection_context();
            hrr_mismatch_context.clear_cipher_suites();
            hrr_mismatch_context.add_cipher_suite(0x1302).add_cipher_suite(0x1301);

            tls_handshake* hrr_mismatch_server_hello = nullptr;
            hrr_mismatch_ret = tls_composer::construct_server_hello(&hrr_mismatch_server_hello, &hrr_mismatch_server, nullptr);
            _test_case.test(hrr_mismatch_ret, __FUNCTION__, "compose a full-handshake ServerHello after declining the HRR PSK");
            if ((errorcode_t::success == hrr_mismatch_ret) && (nullptr != hrr_mismatch_server_hello)) {
                _test_case.assert(tls_flow_t::hello_retry_request == hrr_mismatch_protection.get_flow(), __FUNCTION__,
                                  "preserve the HRR transcript flow when the selected PSK hash is incompatible");
                _test_case.assert(nullptr == hrr_mismatch_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                                  "omit pre_shared_key after declining the incompatible ClientHello2 identity");
                _test_case.assert(hrr_mismatch_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                  "clear the selected PSK early secret while retaining the HRR transcript");
                _test_case.assert(0xffff == hrr_mismatch_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                  "clear the selected identity when ClientHello2 falls back to a full handshake");
                _test_case.assert(0 == hrr_mismatch_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                  "clear the ticket suite when ClientHello2 falls back to a full handshake");
                _test_case.assert(0 == hrr_mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                                  "revoke the early-data allowance when ClientHello2 falls back to a full handshake");
                _test_case.assert(0 == hrr_mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                                  "keep early data rejected on the non-PSK fallback path after HRR");
                hrr_mismatch_server_hello->release();
            } else if (nullptr != hrr_mismatch_server_hello) {
                hrr_mismatch_server_hello->release();
            }
        }
    }
}

template <typename Configure>
static void test_tls13_psk_offer_declines_incompatible_ticket_hash(const binary_t& wire, const tls_resumption_ticket& ticket1, Configure configure) {
    // Scenario: TLS 1.3 declines PSK when the server-preferred cipher-suite hash differs from the ticket.
    // Action: verify a SHA-256 ticket binder, then prefer the SHA-384 cipher suite during ServerHello composition.
    // Expected: decline PSK and clear the ticket Early Secret, identity and early-data allowance.
    _test_case.begin("TLS 1.3 declines PSK when the server-preferred cipher-suite hash differs from the ticket");
    // The server may prefer a different TLS 1.3 cipher-suite hash than
    // the selected ticket. It must preserve that suite preference, decline
    // PSK resumption, and clear the ticket's early-data/key-schedule state.
    {
        tls_session mismatch_server;
        configure(mismatch_server);
        mismatch_server.get_tls_protection().set_cipher_suite(0);
        mismatch_server.store_resumption_ticket(ticket1);
        tls_records mismatch_records;
        return_t mismatch_ret = mismatch_records.read(&mismatch_server, from_client, wire);
        _test_case.test(mismatch_ret, __FUNCTION__, "verify a SHA-256 ticket offered alongside SHA-384-first cipher-suite preferences");
        if (errorcode_t::success == mismatch_ret) {
            auto& mismatch_protection = mismatch_server.get_tls_protection();
            auto& mismatch_context = mismatch_protection.get_protection_context();
            _test_case.assert(tls_flow_t::zero_rtt == mismatch_protection.get_flow(), __FUNCTION__,
                              "retain PSK resumption after binder verification and before suite negotiation");
            uint64 mismatch_early_data_limit = mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit);
            _test_case.assert(4096 == mismatch_early_data_limit, __FUNCTION__, "recognize the ticket's early-data allowance before suite compatibility is evaluated");

            mismatch_context.clear_cipher_suites();
            mismatch_context.add_cipher_suite(0x1302).add_cipher_suite(0x1301);

            tls_handshake* mismatch_server_hello = nullptr;
            mismatch_ret = tls_composer::construct_server_hello(&mismatch_server_hello, &mismatch_server, nullptr);
            _test_case.test(mismatch_ret, __FUNCTION__, "compose ServerHello after preferring the SHA-384 cipher suite");
            if ((errorcode_t::success == mismatch_ret) && (nullptr != mismatch_server_hello)) {
                uint16 negotiated_suite = static_cast<tls_handshake_server_hello*>(mismatch_server_hello)->get_cipher_suite();
                _test_case.assert(0x1302 == negotiated_suite, __FUNCTION__, "preserve the server's negotiated SHA-384 cipher-suite preference");
                _test_case.assert(nullptr == mismatch_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                                  "omit ServerHello pre_shared_key when the selected ticket uses a different hash");
                _test_case.assert(tls_flow_t::one_rtt == mismatch_protection.get_flow(), __FUNCTION__,
                                  "continue with a full-handshake flow after declining the incompatible PSK");
                _test_case.assert(mismatch_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                  "clear the selected ticket's early secret before the full-handshake key schedule");
                _test_case.assert(0xffff == mismatch_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                  "clear the selected PSK identity after declining resumption");
                _test_case.assert(0 == mismatch_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                                  "clear the selected ticket cipher-suite metadata after declining resumption");
                _test_case.assert(0 == mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                                  "revoke the ticket's early-data allowance after declining its PSK");
                _test_case.assert(0 == mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                                  "ensure early data is not marked accepted after PSK decline");
                mismatch_server_hello->release();
            } else if (nullptr != mismatch_server_hello) {
                mismatch_server_hello->release();
            }
        }
    }
}

static void test_tls13_client_multiple_ticket_psk_offer() {
    // Scenario under test: TLS 1.3 client offers multiple cached PSK tickets with independent SHA-256 and SHA-384 binders.
    // Action: compose ClientHello, verify ticket-specific binders, and exercise identity selection, expiry, early-data, and fallback cases.
    // Expected: preserve identity-to-ticket mapping and clear PSK state whenever resumption is declined.
    _test_case.begin("TLS 1.3 client offers multiple cached tickets with independent binders");

    const binary_t identity1 = {0xa1, 0x01};
    const binary_t identity2 = {0xa2, 0x02};
    const binary_t psk1(32, 0x11);
    const binary_t psk2(32, 0x22);
    const binary_t identity3 = {0xa3, 0x03};
    const binary_t psk3(48, 0x33);
    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    auto configure = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        openssl_digest digest;
        binary_t empty;
        binary_t empty_hash;
        return_t ret = digest.digest("sha256", empty, empty_hash);
        _test_case.test(ret, __FUNCTION__, "prepare the empty transcript hash for each ticket binder");
        protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    };

    tls_resumption_ticket ticket1;
    ticket1.identity = identity1;
    ticket1.nonce = {0x00, 0x01};
    ticket1.psk = psk1;
    ticket1.lifetime = 3600;
    ticket1.age_add = 0x10203040;
    ticket1.timestamp = now_ms - 20;
    ticket1.version = tls1_3;
    ticket1.cipher_suite = 0x1301;
    ticket1.max_early_data_size = 4096;

    tls_resumption_ticket ticket2;
    ticket2.identity = identity2;
    ticket2.nonce = {0x00, 0x02};
    ticket2.psk = psk2;
    ticket2.lifetime = 3600;
    ticket2.age_add = 0x50607080;
    ticket2.timestamp = now_ms - 35;
    ticket2.version = tls1_3;
    // 0x1303 uses the same SHA-256 hash as 0x1301. A ticket issued
    // under either suite can therefore share this ClientHello binder hash.
    ticket2.cipher_suite = 0x1303;

    tls_resumption_ticket ticket3;
    ticket3.identity = identity3;
    ticket3.nonce = {0x00, 0x03};
    ticket3.psk = psk3;
    ticket3.lifetime = 3600;
    ticket3.age_add = 0x90a0b0c0;
    ticket3.timestamp = now_ms - 45;
    ticket3.version = tls1_3;
    // 0x1302 uses SHA-384; its binder is independent of the SHA-256 binders.
    ticket3.cipher_suite = 0x1302;

    tls_session client;
    configure(client);
    client.get_tls_protection().set_cipher_suite(0);
    client.store_resumption_ticket(ticket1);
    client.store_resumption_ticket(ticket2);
    client.store_resumption_ticket(ticket3);

    // Use the same composer path as production ClientHello construction. The
    // composer registers supported_groups, key_share, PSK modes, and the
    // supported_versions extension before the PSK offer is attached by the hook.
    tls_handshake* client_hello = nullptr;
    return_t ret = tls_composer::construct_client_hello(&client_hello, &client, [](tls_handshake* handshake, tls_direction_t) -> return_t {
        handshake->get_extensions().add(tls_extension_type_t::early_data, from_client, handshake, nullptr);
        handshake->get_extensions().add(tls_extension_type_t::pre_shared_key, from_client, handshake, nullptr);
        return errorcode_t::success;
    });
    _test_case.test(ret, __FUNCTION__, "construct ClientHello through the TLS composer");
    if ((errorcode_t::success != ret) || (nullptr == client_hello)) {
        return;
    }
    auto& client_protection_context = client.get_tls_protection().get_protection_context();
    _test_case.assert(tls_group_t::unknown != client_protection_context.get0_supported_group(), __FUNCTION__,
                      "retain the composed supported_groups offer in the client context");
    _test_case.assert(tls_group_t::unknown != client_protection_context.get0_keyshare_group(), __FUNCTION__, "retain the composed key_share offer in the client context");

    tls_record_handshake record(&client);
    record << client_hello;
    binary_t wire;
    ret = record.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello with two cached resumption tickets");
    if (errorcode_t::success != ret) {
        return;
    }

    size_t extension_block = 5 + 4 + 2 + 32;
    extension_block += 1 + wire[extension_block];
    uint16 cipher_suites_size = (static_cast<uint16>(wire[extension_block]) << 8) | wire[extension_block + 1];
    extension_block += 2 + cipher_suites_size;
    extension_block += 1 + wire[extension_block];
    uint16 extensions_size = (static_cast<uint16>(wire[extension_block]) << 8) | wire[extension_block + 1];
    size_t extension_pos = extension_block + 2;
    size_t extensions_end = extension_pos + extensions_size;
    size_t psk_offset = wire.size();
    bool key_share_present = false;
    while (extension_pos + 4 <= extensions_end) {
        uint16 extension_type = (static_cast<uint16>(wire[extension_pos]) << 8) | wire[extension_pos + 1];
        uint16 extension_size = (static_cast<uint16>(wire[extension_pos + 2]) << 8) | wire[extension_pos + 3];
        if (static_cast<uint16>(tls_extension_type_t::key_share) == extension_type) {
            key_share_present = true;
        }
        if (static_cast<uint16>(tls_extension_type_t::pre_shared_key) == extension_type) {
            psk_offset = extension_pos;
            break;
        }
        extension_pos += 4 + extension_size;
    }
    _test_case.assert(key_share_present, __FUNCTION__, "serialize the ClientHello key_share extension through the composer");
    _test_case.assert(psk_offset < wire.size(), __FUNCTION__, "locate the serialized pre_shared_key extension");
    if (psk_offset >= wire.size()) {
        return;
    }

    size_t pos = psk_offset + 4;
    uint16 identities_length = (static_cast<uint16>(wire[pos]) << 8) | wire[pos + 1];
    pos += 2;
    size_t identities_end = pos + identities_length;
    size_t identity_count = 0;
    while (pos + 2 <= identities_end) {
        uint16 identity_length = (static_cast<uint16>(wire[pos]) << 8) | wire[pos + 1];
        pos += 2 + identity_length + 4;
        ++identity_count;
    }
    _test_case.assert(3 == identity_count, __FUNCTION__, "offer all cached tickets with their respective hash algorithms");

    uint16 binders_length = (static_cast<uint16>(wire[pos]) << 8) | wire[pos + 1];
    pos += 2;
    size_t first_binder_value_offset = pos + 1;
    size_t binders_end = pos + binders_length;
    size_t binder_count = 0;
    std::vector<uint8> binder_lengths;
    while (pos < binders_end) {
        uint8 binder_length = wire[pos++];
        bool nonzero = false;
        for (size_t i = 0; i < binder_length && pos + i < binders_end; ++i) {
            nonzero = nonzero || (0 != wire[pos + i]);
        }
        _test_case.assert(nonzero, __FUNCTION__, "compute a nonzero binder for each offered ticket");
        binder_lengths.emplace_back(binder_length);
        pos += binder_length;
        ++binder_count;
    }
    _test_case.assert(3 == binder_count, __FUNCTION__, "emit one binder for each offered identity");
    _test_case.assert((binder_lengths.size() == 3) && (32 == binder_lengths[0]) && (32 == binder_lengths[1]) && (48 == binder_lengths[2]), __FUNCTION__,
                      "encode SHA-256 and SHA-384 binder entries with their own digest lengths");
    _test_case.assert(pos == binders_end, __FUNCTION__, "consume the complete binders vector");

    // 0-RTT traffic keys must use the first PSK identity on the wire. The
    // session may contain several cached tickets, and its prior
    // resumption_early value is not a reliable substitute for identity zero.
    binary_t expected_first_early_secret;
    ret = client.get_tls_protection().calc_resumption_early_secret(psk1, expected_first_early_secret);
    _test_case.test(ret, __FUNCTION__, "derive the first offered ticket's Early Secret");
    if (errorcode_t::success == ret) {
        _test_case.assert(expected_first_early_secret == client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                          "retain identity zero's Early Secret for 0-RTT traffic-key derivation");
    }

    // A server that knows only identity zero must derive the same early
    // traffic secret and record keys as the client before EncryptedExtensions.
    tls_session early_server;
    configure(early_server);
    early_server.get_tls_protection().set_cipher_suite(0);
    early_server.store_resumption_ticket(ticket1);
    tls_records early_server_records;
    binary_t early_server_wire = wire;
    ret = early_server_records.read(&early_server, from_client, early_server_wire);
    _test_case.test(ret, __FUNCTION__, "parse the multi-ticket ClientHello using the first cached ticket");
    if (errorcode_t::success == ret) {
        const auto& client_secrets = client.get_tls_protection().get_secrets();
        const auto& server_secrets = early_server.get_tls_protection().get_secrets();
        _test_case.assert(client_secrets.get(tls_secret_t::resumption_early) == server_secrets.get(tls_secret_t::resumption_early), __FUNCTION__,
                          "derive the same Early Secret from wire identity zero");
        _test_case.assert(client_secrets.get(tls_secret_t::c_e_traffic) == server_secrets.get(tls_secret_t::c_e_traffic), __FUNCTION__,
                          "derive matching client early traffic secrets");
        _test_case.assert(client_secrets.get(tls_secret_t::c_e_traffic_key) == server_secrets.get(tls_secret_t::c_e_traffic_key), __FUNCTION__,
                          "derive matching client early traffic keys");
        _test_case.assert(client_secrets.get(tls_secret_t::c_e_traffic_iv) == server_secrets.get(tls_secret_t::c_e_traffic_iv), __FUNCTION__,
                          "derive matching client early traffic IVs");
    }

    {
        tls_session hrr_client;
        configure(hrr_client);
        hrr_client.get_tls_protection().set_cipher_suite(0x1302);
        hrr_client.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        hrr_client.store_resumption_ticket(ticket1);
        hrr_client.store_resumption_ticket(ticket2);
        hrr_client.store_resumption_ticket(ticket3);

        tls_handshake_client_hello hrr_hello(&hrr_client);
        hrr_hello.add_ciphersuite(0x1301);
        hrr_hello.add_ciphersuite(0x1302);
        hrr_hello.add_ciphersuite(0x1303);
        tls_extension_client_psk hrr_psk(&hrr_hello);
        binary_t hrr_wire;
        return_t hrr_ret = hrr_psk.write(from_client, hrr_wire);
        _test_case.test(hrr_ret, __FUNCTION__, "compose ClientHello2 PSKs using the HRR-selected cipher-suite hash");
        if (errorcode_t::success == hrr_ret) {
            _test_case.assert(1 == hrr_psk.get_identity_count(), __FUNCTION__, "omit SHA-256 PSKs after the server selected SHA-384 in HRR");
            auto hrr_tickets = hrr_client.get_offered_resumption_tickets();
            _test_case.assert((hrr_tickets.size() == 1) && (hrr_tickets.front().identity == identity3), __FUNCTION__,
                              "retain only the SHA-384 ticket compatible with the HRR-selected suite");
        }
    }

    test_tls13_psk_offer_omits_hash_incompatible_ticket(ticket1, ticket3, configure);

    // The server knows only the second identity. It must verify binder index 1
    // with that ticket's PSK rather than reusing the first ticket's PSK.
    tls_session server;
    configure(server);
    server.get_tls_protection().set_cipher_suite(0);
    server.store_resumption_ticket(ticket2);
    tls_records records;
    binary_t server_wire = wire;
    if (first_binder_value_offset < server_wire.size()) {
        server_wire[first_binder_value_offset] ^= 0xff;
    }
    ret = records.read(&server, from_client, server_wire);
    _test_case.test(ret, __FUNCTION__, "ignore the unknown first identity and verify only the selected second identity's binder");
    if (errorcode_t::success != ret) {
        return;
    }

    // ClientHello parsing and server negotiation are separate handshake phases.
    // At this point the server has processed the PSK offer and verified its binder,
    // but the composer has not yet run protection.negotiate()/select_from().
    binary_t expected_early_secret;
    return_t early_ret = server.get_tls_protection().calc_resumption_early_secret(psk2, expected_early_secret);
    _test_case.test(early_ret, __FUNCTION__, "derive early secret from the selected ticket PSK");
    _test_case.assert(expected_early_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                      "select the PSK associated with the matching second identity");
    _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "retain the resumption flow after verifying the matching binder");
    _test_case.assert(0 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                      "do not accept early data when the selected PSK is not the first offered identity");

    {
        tls_session unknown_server;
        configure(unknown_server);
        unknown_server.get_tls_protection().set_cipher_suite(0);
        tls_records unknown_records;
        return_t unknown_ret = unknown_records.read(&unknown_server, from_client, wire);
        _test_case.test(unknown_ret, __FUNCTION__, "ignore all unknown PSK identities and continue with a full handshake");
        if (errorcode_t::success == unknown_ret) {
            _test_case.assert(tls_flow_t::one_rtt == unknown_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "fall back to the non-PSK handshake when no offered identity is acceptable");
            _test_case.assert(unknown_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                              "do not retain an unknown PSK as the resumption early secret");
        }
    }

    test_tls13_psk_offer_verifies_sha384_binder(wire, ticket3, configure);

    test_tls13_psk_offer_ticket_age_mismatch(wire, ticket1, now_ms, configure);

    test_tls13_psk_offer_retires_expired_earlier_identity(wire, ticket1, ticket2, identity2, now_ms, configure);

    test_tls13_psk_offer_declines_incompatible_ticket_hash(wire, ticket1, configure);

    test_tls13_psk_offer_hrr_declines_incompatible_ticket_hash(wire, ticket1, configure);

    test_tls13_psk_offer_clears_state_on_suite_failure(wire, ticket1, configure);

    test_tls13_psk_offer_client_restores_selected_ticket_psk(server, client, psk2);

    test_tls13_psk_offer_rejects_mismatched_server_identity(wire, ticket2, configure);
}

static void test_tls13_client_falls_back_when_server_declines_psk() {
    // Scenario under test: TLS 1.3 client discards the offered PSK when the server declines resumption.
    // Action: prepare the ClientHello binder transcript hash.
    // Expected: decline PSK resumption when the ticket identity is unknown.
    _test_case.begin("TLS 1.3 client discards the offered PSK when the server declines resumption");

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket ticket;
    ticket.identity = {0xb1, 0x01};
    ticket.nonce = {0x00, 0x01};
    ticket.psk = binary_t(32, 0x31);
    ticket.lifetime = 3600;
    ticket.age_add = 0x10203040;
    ticket.timestamp = now_ms - 10;
    ticket.cipher_suite = 0x1301;

    auto configure = [](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        openssl_digest digest;
        binary_t empty;
        binary_t empty_hash;
        return_t ret = digest.digest("sha256", empty, empty_hash);
        _test_case.test(ret, __FUNCTION__, "prepare the ClientHello binder transcript hash");
        protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    };

    tls_session client;
    configure(client);
    client.get_tls_protection().set_cipher_suite(0);
    client.store_resumption_ticket(ticket);

    tls_handshake* client_hello = nullptr;
    return_t ret = tls_composer::construct_client_hello(&client_hello, &client, [](tls_handshake* handshake, tls_direction_t) -> return_t {
        handshake->get_extensions().add(tls_extension_type_t::pre_shared_key, from_client, handshake, nullptr);
        return errorcode_t::success;
    });
    _test_case.test(ret, __FUNCTION__, "construct a ClientHello offering the cached ticket");
    if ((errorcode_t::success != ret) || (nullptr == client_hello)) {
        return;
    }

    tls_record_handshake client_record(&client);
    client_record << client_hello;
    binary_t client_hello_wire;
    ret = client_record.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the ClientHello with its PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session server;
    configure(server);
    // This server has no matching ticket and must continue with a full handshake.
    tls_records client_hello_records;
    ret = client_hello_records.read(&server, from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "ignore the unknown ticket identity and continue ClientHello processing");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "decline PSK resumption when the ticket identity is unknown");

    tls_handshake* server_hello = nullptr;
    ret = tls_composer::construct_server_hello(&server_hello, &server, nullptr);
    _test_case.test(ret, __FUNCTION__, "construct a full-handshake ServerHello without a PSK selection");
    if ((errorcode_t::success != ret) || (nullptr == server_hello)) {
        return;
    }
    _test_case.assert(nullptr == server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                      "omit ServerHello pre_shared_key when the server declines the ticket");

    binary_t server_hello_wire;
    ret = server_hello->write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the full-handshake ServerHello");
    // Match the record-layer post-write boundary for this direct handshake write.
    server.run_scheduled(from_server);
    server_hello->release();
    if (errorcode_t::success != ret) {
        return;
    }

    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    tls_handshake_server_hello server_hello_reader(&client);
    size_t server_hello_pos = 0;
    ret = server_hello_reader.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept the ServerHello that declines PSK resumption");
    auto& client_protection = client.get_tls_protection();
    auto& server_protection = server.get_tls_protection();
    auto& client_secrets = client_protection.get_secrets();
    auto& server_secrets = server_protection.get_secrets();
    _test_case.assert(tls_flow_t::one_rtt == client_protection.get_flow(), __FUNCTION__, "switch the client to the full-handshake key schedule");
    _test_case.assert(client_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "discard the cached PSK early secret before deriving handshake traffic keys");
    _test_case.assert(server_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "keep the server's key schedule free of an unselected PSK");
    _test_case.assert(
        !client_secrets.get(tls_secret_t::early_secret).empty() && client_secrets.get(tls_secret_t::early_secret) == server_secrets.get(tls_secret_t::early_secret),
        __FUNCTION__, "derive the same zero-PSK early secret at both endpoints");
    _test_case.assert(!client_secrets.get(tls_secret_t::handshake).empty() && client_secrets.get(tls_secret_t::handshake) == server_secrets.get(tls_secret_t::handshake),
                      __FUNCTION__, "derive matching full-handshake secrets from the negotiated (EC)DHE input");
    _test_case.assert(server_hello_wire.size() == server_hello_pos, __FUNCTION__, "consume the complete ServerHello");
}

static void test_tls13_psk_ke_serverhello_roundtrip() {
    // Scenario under test: TLS 1.3 psk_ke ServerHello, key schedule, and 0-RTT acceptance.
    // Action: prepare a client with one SHA-256 resumption ticket.
    // Expected: record the serialized ClientHello early_data offer.
    _test_case.begin("TLS 1.3 psk_ke ServerHello, key schedule, and 0-RTT acceptance");

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket ticket;
    ticket.identity = {0xc1, 0x01};
    ticket.nonce = {0x00, 0x01};
    ticket.psk = binary_t(32, 0x41);
    ticket.lifetime = 3600;
    ticket.age_add = 0x10203040;
    ticket.timestamp = now_ms - 20;
    ticket.cipher_suite = 0x1301;
    ticket.version = static_cast<uint16>(tls1_3);
    ticket.max_early_data_size = 4096;

    auto configure = [&](tls_session& session) -> return_t {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        session.store_resumption_ticket(ticket);

        openssl_digest digest;
        binary_t empty;
        binary_t empty_hash;
        return_t digest_ret = digest.digest("sha256", empty, empty_hash);
        if (errorcode_t::success == digest_ret) {
            protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
        }
        return digest_ret;
    };

    tls_session client;
    return_t ret = configure(client);
    _test_case.test(ret, __FUNCTION__, "prepare a client with one SHA-256 resumption ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);
    auto versions = new tls_extension_client_supported_versions(client_hello);
    versions->add(tls1_3);
    client_hello->get_extensions().add(versions);
    auto modes = new tls_extension_psk_key_exchange_modes(client_hello);
    modes->add(0);  // psk_ke only
    client_hello->get_extensions().add(modes);
    client_hello->get_extensions().add(new tls_extension_early_data(client_hello));
    client_hello->get_extensions().add(tls_extension_type_t::pre_shared_key, from_client, client_hello, nullptr);

    tls_record_handshake client_record(&client);
    client_record << client_hello;
    binary_t client_hello_wire;
    ret = client_record.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a ClientHello offering psk_ke and early_data");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "record the serialized ClientHello early_data offer");
    _test_case.assert(4096 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                      "bind the client 0-RTT limit to the first PSK ticket");
    tls_session server;
    ret = configure(server);
    _test_case.test(ret, __FUNCTION__, "prepare a server with the matching resumption ticket");
    if (errorcode_t::success != ret) {
        return;
    }
    // The rejected-ciphertext budget is server policy, independent of the
    // ticket's plaintext max_early_data_size.
    server.set_early_data_discard_limit(8192);

    tls_records records;
    ret = records.read(&server, from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello, record the early_data offer, and verify its PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "record the peer's early_data offer before EncryptedExtensions");
    _test_case.assert(4096 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                      "derive the server 0-RTT limit from the selected identity-zero ticket");
    _test_case.assert(8192 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_discard_limit), __FUNCTION__,
                      "retain the independently configured ciphertext discard bound");
    tls_handshake* server_hello = nullptr;
    ret = tls_composer::construct_server_hello(&server_hello, &server, nullptr);
    _test_case.test(ret, __FUNCTION__, "compose ServerHello for a psk_ke-only offer");
    if ((errorcode_t::success != ret) || (nullptr == server_hello)) {
        if (nullptr != server_hello) {
            server_hello->release();
        }
        return;
    }

    _test_case.assert(nullptr == server_hello->get_extensions().get(tls_extension_type_t::key_share), __FUNCTION__, "omit ServerHello key_share when psk_ke is selected");
    _test_case.assert(nullptr != server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                      "acknowledge the selected PSK identity in ServerHello");
    _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__, "retain the selected psk_ke mode for the server key schedule");

    binary_t server_hello_wire;
    ret = server_hello->write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the psk_ke ServerHello and derive handshake traffic secrets");
    // Match the record-layer post-write boundary for this direct handshake write.
    server.run_scheduled(from_server);
    server_hello->release();
    if (errorcode_t::success != ret) {
        return;
    }

    const binary_t& server_shared_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(binary_t(32, 0) == server_shared_secret, __FUNCTION__, "use Hash.length zero bytes as the absent (EC)DHE input");

    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    tls_handshake_server_hello server_hello_reader(&client);
    size_t server_hello_pos = 0;
    ret = server_hello_reader.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept the psk_ke ServerHello without key_share");
    _test_case.assert(server_hello_wire.size() == server_hello_pos, __FUNCTION__, "consume the complete psk_ke ServerHello");
    _test_case.assert(0 == client.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__, "record the selected psk_ke mode on the client");

    const auto& client_shared_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(server_shared_secret == client_shared_secret, __FUNCTION__, "derive the same zero (EC)DHE input on both peers");
    _test_case.assert(
        server.get_tls_protection().get_secrets().get(tls_secret_t::c_hs_traffic) == client.get_tls_protection().get_secrets().get(tls_secret_t::c_hs_traffic),
        __FUNCTION__, "derive matching client handshake traffic secrets");
    _test_case.assert(
        server.get_tls_protection().get_secrets().get(tls_secret_t::s_hs_traffic) == client.get_tls_protection().get_secrets().get(tls_secret_t::s_hs_traffic),
        __FUNCTION__, "derive matching server handshake traffic secrets");
    _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                      "retain the early traffic flow while the server decides whether to accept 0-RTT");
    _test_case.assert(tls_flow_t::zero_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "retain the client early traffic flow until EncryptedExtensions");
    _test_case.assert(server.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate server-side early traffic decryption after ServerHello");
    _test_case.assert(client.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate client-side early traffic protection after ServerHello");

    tls_handshake_encrypted_extensions server_ee(&server);
    server_ee.get_extensions().add(new tls_extension_early_data(&server_ee));
    binary_t server_ee_wire;
    ret = server_ee.write(from_server, server_ee_wire);
    _test_case.test(ret, __FUNCTION__, "accept early data in EncryptedExtensions when the selected ticket matches");
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record server acceptance only after serializing the early_data extension");
    _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "keep early traffic keys active after server acceptance");

    tls_handshake_encrypted_extensions client_ee(&client);
    size_t client_ee_pos = 0;
    ret = client_ee.read(from_server, server_ee_wire.data(), server_ee_wire.size(), client_ee_pos);
    _test_case.test(ret, __FUNCTION__, "validate server early-data acceptance against the selected PSK ticket");
    _test_case.assert(server_ee_wire.size() == client_ee_pos, __FUNCTION__, "consume the complete EncryptedExtensions message");
    _test_case.assert(1 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record validated client acceptance of 0-RTT");
    _test_case.assert(tls_flow_t::zero_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "keep client early traffic keys active after valid acceptance");
}

static void test_tls13_psk_offer_requires_key_exchange_modes() {
    // Scenario under test: TLS 1.3 PSK offer requires psk_key_exchange_modes.
    // Action: construct a TLS 1.3-capable ClientHello.
    // Expected: locate ClientHello session ID.
    _test_case.begin("TLS 1.3 PSK offer requires psk_key_exchange_modes");

    tls_session client;
    client.set_type(session_type_t::tls);
    binary_t wire;
    return_t ret = test_client_supportedversion_clienthello(&client, tls1_2, tls1_3, wire);
    _test_case.test(ret, __FUNCTION__, "construct a TLS 1.3-capable ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Remove the composer-generated psk_key_exchange_modes extension, then
    // append a structurally valid PSK extension as the final ClientHello
    // extension. The server has no matching ticket, so binder verification
    // is not the subject of this test.
    size_t pos = 9 + 2 + 32;
    if (pos >= wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello session ID");
        return;
    }
    uint8 session_id_len = wire[pos++];
    pos += session_id_len;
    if (pos + 2 > wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello cipher suites");
        return;
    }
    uint16 cipher_suites_len = test_read_u16(wire, pos);
    pos += 2 + cipher_suites_len;
    if (pos >= wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello compression methods");
        return;
    }
    uint8 compression_methods_len = wire[pos++];
    pos += compression_methods_len;
    if (pos + 2 > wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello extensions length");
        return;
    }

    size_t extensions_length_pos = pos;
    uint16 extensions_length = test_read_u16(wire, pos);
    pos += 2;
    size_t extension_pos = pos;
    size_t extensions_end = extension_pos + extensions_length;
    if (extensions_end != wire.size()) {
        _test_case.assert(false, __FUNCTION__, "validate ClientHello extension boundary");
        return;
    }

    bool removed_modes = false;
    while (extension_pos + 4 <= extensions_end) {
        uint16 extension_type = test_read_u16(wire, extension_pos);
        uint16 extension_size = test_read_u16(wire, extension_pos + 2);
        size_t extension_end = extension_pos + 4 + extension_size;
        if (extension_end > extensions_end) {
            _test_case.assert(false, __FUNCTION__, "validate extension length while locating PSK modes");
            return;
        }
        if (static_cast<uint16>(tls_extension_type_t::psk_key_exchange_modes) == extension_type) {
            size_t removed_size = 4 + extension_size;
            wire.erase(wire.begin() + extension_pos, wire.begin() + extension_end);
            test_write_u16(wire, extensions_length_pos, static_cast<uint16>(extensions_length - removed_size));
            test_write_u24(wire, 6, test_read_u24(wire, 6) - static_cast<uint32>(removed_size));
            test_write_u16(wire, 3, static_cast<uint16>(test_read_u16(wire, 3) - removed_size));
            removed_modes = true;
            break;
        }
        extension_pos = extension_end;
    }
    _test_case.assert(removed_modes, __FUNCTION__, "remove psk_key_exchange_modes from ClientHello");
    if (!removed_modes) {
        return;
    }

    binary_t psk_extension = {
        0x00, 0x29, 0x00, 0x2c,  // pre_shared_key extension header
        0x00, 0x07,              // identities vector length
        0x00, 0x01, 0xaa,        // one-byte identity
        0x00, 0x00, 0x00, 0x00,  // obfuscated_ticket_age
        0x00, 0x21,              // binders vector length
        0x20                     // binder length
    };
    psk_extension.insert(psk_extension.end(), 32, 0x00);
    wire.insert(wire.end(), psk_extension.begin(), psk_extension.end());
    test_write_u16(wire, extensions_length_pos, static_cast<uint16>(test_read_u16(wire, extensions_length_pos) + psk_extension.size()));
    test_write_u24(wire, 6, test_read_u24(wire, 6) + static_cast<uint32>(psk_extension.size()));
    test_write_u16(wire, 3, static_cast<uint16>(test_read_u16(wire, 3) + psk_extension.size()));

    tls_session server;
    server.set_type(session_type_t::tls);
    tls_records records;
    ret = records.read(&server, from_client, wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a PSK offer without psk_key_exchange_modes");

    size_t missing_extension_alerts = test_count_fatal_alert(server, from_client, tls_alertdesc_t::missing_extension);
    _test_case.assert(1 == missing_extension_alerts, __FUNCTION__, "send fatal missing_extension for the omitted PSK modes extension");

    // RFC 8446 4.2.11 also requires pre_shared_key to be the final
    // ClientHello extension. Put psk_key_exchange_modes after it and verify
    // that the server rejects the ordering before processing the PSK binder.
    binary_t reordered_wire = wire;
    const binary_t trailing_modes = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
    reordered_wire.insert(reordered_wire.end(), trailing_modes.begin(), trailing_modes.end());
    test_write_u16(reordered_wire, extensions_length_pos, static_cast<uint16>(test_read_u16(reordered_wire, extensions_length_pos) + trailing_modes.size()));
    test_write_u24(reordered_wire, 6, test_read_u24(reordered_wire, 6) + static_cast<uint32>(trailing_modes.size()));
    test_write_u16(reordered_wire, 3, static_cast<uint16>(test_read_u16(reordered_wire, 3) + trailing_modes.size()));

    tls_session reordered_server;
    reordered_server.set_type(session_type_t::tls);
    tls_records reordered_records;
    ret = reordered_records.read(&reordered_server, from_client, reordered_wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject pre_shared_key when another extension follows it");

    size_t illegal_parameter_alerts = test_count_fatal_alert(reordered_server, from_client, tls_alertdesc_t::illegal_parameter);
    _test_case.assert(1 == illegal_parameter_alerts, __FUNCTION__, "send fatal illegal_parameter when pre_shared_key is not the final extension");
}

static void test_tls13_psk_key_exchange_modes_vector() {
    // Scenario under test: TLS 1.3 PSK key exchange modes vector boundaries.
    // Action: read the psk_ke and psk_dhe_ke modes.
    // Expected: reject an empty, truncated, or trailing PSK modes vector.
    _test_case.begin("TLS 1.3 PSK key exchange modes vector boundaries");

    tls_session session;
    session.set_type(session_type_t::tls);
    tls_handshake_client_hello client_hello(&session);

    const std::array<binary_t, 4> malformed = {
        binary_t{0x00, 0x2d, 0x00, 0x00},                    // empty extension body
        binary_t{0x00, 0x2d, 0x00, 0x01, 0x00},              // empty modes vector
        binary_t{0x00, 0x2d, 0x00, 0x02, 0x02, 0x00},        // declared vector exceeds body
        binary_t{0x00, 0x2d, 0x00, 0x03, 0x01, 0x00, 0x01},  // trailing byte beyond vector
    };
    for (const auto& wire : malformed) {
        tls_extension_psk_key_exchange_modes extension(&client_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_client, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an empty, truncated, or trailing PSK modes vector");
    }

    {
        tls_extension_psk_key_exchange_modes extension(&client_hello);
        binary_t wire;
        return_t ret = extension.write(from_client, wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "do not serialize an empty PSK modes vector");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no malformed PSK modes extension");
    }

    {
        const binary_t wire = {0x00, 0x2d, 0x00, 0x03, 0x02, 0x00, 0x01};
        tls_extension_psk_key_exchange_modes extension(&client_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the psk_ke and psk_dhe_ke modes");
        if (errorcode_t::success == ret) {
            _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete PSK modes extension");
            _test_case.assert(0x03 == extension.get_modes(), __FUNCTION__, "retain both recognized PSK key exchange modes");
        }
    }

    {
        binary_t wire = {0x00, 0x2d, 0x01, 0x00, 0xff};
        wire.insert(wire.end(), 255, 0x01);
        tls_extension_psk_key_exchange_modes extension(&client_hello);
        size_t pos = 0;
        return_t ret = extension.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "accept the maximum 255-entry PSK modes vector");
        if (errorcode_t::success == ret) {
            _test_case.assert(wire.size() == pos, __FUNCTION__, "consume all 255 PSK mode entries");
        }
    }

    {
        tls_extension_psk_key_exchange_modes extension(&client_hello);
        for (uint16 i = 0; i < 256; ++i) {
            extension.add(1);
        }
        binary_t wire;
        return_t ret = extension.write(from_client, wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject serialization of more than 255 PSK modes");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no oversized PSK modes extension");
    }
}

static void test_tls13_psk_key_exchange_modes_message_scope() {
    // Action: place psk_key_exchange_modes in EncryptedExtensions and parse it on the receiving endpoint.
    // Scenario under test: TLS 1.3 PSK key exchange modes are ClientHello-only.
    // Expected: reject psk_key_exchange_modes received in EncryptedExtensions.
    _test_case.begin("TLS 1.3 PSK key exchange modes are ClientHello-only");

    {
        tls_session receiver;
        receiver.set_type(session_type_t::tls);
        tls_handshake_encrypted_extensions encrypted_extensions(&receiver);
        tls_extension_psk_key_exchange_modes extension(&encrypted_extensions);
        const binary_t wire = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
        size_t pos = 0;
        return_t ret = extension.read(from_server, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject psk_key_exchange_modes received in EncryptedExtensions");
        size_t illegal_parameter_count = test_count_fatal_alert(receiver, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report one fatal illegal_parameter for the misplaced extension");
    }

    {
        tls_session sender;
        sender.set_type(session_type_t::tls);
        tls_handshake_encrypted_extensions encrypted_extensions(&sender);
        tls_extension_psk_key_exchange_modes extension(&encrypted_extensions);
        extension.add(1);
        binary_t wire;
        return_t ret = extension.write(from_server, wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "do not serialize psk_key_exchange_modes in server EncryptedExtensions");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no forbidden PSK modes extension");
    }

    {
        tls_session receiver;
        receiver.set_type(session_type_t::tls);
        auto& protection = receiver.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        receiver.update_session_status(session_status_client_hello);
        receiver.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        binary_t body = {0x03, 0x03};                                                                     // legacy_version
        body.insert(body.end(), 32, 0x00);                                                                // random
        body.insert(body.end(), {0x00, 0x13, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,  // supported_versions = TLS 1.3
                                 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01});                                    // forbidden psk_key_exchange_modes
        uint32 body_size = t_narrow_cast(body.size());
        binary_t wire = {static_cast<byte_t>(tls_handshake_type_t::server_hello), static_cast<byte_t>(body_size >> 16), static_cast<byte_t>(body_size >> 8),
                         static_cast<byte_t>(body_size)};
        wire.insert(wire.end(), body.begin(), body.end());

        tls_handshake_server_hello server_hello(&receiver);
        size_t pos = 0;
        return_t ret = server_hello.read(from_server, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__,
                          "reject psk_key_exchange_modes received in a TLS 1.3 ServerHello through the generic extension-context guard");
        size_t illegal_parameter_count = test_count_fatal_alert(receiver, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for psk_key_exchange_modes in ServerHello");
        _test_case.assert(0 == receiver.get_session_status(), __FUNCTION__, "reset handshake status after the forbidden ServerHello extension");
    }
}

static void test_tls13_psk_ticket_sni_binding() {
    // Scenario under test: TLS 1.3 cached PSKs are bound to their original SNI.
    // Action: prepare the ClientHello binder transcript hash.
    // Expected: omit a ticket issued for a different server name.
    _test_case.begin("TLS 1.3 cached PSKs are bound to their original SNI");

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket matching;
    matching.identity = {0xb1, 0x01};
    matching.server_name = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    matching.psk = binary_t(32, 0x41);
    matching.lifetime = 3600;
    matching.timestamp = now_ms - 10;
    matching.cipher_suite = 0x1301;

    tls_resumption_ticket different;
    different.identity = {0xb2, 0x02};
    different.server_name = {'o', 't', 'h', 'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
    different.psk = binary_t(32, 0x42);
    different.lifetime = 3600;
    different.timestamp = now_ms - 10;
    different.cipher_suite = 0x1301;

    auto configure = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.get_tls_protection().set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.set_client_server_name({'E', 'X', 'A', 'M', 'P', 'L', 'E', '.', 'C', 'O', 'M'});

        openssl_digest digest;
        binary_t empty;
        binary_t empty_hash;
        return_t digest_ret = digest.digest("sha256", empty, empty_hash);
        _test_case.test(digest_ret, __FUNCTION__, "prepare the ClientHello binder transcript hash");
        session.get_tls_protection().get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    };

    {
        tls_session client;
        configure(client);
        client.store_resumption_ticket(matching);
        client.store_resumption_ticket(different);

        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0x1301);
        tls_extension_client_psk psk(&hello);
        binary_t wire;
        return_t ret = psk.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "serialize only tickets associated with the current SNI");
        if (errorcode_t::success == ret) {
            _test_case.assert(1 == psk.get_identity_count(), __FUNCTION__, "omit a ticket issued for a different server name");
            auto offered = client.get_offered_resumption_tickets();
            _test_case.assert((offered.size() == 1) && (offered.front().identity == matching.identity), __FUNCTION__,
                              "retain only the matching SNI ticket in ClientHello identity order");
        }
    }

    {
        tls_session client;
        configure(client);
        client.store_resumption_ticket(different);
        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0x1301);
        tls_extension_client_psk psk(&hello);
        binary_t wire;
        return_t ret = psk.write(from_client, wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "decline resumption when no ticket matches the current SNI");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no PSK extension for a different server name");
    }
}

static void test_tls13_client_psk_hrr_filters_mixed_hash_tickets() {
    // Scenario under test: TLS 1.3 ClientHello2 filters PSKs by the HRR-selected hash.
    // Action: prepare the SHA-256 binder hash selected by HelloRetryRequest.
    // Expected: remove the incompatible SHA-384 identity from ClientHello2.
    _test_case.begin("TLS 1.3 ClientHello2 filters PSKs by the HRR-selected hash");

    const uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    tls_resumption_ticket sha256_first;
    sha256_first.identity = {0xa1};
    sha256_first.psk = binary_t(32, 0x11);
    sha256_first.lifetime = 3600;
    sha256_first.timestamp = now_ms - 10;
    sha256_first.cipher_suite = 0x1301;

    tls_resumption_ticket sha384_middle;
    sha384_middle.identity = {0xb2};
    sha384_middle.psk = binary_t(48, 0x22);
    sha384_middle.lifetime = 3600;
    sha384_middle.timestamp = now_ms - 10;
    sha384_middle.cipher_suite = 0x1302;

    tls_resumption_ticket sha256_last = sha256_first;
    sha256_last.identity = {0xc3};
    sha256_last.cipher_suite = 0x1303;

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& protection = client.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1303);
    protection.set_flow(tls_flow_t::hello_retry_request);
    client.get_keyvalue().set(session_tls_version, tls1_3);
    client.store_resumption_ticket(sha256_first);
    client.store_resumption_ticket(sha384_middle);
    client.store_resumption_ticket(sha256_last);

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "prepare the SHA-256 binder hash selected by HelloRetryRequest");
    if (errorcode_t::success != ret) {
        return;
    }
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    tls_handshake_client_hello hello(&client);
    hello.add_ciphersuite(0x1301);
    hello.add_ciphersuite(0x1303);
    tls_extension_client_psk psk(&hello);
    binary_t wire;
    ret = psk.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 PSK identities under the HRR-selected SHA-256 hash");
    if (errorcode_t::success != ret) {
        return;
    }

    const auto offered = client.get_offered_resumption_tickets();
    _test_case.assert(2 == psk.get_identity_count(), __FUNCTION__, "remove the incompatible SHA-384 identity from ClientHello2");
    _test_case.assert((2 == offered.size()) && (offered[0].identity == sha256_first.identity) && (offered[1].identity == sha256_last.identity), __FUNCTION__,
                      "preserve the relative order of compatible SHA-256 identities");
    _test_case.assert(0x1303 == protection.get_cipher_suite(), __FUNCTION__, "retain the exact cipher suite selected by HelloRetryRequest");
}

static void test_tls13_early_data_uses_first_serializable_psk_identity() {
    // Scenario under test: TLS 1.3 early_data allowance follows the first serializable PSK identity.
    // Action: prepare the empty transcript hash for the PSK binder.
    // Expected: derive the early-data allowance from the first identity that can actually be serialized.
    _test_case.begin("TLS 1.3 early_data allowance follows the first serializable PSK identity");

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& protection = client.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    client.get_keyvalue().set(session_tls_version, tls1_3);
    client.update_session_status(session_status_server_finished);
    client.update_session_status(session_status_client_finished);
    client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket oversized_ticket;
    oversized_ticket.identity.assign(0x10000, 0x11);
    oversized_ticket.psk = binary_t(32, 0x31);
    oversized_ticket.cipher_suite = 0x1301;
    oversized_ticket.version = static_cast<uint16>(tls1_3);
    oversized_ticket.lifetime = 3600;
    oversized_ticket.timestamp = now_ms - 100;
    oversized_ticket.max_early_data_size = 8192;
    client.store_resumption_ticket(oversized_ticket);

    // This identity length is representable in its uint16 field, but the
    // identity, binder, and enclosing vector lengths exceed the complete
    // pre_shared_key extension body's uint16 limit.
    tls_resumption_ticket extension_oversized_ticket;
    extension_oversized_ticket.identity.assign(65493, 0x12);
    extension_oversized_ticket.psk = binary_t(32, 0x32);
    extension_oversized_ticket.cipher_suite = 0x1301;
    extension_oversized_ticket.version = static_cast<uint16>(tls1_3);
    extension_oversized_ticket.lifetime = 3600;
    extension_oversized_ticket.timestamp = now_ms - 100;
    extension_oversized_ticket.max_early_data_size = 4096;
    client.store_resumption_ticket(extension_oversized_ticket);

    tls_resumption_ticket serializable_ticket;
    serializable_ticket.identity = {0x22, 0x23};
    serializable_ticket.psk = binary_t(48, 0x42);
    serializable_ticket.cipher_suite = 0x1302;
    serializable_ticket.version = static_cast<uint16>(tls1_3);
    serializable_ticket.lifetime = 3600;
    serializable_ticket.timestamp = now_ms - 100;
    serializable_ticket.max_early_data_size = 1024;
    client.store_resumption_ticket(serializable_ticket);

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha384", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "prepare the empty transcript hash for the PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);
    client_hello->add_ciphersuite(0x1302);
    auto versions = new tls_extension_client_supported_versions(client_hello);
    versions->add(tls1_3);
    client_hello->get_extensions().add(versions);
    auto modes = new tls_extension_psk_key_exchange_modes(client_hello);
    modes->add(1);  // psk_dhe_ke
    client_hello->get_extensions().add(modes);
    client_hello->get_extensions().add(new tls_extension_early_data(client_hello));
    client_hello->get_extensions().add(new tls_extension_client_psk(client_hello));

    tls_record_handshake record(&client);
    record << client_hello;
    binary_t wire;
    ret = record.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello after filtering identities that exceed the complete PSK extension size limit");
    if (errorcode_t::success != ret) {
        return;
    }

    const auto& early_state = client.get_session_info(from_server).get_keyvalue();
    _test_case.assert(1024 == early_state.get(session_early_data_limit), __FUNCTION__,
                      "derive the early-data allowance from the first identity that can actually be serialized");
    _test_case.assert(1 == early_state.get(session_early_data_offered), __FUNCTION__, "retain the eligible early_data offer");
    _test_case.assert(tls_flow_t::zero_rtt == protection.get_flow(), __FUNCTION__, "enter zero_rtt only with the serializable first ticket");
    _test_case.assert(0x1302 == protection.get_cipher_suite(), __FUNCTION__, "select the cipher-suite hash belonging to the first identity actually serialized");

    binary_t expected_serializable_early_secret;
    ret = protection.calc_resumption_early_secret(serializable_ticket.psk, expected_serializable_early_secret);
    _test_case.test(ret, __FUNCTION__, "derive the Early Secret for the first serializable ticket");
    if (errorcode_t::success == ret) {
        _test_case.assert(expected_serializable_early_secret == protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                          "use the first serializable PSK identity for early traffic-key derivation");
    }
    tls_resumption_ticket retained_early_ticket = client.get_early_data_ticket();
    _test_case.assert(serializable_ticket.identity == retained_early_ticket.identity, __FUNCTION__,
                      "bind early-data metadata to the first PSK identity emitted on the wire");
    auto offered_tickets = client.get_offered_resumption_tickets();
    _test_case.assert(1 == offered_tickets.size(), __FUNCTION__, "omit both oversized identities from the serialized PSK offer");
    if (1 == offered_tickets.size()) {
        _test_case.assert(serializable_ticket.identity == offered_tickets.front().identity, __FUNCTION__,
                          "keep the offered-ticket index aligned with the PSK identities on the wire");
    }
}

static void test_tls13_clienthello_early_key_schedule_failure_is_terminal() {
    // Scenario: ClientHello early-data key-schedule derivation fails locally.
    // Action: run ClientHello postprocessing for both read and write operations with an invalid suite.
    // Expected: queue one fatal internal_error and clear all provisional PSK and early-data state.
    _test_case.begin("TLS 1.3 ClientHello early key-schedule failure terminates the session");

    class client_hello_postprocess_probe : public tls_handshake_client_hello {
       public:
        explicit client_hello_postprocess_probe(tls_session* session) : tls_handshake_client_hello(session) {}
        return_t run_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) { return do_postprocess(dir, opdir, stream, size); }
    };

    const byte_t marker = 0;
    for (auto opdir : {tls_io_operation_t::read, tls_io_operation_t::write}) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0);
        protection.set_flow(tls_flow_t::zero_rtt);
        return_t ret = protection.reset_transcript_hash(&session);
        _test_case.test(ret, __FUNCTION__, "initialize the TLS 1.3 ClientHello transcript");

        auto& secrets = protection.get_secrets();
        secrets.assign(tls_secret_t::resumption_early, binary_t(32, 0x44));
        secrets.assign(tls_secret_t::c_e_traffic, binary_t(32, 0x55));
        secrets.assign(tls_secret_t::e_exp_master, binary_t(32, 0x66));
        secrets.assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x77));
        secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x88));

        tls_resumption_ticket ticket;
        ticket.identity = {0xa1, 0xb2, 0xc3};
        ticket.psk = binary_t(32, 0x44);
        ticket.cipher_suite = 0x1301;
        ticket.version = static_cast<uint16>(tls1_3);
        ticket.lifetime = 3600;
        ticket.timestamp = 1;
        ticket.max_early_data_size = 1024;
        session.set_early_data_ticket(ticket);
        session.set_offered_resumption_tickets(std::vector<tls_resumption_ticket>{ticket});
        session.get_keyvalue().set(session_server_psk_selected_identity, 0);
        session.get_keyvalue().set(session_server_psk_key_exchange_mode, 1);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);
        session.get_keyvalue().set(session_client_psk_identity_count, 1);

        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        early_state.set(session_early_data_offered_initial, 1);
        early_state.set(session_early_data_limit, 1024);

        client_hello_postprocess_probe hello(&session);
        hello.get_extensions().add(new tls_extension_psk_key_exchange_modes(&hello));
        auto psk = new tls_extension_client_psk(&hello);
        psk->set_suppressed(tls_io_operation_t::write == opdir);
        hello.get_extensions().add(psk);
        hello.get_extensions().add(new tls_extension_early_data(&hello));

        ret = hello.run_postprocess(from_client, opdir, &marker, sizeof(marker));
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "propagate the local ClientHello key-schedule failure");

        size_t fatal_internal_error_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::internal_error);
        _test_case.assert(1 == fatal_internal_error_count, __FUNCTION__, "queue exactly one fatal internal_error for the local key-schedule failure");
        _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "do not commit ClientHello handshake status after key-schedule failure");
        _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "leave zero_rtt after the failed early key schedule");
        _test_case.assert(0xffff == session.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "clear the provisional selected PSK identity");
        _test_case.assert(0 == session.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__, "clear provisional ticket cipher-suite metadata");
        _test_case.assert(session.get_offered_resumption_tickets().empty(), __FUNCTION__, "clear the provisional offered-ticket snapshot");
        _test_case.assert(session.get_early_data_ticket().identity.empty(), __FUNCTION__, "clear the provisional early-data ticket");
        _test_case.assert(0 == early_state.get(session_early_data_offered), __FUNCTION__, "clear the early_data offer state");
        _test_case.assert(0 == early_state.get(session_early_data_offered_initial), __FUNCTION__, "clear the initial early_data offer state");
        _test_case.assert(0 == early_state.get(session_early_data_limit), __FUNCTION__, "clear the early-data allowance");
        _test_case.assert(secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "clear the retained resumption Early Secret");
        _test_case.assert(secrets.get(tls_secret_t::c_e_traffic).empty(), __FUNCTION__, "clear the partial client early traffic secret");
        _test_case.assert(secrets.get(tls_secret_t::e_exp_master).empty(), __FUNCTION__, "clear the partial early exporter secret");
        _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_key).empty(), __FUNCTION__, "clear the partial client early traffic key");
        _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_iv).empty(), __FUNCTION__, "clear the partial client early traffic IV");
    }
}

static void test_tls13_serverhello_key_schedule_failure_is_terminal() {
    // Scenario: ServerHello key-schedule derivation fails locally after HRR.
    // Action: run ServerHello postprocessing with a TLS 1.3 HRR transcript and an invalid suite.
    // Expected: preserve the failure, queue one fatal internal_error, and clear provisional state.
    _test_case.begin("TLS 1.3 ServerHello key-schedule failure is terminal");

    class server_hello_postprocess_probe : public tls_handshake_server_hello {
       public:
        explicit server_hello_postprocess_probe(tls_session* session) : tls_handshake_server_hello(session) {}
        return_t run_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) { return do_postprocess(dir, opdir, stream, size); }
    };

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0);
    protection.set_flow(tls_flow_t::hello_retry_request);
    return_t ret = protection.reset_transcript_hash(&session);
    _test_case.test(ret, __FUNCTION__, "initialize the HRR transcript before ServerHello");

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::client_hello, binary_t{0x01, 0x00, 0x00, 0x00});
    secrets.assign(tls_secret_t::resumption_early, binary_t(32, 0x44));
    secrets.assign(tls_secret_t::c_e_traffic, binary_t(32, 0x55));
    secrets.assign(tls_secret_t::e_exp_master, binary_t(32, 0x66));
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x77));
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x88));

    session.get_keyvalue().set(session_tls_version, tls1_3);
    session.get_keyvalue().set(session_server_psk_selected_identity, 0);
    session.get_keyvalue().set(session_server_psk_key_exchange_mode, 1);
    session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);

    tls_resumption_ticket ticket;
    ticket.identity = {0xa1, 0xb2, 0xc3};
    ticket.psk = binary_t(32, 0x44);
    ticket.cipher_suite = 0x1301;
    ticket.version = static_cast<uint16>(tls1_3);
    ticket.lifetime = 3600;
    ticket.timestamp = 1;
    ticket.max_early_data_size = 1024;
    session.set_early_data_ticket(ticket);
    session.set_offered_resumption_tickets(std::vector<tls_resumption_ticket>{ticket});

    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_limit, 1024);

    session.update_session_status(session_status_client_hello);
    session.update_session_status(session_status_hello_retry_request);
    session.get_session_info(from_client).begin_protection();

    server_hello_postprocess_probe hello(&session);
    // A TLS 1.3 ServerHello must carry supported_versions. Without it,
    // do_postprocess() treats the message as TLS 1.2 and exits through the
    // downgrade check before reaching the key schedule.
    hello.get_extensions().add(tls_extension_type_t::supported_versions, from_server, &hello, [](tls_extension* extension) -> return_t {
        static_cast<tls_extension_server_supported_versions*>(extension)->set(tls1_3);
        return errorcode_t::success;
    });
    _test_case.assert(tls1_3 == protection.get_tls_version(), __FUNCTION__, "keep TLS 1.3 selected by the ServerHello supported_versions extension");
    const byte_t marker = 0;
    ret = hello.run_postprocess(from_server, tls_io_operation_t::write, &marker, sizeof(marker));
    _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__,
                      "preserve the local key-schedule failure instead of overwriting it while resuming pending records");

    std::set<tls_alertdesc_t> fatal_alerts;
    size_t fatal_alert_count = test_collect_fatal_alerts(session, from_server, fatal_alerts);
    _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue exactly one fatal alert for the local key-schedule failure");
    _test_case.assert(fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::internal_error}, __FUNCTION__,
                      "queue internal_error without protocol_version for the local key-schedule failure");
    _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "reset handshake status after ServerHello key-schedule failure");
    _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "leave HRR flow after terminal ServerHello failure");
    _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                      "disable residual client-direction protection after ServerHello failure during HRR");
    _test_case.assert(0xffff == session.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "clear provisional selected_identity");
    _test_case.assert(0 == session.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__, "clear provisional ticket cipher-suite metadata");
    _test_case.assert(session.get_offered_resumption_tickets().empty(), __FUNCTION__, "clear provisional offered-ticket snapshot");
    _test_case.assert(session.get_early_data_ticket().identity.empty(), __FUNCTION__, "clear provisional early-data ticket");
    _test_case.assert(0 == early_state.get(session_early_data_offered), __FUNCTION__, "clear the early_data offer");
    _test_case.assert(0 == early_state.get(session_early_data_offered_initial), __FUNCTION__, "clear the initial early_data offer");
    _test_case.assert(0 == early_state.get(session_early_data_limit), __FUNCTION__, "clear the early-data allowance");
    _test_case.assert(secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "clear the retained resumption Early Secret");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic).empty(), __FUNCTION__, "clear the client early traffic secret");
    _test_case.assert(secrets.get(tls_secret_t::e_exp_master).empty(), __FUNCTION__, "clear the early exporter secret");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_key).empty(), __FUNCTION__, "clear the client early traffic key");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_iv).empty(), __FUNCTION__, "clear the client early traffic IV");
}

void testcase_gpt_psk_offer() {
    test_tls13_serverhello_key_schedule_failure_is_terminal();
    test_tls13_clienthello_early_key_schedule_failure_is_terminal();
    test_tls13_early_data_uses_first_serializable_psk_identity();
    test_tls13_client_psk_hrr_filters_mixed_hash_tickets();
    test_tls13_server_psk_selected_identity_encoding();
    test_tls13_server_psk_selected_identity_range();
    test_tls13_client_multiple_ticket_psk_offer();
    test_tls13_client_falls_back_when_server_declines_psk();
    test_tls13_psk_ke_serverhello_roundtrip();
    test_tls13_psk_offer_requires_key_exchange_modes();
    test_tls13_psk_key_exchange_modes_vector();
    test_tls13_psk_key_exchange_modes_message_scope();
    test_tls13_psk_ticket_sni_binding();
}
