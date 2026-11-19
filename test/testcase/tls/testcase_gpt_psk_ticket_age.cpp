/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk_ticket_age.cpp
 * @author GPT
 * @desc   TLS 1.3 PSK ticket-age calculation, expiration, and client fallback tests.
 */

#include <algorithm>
#include <chrono>

#include "testcase_gpt_common.hpp"

static void test_tls13_psk_ticket_age_limit() {
    // Scenario under test: TLS 1.3 PSK ticket age seven-day limit.
    // Expected: validate the binder for a ticket within the seven-day limit.
    _test_case.begin("TLS 1.3 PSK ticket age seven-day limit");

    const uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
    struct test_vector {
        uint32 ticket_lifetime;
        uint32 ticket_age_ms;
        uint32 ticket_age_add;
        bool expect_binder_validation;
        const char* description;
    };
    const std::array<test_vector, 6> vectors = {
        {{0, 0, 0, false, "decline a zero-lifetime PSK"},
         {3600, 3600 * 1000, 0x10203040, true, "allow a ticket at its advertised lifetime boundary"},
         {3600, 3600 * 1000 + 1, 0x50607080, false, "decline a ticket beyond its advertised lifetime"},
         {max_ticket_lifetime + 3600, max_ticket_lifetime * 1000 - 1, 0x12345678, true, "allow an age immediately below seven days"},
         {max_ticket_lifetime + 3600, max_ticket_lifetime * 1000, 0x87654321, true, "allow an age exactly at seven days"},
         {max_ticket_lifetime + 3600, max_ticket_lifetime * 1000 + 1, 0xdeadbeef, false, "decline an age beyond seven days even with larger metadata"}}};

    for (const auto& vector : vectors) {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().set_cipher_suite(0x1301);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        session.get_keyvalue().set(session_tls_version, tls_13);
        session.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xaa});
        session.get_tls_protection().get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x11));
        auto& kv = session.get_session_info(from_server).get_keyvalue();
        kv.set(session_ticket_lifetime, vector.ticket_lifetime);
        kv.set(session_ticket_age_add, vector.ticket_age_add);
        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        // The parser samples the wall clock after this fixture timestamp is set.
        // For an exact advertised/effective lifetime boundary, keep the server-side
        // issuance age one second inside the limit while preserving the exact
        // obfuscated_ticket_age in the wire vector. This isolates the age-vector
        // boundary from millisecond scheduling during the test.
        uint64 server_ticket_age_ms = vector.ticket_age_ms;
        uint64 effective_lifetime_ms = static_cast<uint64>((vector.ticket_lifetime > max_ticket_lifetime) ? max_ticket_lifetime : vector.ticket_lifetime) * 1000;
        // The parser samples the clock after this timestamp is set. Keep
        // near-boundary server-side ages one second inside the limit so
        // scheduling latency cannot expire a ticket whose wire age is still
        // within the intended inclusive seven-day boundary. The wire vector
        // below retains its exact boundary value for binder validation.
        if (vector.expect_binder_validation && (0 != effective_lifetime_ms) && (server_ticket_age_ms >= effective_lifetime_ms - 1000)) {
            server_ticket_age_ms -= 1000;
        }
        kv.set(session_ticket_timestamp, now_ms - server_ticket_age_ms);

        uint32 obfuscated_ticket_age = vector.ticket_age_ms + vector.ticket_age_add;
        binary_t wire = {0x00,
                         0x29,
                         0x00,
                         0x2c,  // pre_shared_key extension header
                         0x00,
                         0x07,  // identities vector length
                         0x00,
                         0x01,
                         0xaa,  // identity
                         (byte_t)(obfuscated_ticket_age >> 24),
                         (byte_t)(obfuscated_ticket_age >> 16),
                         (byte_t)(obfuscated_ticket_age >> 8),
                         (byte_t)obfuscated_ticket_age,
                         0x00,
                         0x21,   // binders vector length
                         0x20};  // binder length
        wire.insert(wire.end(), 32, 0x00);

        tls_handshake_client_hello handshake(&session);
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_client, wire.data(), wire.size(), pos);

        if (vector.expect_binder_validation) {
            // The deliberately invalid binder must be checked for an in-range ticket.
            _test_case.assert(nullptr == parsed, __FUNCTION__, vector.description);
            size_t decrypt_error_count = 0;
            session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decrypt_error == desc)) {
                    ++decrypt_error_count;
                }
            });
            _test_case.assert(1 == decrypt_error_count, __FUNCTION__, "validate the binder for a ticket within the seven-day limit");
        } else {
            _test_case.assert(nullptr != parsed, __FUNCTION__, vector.description);
            if (parsed) {
                parsed->release();
            }
            _test_case.assert(tls_flow_t::one_rtt == session.get_tls_protection().get_flow(), __FUNCTION__,
                              "fall back to a full handshake for an expired or zero-lifetime ticket");
            _test_case.assert(0 == session.get_keyvalue().get(session_tls_version), __FUNCTION__, "reset the prior negotiated version before a full handshake");
            _test_case.assert(session.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                              "discard the expired or zero-lifetime ticket");
            _test_case.assert(session.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                              "discard the resumption PSK together with its expired ticket");
            _test_case.assert(0 == kv.get(session_ticket_lifetime), __FUNCTION__, "clear the expired ticket lifetime metadata");
            _test_case.assert(0 == kv.get(session_ticket_age_add), __FUNCTION__, "clear the expired ticket age_add metadata");
            _test_case.assert(0 == kv.get(session_ticket_timestamp), __FUNCTION__, "clear the expired ticket issuance timestamp");
        }
    }
}

static void test_tls13_psk_expired_clienthello_fallback() {
    // Scenario under test: TLS 1.3 expired PSK ClientHello full-handshake fallback.
    // Action: construct a TLS 1.3-capable ClientHello.
    // Expected: locate ClientHello session ID.
    _test_case.begin("TLS 1.3 expired PSK ClientHello full-handshake fallback");

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls_13);
    server.get_tls_protection().set_tls_version(tls_13);
    server.get_keyvalue().set(session_tls_version, tls_13);
    // Model a fully completed TLS 1.3 handshake: the plaintext ClientHello
    // phase gate requires both Finished messages before accepting a new
    // ClientHello for a resumption attempt.
    server.update_session_status(session_status_server_finished);
    server.update_session_status(session_status_client_finished);
    server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

    constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
    constexpr uint32 ticket_age_add = 0x50607080;
    constexpr uint32 expired_ticket_age_ms = max_ticket_lifetime * 1000 + 1;
    auto& server_kv = server.get_session_info(from_server).get_keyvalue();
    server_kv.set(session_ticket_lifetime, max_ticket_lifetime + 3600);
    server_kv.set(session_ticket_age_add, ticket_age_add);
    server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xaa});

    binary_t client_hello;
    return_t ret = test_client_supportedversion_clienthello(&client, tls_12, tls_13, client_hello);
    _test_case.test(ret, __FUNCTION__, "construct a TLS 1.3-capable ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Locate the ClientHello extensions vector in the TLSPlaintext record.
    size_t pos = 9 + 2 + 32;
    if (pos >= client_hello.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello session ID");
        return;
    }
    uint8 session_id_len = client_hello[pos++];
    pos += session_id_len;
    if (pos + 2 > client_hello.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello cipher suites");
        return;
    }
    uint16 cipher_suites_len = test_read_u16(client_hello, pos);
    pos += 2 + cipher_suites_len;
    if (pos >= client_hello.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello compression methods");
        return;
    }
    uint8 compression_methods_len = client_hello[pos++];
    pos += compression_methods_len;
    if (pos + 2 > client_hello.size()) {
        _test_case.assert(false, __FUNCTION__, "locate ClientHello extensions length");
        return;
    }

    size_t extensions_len_pos = pos;
    uint16 extensions_len = test_read_u16(client_hello, pos);
    pos += 2;
    if (pos + extensions_len != client_hello.size()) {
        _test_case.assert(false, __FUNCTION__, "validate ClientHello extension vector boundary");
        return;
    }

    uint32 obfuscated_ticket_age = expired_ticket_age_ms + ticket_age_add;
    binary_t psk_extension = {0x00,
                              0x29,
                              0x00,
                              0x2c,  // pre_shared_key extension header
                              0x00,
                              0x07,  // identities vector length
                              0x00,
                              0x01,
                              0xaa,  // identity
                              (byte_t)(obfuscated_ticket_age >> 24),
                              (byte_t)(obfuscated_ticket_age >> 16),
                              (byte_t)(obfuscated_ticket_age >> 8),
                              (byte_t)obfuscated_ticket_age,
                              0x00,
                              0x21,   // binders vector length
                              0x20};  // binder length
    psk_extension.insert(psk_extension.end(), 32, 0x00);

    client_hello.insert(client_hello.end(), psk_extension.begin(), psk_extension.end());
    test_write_u16(client_hello, extensions_len_pos, extensions_len + (uint16)psk_extension.size());
    test_write_u24(client_hello, 6, test_read_u24(client_hello, 6) + (uint32)psk_extension.size());
    test_write_u16(client_hello, 3, test_read_u16(client_hello, 3) + (uint16)psk_extension.size());

    tls_records records;
    ret = records.read(&server, from_client, client_hello);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello with an expired PSK and complete full-handshake fallback");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "keep the ClientHello on the full-handshake path");
        _test_case.assert(0 == server.get_keyvalue().get(session_tls_version), __FUNCTION__, "clear the prior negotiated version during full-handshake fallback");
        _test_case.assert(server.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                          "discard the expired ticket before completing ClientHello processing");
        _test_case.assert(session_status_client_hello == (server.get_session_status() & session_status_client_hello), __FUNCTION__,
                          "complete ClientHello state transition after declining the expired PSK");
    }
}

static void test_tls13_client_ticket_age_fallback() {
    // Scenario under test: TLS 1.3 client enforces advertised and seven-day ticket lifetime.
    // Action: prepare the empty transcript hash for PSK binder generation.
    // Expected: retain a usable ticket.
    _test_case.begin("TLS 1.3 client enforces advertised and seven-day ticket lifetime");

    constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
    struct test_vector {
        uint32 ticket_lifetime;
        uint64 ticket_age_ms;
        bool future_timestamp;
        bool expect_resumption;
        const char* description;
    };
    // These cases exercise the live ClientHello path, which samples the
    // wall clock after the fixture timestamp is written. Keep a ten-second
    // margin on either side so setup/runtime latency cannot move a vector
    // across the intended boundary. Exact equality remains inclusive in the
    // production <= comparisons; a live wall-clock test cannot pin that
    // comparison to a deterministic millisecond.
    const std::array<test_vector, 6> vectors = {{
        {3600, 3590 * 1000ULL, false, true, "retain a ticket ten seconds before its advertised lifetime"},
        {3600, 3610 * 1000ULL, false, false, "decline a ticket ten seconds beyond its advertised lifetime"},
        {max_ticket_lifetime + 3600, (max_ticket_lifetime - 10) * 1000ULL, false, true, "retain a ticket ten seconds before the seven-day limit"},
        {max_ticket_lifetime + 3600, (max_ticket_lifetime + 10) * 1000ULL, false, false, "decline a ticket ten seconds beyond seven days despite larger metadata"},
        {0, 0, false, false, "decline a zero-lifetime ticket"},
        {3600, 0, true, false, "decline a ticket with a future issuance timestamp"},
    }};

    // The valid-ticket cases serialize a PSK binder. Its binder key derivation
    // requires the hash of the empty transcript, just like the other PSK
    // ClientHello serialization tests.
    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t digest_ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(digest_ret, __FUNCTION__, "prepare the empty transcript hash for PSK binder generation");
    if (errorcode_t::success != digest_ret) {
        return;
    }

    for (const auto& vector : vectors) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);

        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
        ticket_kv.set(session_ticket_lifetime, vector.ticket_lifetime);
        ticket_kv.set(session_ticket_age_add, 0x50607080);
        ticket_kv.set(session_ticket_timestamp, vector.future_timestamp ? now_ms + 1000 : now_ms - vector.ticket_age_ms);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xaa});
        protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x11));
        protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

        tls_handshake_client_hello client_hello(&session);
        client_hello.add_ciphersuite(0x1301);
        // This test covers PSK ticket eligibility, not 0-RTT data.
        // Keep pre_shared_key as the final ClientHello extension.
        auto psk_modes = new tls_extension_psk_key_exchange_modes(&client_hello);
        psk_modes->add(1);  // psk_dhe_ke
        client_hello.get_extensions().add(psk_modes);
        client_hello.get_extensions().add(tls_extension_type_t::pre_shared_key, from_client, &client_hello);

        binary_t encoded;
        return_t ret = client_hello.write(from_client, encoded);
        _test_case.test(ret, __FUNCTION__, vector.description);
        if (errorcode_t::success != ret) {
            continue;
        }

        if (vector.expect_resumption) {
            _test_case.assert(tls_flow_t::zero_rtt == protection.get_flow(), __FUNCTION__, "keep a ticket within both its advertised lifetime and seven-day maximum");
            _test_case.assert(!protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "retain a usable ticket");
            _test_case.assert(!protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "retain the resumption PSK for a usable ticket");
            _test_case.assert(vector.ticket_lifetime == ticket_kv.get(session_ticket_lifetime), __FUNCTION__, "preserve lifetime metadata for a usable ticket");
            _test_case.assert(0x50607080 == ticket_kv.get(session_ticket_age_add), __FUNCTION__, "preserve age_add metadata for a usable ticket");
        } else {
            _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "select a full handshake for an unusable ticket");
            _test_case.assert(protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "discard the unusable ticket");
            _test_case.assert(protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "discard the unusable ticket PSK");
            _test_case.assert(0 == ticket_kv.get(session_ticket_lifetime), __FUNCTION__, "clear unusable ticket lifetime metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_age_add), __FUNCTION__, "clear unusable ticket age_add metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_timestamp), __FUNCTION__, "clear unusable ticket issuance timestamp");
            _test_case.assert(0 == session.get_keyvalue().get(session_tls_version), __FUNCTION__, "clear the previous negotiated TLS version");
        }
    }
}

static void test_tls13_client_psk_writer_ticket_lifetime() {
    // Scenario under test: TLS 1.3 client PSK writer enforces ticket lifetime.
    // Action: serialize a PSK extension while the ticket remains within its effective lifetime.
    // Expected: emit no PSK extension for an expired or zero-lifetime ticket.
    _test_case.begin("TLS 1.3 client PSK writer enforces ticket lifetime");

    constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
    constexpr uint32 ticket_age_add = 0x50607080;
    const binary_t ticket = {0xaa, 0xbb, 0xcc};
    const binary_t resumption_psk(32, 0x11);

    auto verify_writer = [&](uint32 advertised_lifetime, uint64 ticket_age_ms, bool expect_success, const char* description) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
        protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);

        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
        ticket_kv.set(session_ticket_lifetime, advertised_lifetime);
        ticket_kv.set(session_ticket_age_add, ticket_age_add);
        ticket_kv.set(session_ticket_timestamp, now_ms - ticket_age_ms);

        tls_handshake_client_hello client_hello(&session);
        tls_extension_client_psk extension(&client_hello);
        binary_t wire;
        return_t ret = extension.write(from_client, wire);
        if (expect_success) {
            _test_case.test(ret, __FUNCTION__, description);
            if (errorcode_t::success == ret) {
                _test_case.assert(!wire.empty(), __FUNCTION__, "serialize a PSK extension while the ticket remains within its effective lifetime");
            }
        } else {
            _test_case.assert(errorcode_t::success != ret, __FUNCTION__, description);
            _test_case.assert(wire.empty(), __FUNCTION__, "emit no PSK extension for an expired or zero-lifetime ticket");
        }
    };

    verify_writer(3600, 3599000, true, "allow a PSK ticket before its advertised lifetime expires");
    verify_writer(3600, 3600001, false, "reject a PSK ticket one millisecond beyond its advertised lifetime");
    verify_writer(0, 0, false, "reject a zero-lifetime PSK ticket in the extension writer");
    verify_writer(max_ticket_lifetime + 3600, static_cast<uint64>(max_ticket_lifetime - 1) * 1000, true,
                  "allow a PSK ticket immediately before the seven-day cap when the advertised lifetime is longer");
    verify_writer(max_ticket_lifetime + 3600, static_cast<uint64>(max_ticket_lifetime) * 1000 + 1, false,
                  "reject a PSK ticket one millisecond beyond the seven-day cap even when the advertised lifetime is longer");
}

void testcase_gpt_psk_ticket_age() {
    test_tls13_psk_ticket_age_limit();
    test_tls13_psk_expired_clienthello_fallback();
    test_tls13_client_ticket_age_fallback();
    test_tls13_client_psk_writer_ticket_lifetime();
}
