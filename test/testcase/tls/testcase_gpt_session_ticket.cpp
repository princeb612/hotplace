/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_session_ticket.cpp
 * @author GPT
 * @desc   TLS 1.3 NewSessionTicket lifecycle tests.
 */

#include <algorithm>
#include <chrono>
#include <memory>
#include <vector>

#include "testcase_gpt_common.hpp"

static void test_tls13_new_session_ticket_lifetime_boundaries(const char* function_name, uint32 max_ticket_lifetime) {
    // Scenario under test: TLS 1.3 NewSessionTicket lifetime boundaries.
    // Action: parse tickets with zero, boundary, and over-limit lifetimes.
    // Expected: cap cached lifetime at seven days and discard zero-lifetime tickets.
    const std::array<uint32, 4> lifetimes = {0, max_ticket_lifetime - 1, max_ticket_lifetime, max_ticket_lifetime + 1};

    for (uint32 lifetime : lifetimes) {
        binary_t wire = {0x04, 0x00, 0x00, 0x0e};
        wire.push_back((byte_t)(lifetime >> 24));
        wire.push_back((byte_t)(lifetime >> 16));
        wire.push_back((byte_t)(lifetime >> 8));
        wire.push_back((byte_t)lifetime);
        // Zero age_add, empty nonce, one-byte ticket identity, and empty extensions.
        wire.insert(wire.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00});

        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x22));
        if (0 != lifetime) {
            protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        }

        tls_handshake_new_session_ticket ticket(&session);
        size_t pos = 0;
        return_t ret = ticket.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "read NewSessionTicket lifetime boundary");
        if (errorcode_t::success != ret) {
            continue;
        }

        uint32 expected_lifetime = (lifetime > max_ticket_lifetime) ? max_ticket_lifetime : lifetime;
        uint32 stored_lifetime = t_narrow_cast(session.get_session_info(from_server).get_keyvalue().get(session_ticket_lifetime));
        _test_case.assert(expected_lifetime == stored_lifetime, function_name, "cap cached ticket lifetime at seven days");
        _test_case.assert(wire.size() == pos, function_name, "consume complete NewSessionTicket message");

        const binary_t& stored_ticket = session.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket);
        if (0 == lifetime) {
            _test_case.assert(stored_ticket.empty(), function_name, "discard a zero-lifetime ticket immediately");
            _test_case.assert(binary_t(32, 0x22) == session.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), function_name,
                              "leave the active early secret untouched when discarding a zero-lifetime ticket");
            const auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
            _test_case.assert(0 == ticket_kv.get(session_ticket_lifetime), function_name, "clear zero-lifetime ticket lifetime metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_age_add), function_name, "clear zero-lifetime ticket age_add metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_timestamp), function_name, "clear zero-lifetime ticket issuance timestamp");
        } else {
            _test_case.assert(binary_t{0xaa} == stored_ticket, function_name, "retain a nonzero-lifetime ticket");
        }
    }
}

static void test_tls13_new_session_ticket_rejects_empty_identity(const char* function_name) {
    // Scenario under test: TLS 1.3 NewSessionTicket with an empty ticket identity.
    // Action: parse a ticket whose opaque identity has zero length.
    // Expected: reject it without replacing previously cached metadata.
    // RFC 8446 requires a non-empty ticket identity (opaque<1..2^16-1>).
    // Reject an empty identity before changing any previously cached ticket metadata.
    {
        const binary_t empty_identity_ticket = {
            0x04, 0x00, 0x00, 0x0d,  // NewSessionTicket, 13-byte body
            0x00, 0x00, 0x0e, 0x10,  // lifetime = 3600
            0x01, 0x02, 0x03, 0x04,  // age_add
            0x00,                    // empty nonce
            0x00, 0x00,              // empty ticket identity (invalid)
            0x00, 0x00               // empty extensions
        };
        tls_session empty_identity_session;
        empty_identity_session.set_type(session_type_t::tls);
        auto& empty_identity_protection = empty_identity_session.get_tls_protection();
        empty_identity_protection.set_tls_version(tls1_3);
        empty_identity_protection.set_cipher_suite(0x1301);
        empty_identity_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        auto& empty_identity_kv = empty_identity_session.get_session_info(from_server).get_keyvalue();
        empty_identity_kv.set(session_ticket_lifetime, 1234);
        empty_identity_kv.set(session_ticket_age_add, 0x11223344);
        empty_identity_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket empty_identity_message(&empty_identity_session);
        size_t empty_identity_pos = 0;
        return_t empty_identity_ret = empty_identity_message.read(from_server, empty_identity_ticket.data(), empty_identity_ticket.size(), empty_identity_pos);
        _test_case.assert(errorcode_t::success != empty_identity_ret, function_name, "reject a NewSessionTicket with an empty ticket identity");
        _test_case.assert(empty_identity_session.get_resumption_tickets().empty(), function_name, "do not cache an empty ticket identity");
        _test_case.assert(empty_identity_protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), function_name,
                          "do not publish an empty ticket identity as the legacy ticket");
        _test_case.assert(1234 == empty_identity_kv.get(session_ticket_lifetime), function_name, "preserve prior lifetime metadata for an invalid empty identity");
        _test_case.assert(0x11223344 == empty_identity_kv.get(session_ticket_age_add), function_name, "preserve prior age_add metadata for an invalid empty identity");
        _test_case.assert(uint64(0x0102030405060708ULL) == empty_identity_kv.get(session_ticket_timestamp), function_name,
                          "preserve prior timestamp metadata for an invalid empty identity");
    }
}

static void test_tls13_new_session_ticket_rejects_missing_resumption_secret(const char* function_name) {
    // Scenario under test: TLS 1.3 NewSessionTicket when the resumption master secret is unavailable.
    // Action: parse a ticket with a valid identity but no derivable PSK.
    // Expected: reject it and preserve prior ticket metadata.
    // If the ticket PSK cannot be derived, do not publish its metadata
    // over a previously usable ticket's compatibility fields.
    {
        const binary_t valid_identity_missing_secret = {
            0x04, 0x00, 0x00, 0x0f,  // NewSessionTicket, 15-byte body
            0x00, 0x00, 0x0e, 0x10,  // lifetime = 3600
            0x01, 0x02, 0x03, 0x04,  // age_add
            0x01, 0x01,              // nonce length + nonce
            0x00, 0x01, 0xaa,        // one-byte ticket identity
            0x00, 0x00               // empty extensions
        };
        tls_session missing_secret_session;
        missing_secret_session.set_type(session_type_t::tls);
        auto& missing_secret_protection = missing_secret_session.get_tls_protection();
        missing_secret_protection.set_tls_version(tls1_3);
        missing_secret_protection.set_cipher_suite(0x1301);
        auto& missing_secret_kv = missing_secret_session.get_session_info(from_server).get_keyvalue();
        missing_secret_kv.set(session_ticket_lifetime, 1234);
        missing_secret_kv.set(session_ticket_age_add, 0x11223344);
        missing_secret_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket missing_secret_message(&missing_secret_session);
        size_t missing_secret_pos = 0;
        return_t missing_secret_ret =
            missing_secret_message.read(from_server, valid_identity_missing_secret.data(), valid_identity_missing_secret.size(), missing_secret_pos);
        _test_case.assert(errorcode_t::success != missing_secret_ret, function_name, "reject a NewSessionTicket when its resumption master secret is unavailable");
        _test_case.assert(missing_secret_session.get_resumption_tickets().empty(), function_name, "do not cache a ticket whose PSK could not be derived");
        _test_case.assert(missing_secret_protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), function_name,
                          "do not publish a ticket identity whose PSK could not be derived");
        _test_case.assert(1234 == missing_secret_kv.get(session_ticket_lifetime), function_name, "preserve prior lifetime metadata when PSK derivation fails");
        _test_case.assert(0x11223344 == missing_secret_kv.get(session_ticket_age_add), function_name, "preserve prior age_add metadata when PSK derivation fails");
        _test_case.assert(uint64(0x0102030405060708ULL) == missing_secret_kv.get(session_ticket_timestamp), function_name,
                          "preserve prior timestamp metadata when PSK derivation fails");
    }
}

static void test_tls13_new_session_ticket_rejects_malformed_early_data(const char* function_name) {
    // Scenario under test: TLS 1.3 NewSessionTicket with malformed early_data extension.
    // Action: parse an early_data extension with an invalid body length.
    // Expected: reject the ticket and preserve prior metadata.
    // A malformed early_data extension in NewSessionTicket must not be
    // silently accepted when the extension parser reports a format error.
    {
        // lifetime=3600, age_add=0, empty nonce, ticket={0xaa},
        // early_data extension with an invalid three-byte body (expects uint32).
        binary_t malformed_ticket_extension = {0x04, 0x00, 0x00, 0x15, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x01, 0xaa, 0x00, 0x07, 0x00, 0x2a, 0x00, 0x03, 0x00, 0x00, 0x00};
        tls_session malformed_session;
        malformed_session.set_type(session_type_t::tls);
        auto& malformed_protection = malformed_session.get_tls_protection();
        malformed_protection.set_tls_version(tls1_3);
        malformed_protection.set_cipher_suite(0x1301);
        malformed_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        auto& malformed_ticket_kv = malformed_session.get_session_info(from_server).get_keyvalue();
        malformed_ticket_kv.set(session_ticket_lifetime, 1234);
        malformed_ticket_kv.set(session_ticket_age_add, 0x11223344);
        malformed_ticket_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket malformed_ticket(&malformed_session);
        size_t malformed_pos = 0;
        return_t malformed_ret = malformed_ticket.read(from_server, malformed_ticket_extension.data(), malformed_ticket_extension.size(), malformed_pos);
        _test_case.assert(errorcode_t::success != malformed_ret, function_name, "reject a NewSessionTicket whose early_data extension body is malformed");
        _test_case.assert(malformed_session.get_resumption_tickets().empty(), function_name, "do not cache a ticket after its extension list fails to parse");
        _test_case.assert(1234 == malformed_ticket_kv.get(session_ticket_lifetime), function_name,
                          "preserve prior ticket lifetime metadata when extension parsing fails");
        _test_case.assert(0x11223344 == malformed_ticket_kv.get(session_ticket_age_add), function_name,
                          "preserve prior ticket age_add metadata when extension parsing fails");
        _test_case.assert(uint64(0x0102030405060708ULL) == malformed_ticket_kv.get(session_ticket_timestamp), function_name,
                          "preserve prior ticket timestamp when extension parsing fails");
    }
}

static void test_tls13_new_session_ticket_preserves_ticket_early_data_allowance(const char* function_name) {
    // Scenario under test: independent max_early_data_size values for multiple TLS 1.3 tickets.
    // Action: parse two tickets with distinct early-data allowances.
    // Expected: cache each allowance with its corresponding ticket identity.
    // Preserve the max_early_data_size advertised by each ticket independently.
    {
        auto make_early_data_ticket = [](uint8 nonce, uint8 identity, uint32 max_early_data_size) {
            binary_t wire = {0x04, 0x00, 0x00, 0x17};
            auto append_u32 = [&](uint32 value) {
                wire.push_back(static_cast<byte_t>(value >> 24));
                wire.push_back(static_cast<byte_t>(value >> 16));
                wire.push_back(static_cast<byte_t>(value >> 8));
                wire.push_back(static_cast<byte_t>(value));
            };
            append_u32(3600);
            append_u32(0x01020304);
            wire.push_back(1);
            wire.push_back(nonce);
            wire.push_back(0);
            wire.push_back(1);
            wire.push_back(identity);
            wire.push_back(0);
            wire.push_back(8);
            wire.push_back(0);
            wire.push_back(0x2a);
            wire.push_back(0);
            wire.push_back(4);
            append_u32(max_early_data_size);
            return wire;
        };

        tls_session early_data_session;
        early_data_session.set_type(session_type_t::tls);
        auto& early_data_protection = early_data_session.get_tls_protection();
        early_data_protection.set_tls_version(tls1_3);
        early_data_protection.set_cipher_suite(0x1301);
        early_data_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

        const binary_t first_wire = make_early_data_ticket(0x11, 0xa1, 4096);
        const binary_t second_wire = make_early_data_ticket(0x22, 0xa2, 8192);
        tls_handshake_new_session_ticket first_ticket(&early_data_session);
        tls_handshake_new_session_ticket second_ticket(&early_data_session);
        size_t first_pos = 0;
        size_t second_pos = 0;
        return_t first_ret = first_ticket.read(from_server, first_wire.data(), first_wire.size(), first_pos);
        return_t second_ret = second_ticket.read(from_server, second_wire.data(), second_wire.size(), second_pos);
        _test_case.test(first_ret, function_name, "parse the first ticket's early-data allowance");
        _test_case.test(second_ret, function_name, "parse the second ticket's early-data allowance");
        _test_case.assert(first_wire.size() == first_pos, function_name, "consume the complete first early-data ticket");
        _test_case.assert(second_wire.size() == second_pos, function_name, "consume the complete second early-data ticket");

        tls_resumption_ticket cached_first;
        tls_resumption_ticket cached_second;
        bool found_first = early_data_session.find_resumption_ticket(binary_t{0xa1}, cached_first);
        bool found_second = early_data_session.find_resumption_ticket(binary_t{0xa2}, cached_second);
        _test_case.assert(found_first && found_second, function_name, "cache both tickets with their independent identities");
        if (found_first && found_second) {
            _test_case.assert(4096 == cached_first.max_early_data_size, function_name, "retain the first ticket's max_early_data_size");
            _test_case.assert(8192 == cached_second.max_early_data_size, function_name, "retain the second ticket's max_early_data_size");
        }
    }
}

static void test_tls13_new_session_ticket_rejects_truncated_body(const char* function_name) {
    // Scenario under test: truncated TLS 1.3 NewSessionTicket body.
    // Action: parse a body ending before ticket_nonce_len.
    // Expected: reject it without caching a partially decoded ticket.
    // The fixed and length-prefixed fields of NewSessionTicket must all be
    // present; a truncated body must not be treated as a partially decoded ticket.
    {
        // The body ends immediately after ticket_age_add, before ticket_nonce_len.
        binary_t truncated_ticket = {0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02};
        tls_session truncated_session;
        truncated_session.set_type(session_type_t::tls);
        auto& truncated_protection = truncated_session.get_tls_protection();
        truncated_protection.set_tls_version(tls1_3);
        truncated_protection.set_cipher_suite(0x1301);

        tls_handshake_new_session_ticket truncated_message(&truncated_session);
        size_t truncated_pos = 0;
        return_t truncated_ret = truncated_message.read(from_server, truncated_ticket.data(), truncated_ticket.size(), truncated_pos);
        _test_case.assert(errorcode_t::success != truncated_ret, function_name, "reject a truncated NewSessionTicket body");
        _test_case.assert(truncated_session.get_resumption_tickets().empty(), function_name, "do not cache a partially decoded NewSessionTicket");
    }
}

static void test_tls13_new_session_ticket_serializes_bounded_lifetime(const char* function_name, uint32 max_ticket_lifetime) {
    // Scenario under test: serialized server-issued TLS 1.3 NewSessionTicket lifetime.
    // Action: serialize a NewSessionTicket and inspect its wire fields.
    // Expected: keep wire lifetime within seven days and omit early_data when unset.
    // Verify the server's generated NewSessionTicket on the serialized
    // handshake wire, not only the client-side lifetime handling.
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

        tls_handshake_new_session_ticket ticket(&session);
        binary_t wire;
        return_t ret = ticket.write(from_server, wire);
        _test_case.test(ret, function_name, "serialize a server-issued TLS 1.3 NewSessionTicket");
        if (errorcode_t::success == ret) {
            _test_case.assert(wire.size() >= 8, function_name, "emit a complete NewSessionTicket handshake header and lifetime");
            if (wire.size() >= 8) {
                uint32 body_size = (static_cast<uint32>(wire[1]) << 16) | (static_cast<uint32>(wire[2]) << 8) | wire[3];
                uint32 wire_lifetime = (static_cast<uint32>(wire[4]) << 24) | (static_cast<uint32>(wire[5]) << 16) | (static_cast<uint32>(wire[6]) << 8) | wire[7];
                _test_case.assert(static_cast<uint8>(tls_handshake_type_t::new_session_ticket) == wire[0], function_name,
                                  "serialize the NewSessionTicket handshake message type");
                _test_case.assert(wire.size() == 4 + body_size, function_name, "handshake length matches the serialized ticket body");
                _test_case.assert(wire_lifetime <= max_ticket_lifetime, function_name, "server does not advertise a ticket lifetime greater than seven days");
                uint32 stored_lifetime = t_narrow_cast(session.get_session_info(from_server).get_keyvalue().get(session_ticket_lifetime));
                _test_case.assert(wire_lifetime == stored_lifetime, function_name, "store the same ticket lifetime that was serialized on the wire");
                _test_case.assert((0x00 == wire[wire.size() - 2]) && (0x00 == wire[wire.size() - 1]), function_name,
                                  "omit the ticket early_data extension when no allowance is configured");
                auto issued_tickets = session.get_resumption_tickets();
                _test_case.assert(1 == issued_tickets.size(), function_name, "retain the server-issued ticket");
                if (1 == issued_tickets.size()) {
                    _test_case.assert(0 == issued_tickets.front().max_early_data_size, function_name,
                                      "keep the server-side ticket allowance at zero when early_data is absent");
                }
                _test_case.assert(0 == session.get_session_info(from_server).get_keyvalue().get(session_ticket_max_early_data_size), function_name,
                                  "keep the legacy ticket allowance at zero when early_data is absent");
            }
        }
    }
}

static void test_tls13_new_session_ticket_lifetime() {
    // Scenario under test: TLS 1.3 NewSessionTicket lifetime and cache integrity.
    // Action: exercise lifetime boundaries, malformed tickets, per-ticket early-data metadata, and serialization.
    // Expected: reject invalid tickets, preserve cache state, and enforce the seven-day lifetime cap.
    _test_case.begin("TLS 1.3 NewSessionTicket lifetime limit");

    const uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
    test_tls13_new_session_ticket_lifetime_boundaries(__FUNCTION__, max_ticket_lifetime);
    test_tls13_new_session_ticket_rejects_empty_identity(__FUNCTION__);
    test_tls13_new_session_ticket_rejects_missing_resumption_secret(__FUNCTION__);
    test_tls13_new_session_ticket_rejects_malformed_early_data(__FUNCTION__);
    test_tls13_new_session_ticket_preserves_ticket_early_data_allowance(__FUNCTION__);
    test_tls13_new_session_ticket_rejects_truncated_body(__FUNCTION__);
    test_tls13_new_session_ticket_serializes_bounded_lifetime(__FUNCTION__, max_ticket_lifetime);
}

static void test_tls13_multiple_new_session_tickets_are_cached_independently() {
    // Scenario under test: TLS 1.3 client caches multiple NewSessionTicket messages independently.
    // Action: receive the first NewSessionTicket.
    // Expected: consume the first complete NewSessionTicket.
    _test_case.begin("TLS 1.3 client caches multiple NewSessionTicket messages independently");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t expected_alpn{0x02, 'h', '2'};
    protection.get_secrets().assign(tls_secret_t::alpn, expected_alpn);
    session.set_client_server_name({'E', 'X', 'A', 'M', 'P', 'L', 'E', '.', 'C', 'O', 'M'});

    auto make_ticket = [](uint32 lifetime, uint32 age_add, const binary_t& nonce, const binary_t& identity) {
        binary_t wire = {static_cast<byte_t>(tls_handshake_type_t::new_session_ticket), 0, 0, 0};
        auto append_u16 = [&](uint16 value) {
            wire.push_back(static_cast<byte_t>(value >> 8));
            wire.push_back(static_cast<byte_t>(value));
        };
        auto append_u32 = [&](uint32 value) {
            wire.push_back(static_cast<byte_t>(value >> 24));
            wire.push_back(static_cast<byte_t>(value >> 16));
            wire.push_back(static_cast<byte_t>(value >> 8));
            wire.push_back(static_cast<byte_t>(value));
        };
        append_u32(lifetime);
        append_u32(age_add);
        wire.push_back(static_cast<byte_t>(nonce.size()));
        wire.insert(wire.end(), nonce.begin(), nonce.end());
        append_u16(t_narrow_cast(identity.size()));
        wire.insert(wire.end(), identity.begin(), identity.end());
        append_u16(0);  // empty extensions
        uint32 body_size = t_narrow_cast(wire.size() - 4);
        wire[1] = static_cast<byte_t>(body_size >> 16);
        wire[2] = static_cast<byte_t>(body_size >> 8);
        wire[3] = static_cast<byte_t>(body_size);
        return wire;
    };

    const binary_t nonce1 = {0x01, 0x02};
    const binary_t nonce2 = {0x03, 0x04};
    const binary_t identity1 = {0xa1, 0x01};
    const binary_t identity2 = {0xa2, 0x02};

    binary_t wire1 = make_ticket(3600, 0x10203040, nonce1, identity1);
    binary_t wire2 = make_ticket(1800, 0x50607080, nonce2, identity2);

    tls_handshake_new_session_ticket ticket1(&session);
    size_t pos1 = 0;
    return_t ret = ticket1.read(from_server, wire1.data(), wire1.size(), pos1);
    _test_case.test(ret, __FUNCTION__, "receive the first NewSessionTicket");
    _test_case.assert(wire1.size() == pos1, __FUNCTION__, "consume the first complete NewSessionTicket");

    tls_handshake_new_session_ticket ticket2(&session);
    size_t pos2 = 0;
    ret = ticket2.read(from_server, wire2.data(), wire2.size(), pos2);
    _test_case.test(ret, __FUNCTION__, "receive a second NewSessionTicket on the same connection");
    _test_case.assert(wire2.size() == pos2, __FUNCTION__, "consume the second complete NewSessionTicket");

    auto cached_tickets = session.get_resumption_tickets();
    _test_case.assert(2 == cached_tickets.size(), __FUNCTION__, "retain both received ticket entries instead of overwriting the first");
    tls_resumption_ticket cached1;
    tls_resumption_ticket cached2;
    bool cached1_found_at_352 = session.find_resumption_ticket(identity1, cached1);
    _test_case.assert(cached1_found_at_352, __FUNCTION__, "find the first ticket by its identity");
    bool cached2_found_at_353 = session.find_resumption_ticket(identity2, cached2);
    _test_case.assert(cached2_found_at_353, __FUNCTION__, "find the second ticket by its identity");
    if (cached1_found_at_352 && cached2_found_at_353) {
        _test_case.assert(nonce1 == cached1.nonce, __FUNCTION__, "retain the first ticket nonce");
        _test_case.assert(nonce2 == cached2.nonce, __FUNCTION__, "retain the second ticket nonce");
        _test_case.assert(cached1.psk != cached2.psk, __FUNCTION__, "retain independently derived PSKs for the two ticket nonces");
        _test_case.assert(3600 == cached1.lifetime && 1800 == cached2.lifetime, __FUNCTION__, "retain each ticket's own lifetime");
        const binary_t expected_server_name = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
        _test_case.assert(expected_server_name == cached1.server_name && expected_server_name == cached2.server_name, __FUNCTION__,
                          "associate each received NewSessionTicket with the normalized ClientHello SNI");
        _test_case.assert(expected_alpn == cached1.alpn && expected_alpn == cached2.alpn, __FUNCTION__,
                          "associate each received NewSessionTicket with the negotiated ALPN protocol");
        _test_case.assert(static_cast<uint16>(tls1_3) == cached1.version && static_cast<uint16>(tls1_3) == cached2.version, __FUNCTION__,
                          "retain the TLS version associated with each received ticket");
        _test_case.assert(0x10203040 == cached1.age_add && 0x50607080 == cached2.age_add, __FUNCTION__, "retain each ticket's own age_add");
    }
    _test_case.assert(identity2 == protection.get_secrets().get(tls_secret_t::new_session_ticket), __FUNCTION__,
                      "keep the legacy singleton view pointed at the most recently received ticket");
}

static void test_tls13_new_session_ticket_early_data_issue_and_cache(const char* function_name, tls_session& server, tls_session& client, binary_t& expected_alpn) {
    // Scenario under test: per-ticket early-data allowance is issued and cached.
    // Action: issue tickets with distinct allowances and parse each at the client.
    // Expected: wire encoding and both ticket caches preserve each identity's allowance.
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls1_3);
    server_protection.set_cipher_suite(0x1301);
    server_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    expected_alpn = binary_t{0x02, 'h', '2'};
    server_protection.get_secrets().assign(tls_secret_t::alpn, expected_alpn);

    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls1_3);
    client_protection.set_cipher_suite(0x1301);
    client_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    client_protection.get_secrets().assign(tls_secret_t::alpn, expected_alpn);

    const uint32 expected_limits[] = {0, 4096, 8192};
    for (size_t i = 0; i < (sizeof(expected_limits) / sizeof(expected_limits[0])); ++i) {
        tls_handshake_new_session_ticket issued(&server);
        auto early_data = new tls_extension_early_data(&issued);
        early_data->set_max_early_data_size(expected_limits[i]);
        issued.get_extensions().add(early_data);

        binary_t wire;
        return_t ret = issued.write(from_server, wire);
        _test_case.test(ret, function_name, "serialize a NewSessionTicket with its configured early-data allowance");
        if (errorcode_t::success != ret) {
            continue;
        }

        _test_case.assert(wire.size() >= 8, function_name, "emit a complete NewSessionTicket with its extension vector");
        if (wire.size() >= 8) {
            const size_t extension_offset = wire.size() - 8;
            _test_case.assert((0x00 == wire[extension_offset]) && (0x2a == wire[extension_offset + 1]), function_name,
                              "encode early_data as the NewSessionTicket extension type");
            _test_case.assert((0x00 == wire[extension_offset + 2]) && (0x04 == wire[extension_offset + 3]), function_name,
                              "encode max_early_data_size as exactly four bytes");
            uint32 wire_limit = (static_cast<uint32>(wire[extension_offset + 4]) << 24) | (static_cast<uint32>(wire[extension_offset + 5]) << 16) |
                                (static_cast<uint32>(wire[extension_offset + 6]) << 8) | static_cast<uint32>(wire[extension_offset + 7]);
            _test_case.assert(expected_limits[i] == wire_limit, function_name, "encode the configured allowance in network byte order");
        }

        tls_handshake_new_session_ticket received(&client);
        size_t pos = 0;
        ret = received.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "parse the server-issued NewSessionTicket at the client");
        _test_case.assert(wire.size() == pos, function_name, "consume the complete ticket and its extension vector");

        auto server_tickets = server.get_resumption_tickets();
        _test_case.assert((i + 1) == server_tickets.size(), function_name, "retain each issued ticket independently on the server");
        if ((i + 1) == server_tickets.size()) {
            const auto& issued_ticket = server_tickets.back();
            _test_case.assert(expected_limits[i] == issued_ticket.max_early_data_size, function_name,
                              "store the advertised allowance in the matching server-side ticket");
            tls_resumption_ticket cached_ticket;
            bool found = client.find_resumption_ticket(issued_ticket.identity, cached_ticket);
            _test_case.assert(found, function_name, "cache the server-issued ticket by its identity at the client");
            if (found) {
                _test_case.assert(expected_limits[i] == cached_ticket.max_early_data_size, function_name,
                                  "retain the advertised allowance in the matching client-side ticket");
                _test_case.assert(issued_ticket.psk == cached_ticket.psk, function_name, "derive the same ticket PSK at the server and client");
            }
        }
    }

    auto server_tickets = server.get_resumption_tickets();
    auto client_tickets = client.get_resumption_tickets();
    _test_case.assert(3 == server_tickets.size(), function_name, "issue all three tickets with independent allowance values");
    _test_case.assert(3 == client_tickets.size(), function_name, "cache all three issued tickets at the client");
    _test_case.assert(8192 == server.get_session_info(from_server).get_keyvalue().get(session_ticket_max_early_data_size), function_name,
                      "publish the most recently issued ticket's allowance in the legacy metadata view");
}

static void test_tls13_new_session_ticket_early_data_resumption(const char* function_name, tls_session& server, tls_session& client, const binary_t& expected_alpn) {
    // Scenario under test: a cached ticket's early-data allowance is enforced during 0-RTT resumption.
    // Action: resume with the 4096-byte ticket through ClientHello, PSK selection, EncryptedExtensions, and application data.
    // Expected: accept exactly the advertised allowance and reject the first excess byte.
    auto server_tickets = server.get_resumption_tickets();
    auto client_tickets = client.get_resumption_tickets();
    // Resume with the server-issued 4096-byte ticket and carry its allowance
    // through ClientHello, server PSK selection, EncryptedExtensions, and 0-RTT.
    if ((server_tickets.size() < 2) || (client_tickets.size() < 2)) {
        _test_case.assert(false, function_name, "retain the 4096-byte ticket for the resumed early-data exchange");
        return;
    }

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t resumed_ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(resumed_ret, function_name, "prepare the fresh-connection empty transcript hash");
    if (errorcode_t::success != resumed_ret) {
        return;
    }

    tls_session resumed_client;
    resumed_client.set_type(session_type_t::tls);
    auto& resumed_client_protection = resumed_client.get_tls_protection();
    resumed_client_protection.set_tls_version(tls1_3);
    resumed_client_protection.set_cipher_suite(0x1301);
    resumed_client.get_keyvalue().set(session_tls_version, tls1_3);
    resumed_client.store_resumption_ticket(client_tickets[1]);
    resumed_client_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto resumed_hello = new tls_handshake_client_hello(&resumed_client);
    resumed_hello->add_ciphersuite(0x1301);
    auto resumed_versions = new tls_extension_client_supported_versions(resumed_hello);
    resumed_versions->add(tls1_3);
    resumed_hello->get_extensions().add(resumed_versions);
    // The ticket was issued under h2. A resumed ClientHello must offer that
    // ALPN protocol before the ticket can remain eligible for early data.
    auto resumed_alpn = new tls_extension_alpn(resumed_hello);
    resumed_alpn->set_protocols(expected_alpn);
    resumed_hello->get_extensions().add(resumed_alpn);
    auto resumed_modes = new tls_extension_psk_key_exchange_modes(resumed_hello);
    resumed_modes->add(0);  // psk_ke; early data uses the ticket PSK.
    resumed_hello->get_extensions().add(resumed_modes);
    resumed_hello->get_extensions().add(new tls_extension_early_data(resumed_hello));
    resumed_hello->get_extensions().add(new tls_extension_client_psk(resumed_hello));

    tls_record_handshake resumed_hello_record(&resumed_client);
    resumed_hello_record << resumed_hello;
    binary_t resumed_hello_wire;
    resumed_ret = resumed_hello_record.write(from_client, resumed_hello_wire);
    _test_case.test(resumed_ret, function_name, "offer the server-issued ticket and its cached early-data allowance");
    if (errorcode_t::success != resumed_ret) {
        return;
    }
    auto& resumed_client_early_state = resumed_client.get_session_info(from_server).get_keyvalue();
    _test_case.assert(tls_flow_t::zero_rtt == resumed_client_protection.get_flow(), function_name, "enter zero-RTT flow for the resumed early-data offer");
    _test_case.assert(1 == resumed_client_early_state.get(session_early_data_offered), function_name, "offer early data with the cached ticket");
    _test_case.assert(4096 == resumed_client_early_state.get(session_early_data_limit), function_name,
                      "restore the exact 4096-byte allowance from the received NewSessionTicket");

    tls_session resumed_server;
    resumed_server.set_type(session_type_t::tls);
    auto& resumed_server_protection = resumed_server.get_tls_protection();
    resumed_server_protection.set_tls_version(tls1_3);
    resumed_server_protection.set_cipher_suite(0x1301);
    resumed_server.get_keyvalue().set(session_tls_version, tls1_3);
    resumed_server_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    resumed_server.set_early_data_discard_limit(4096);
    resumed_server.store_resumption_ticket(server_tickets[1]);

    tls_records resumed_server_records;
    // The ticket is bound to h2. Configure the server's ALPN policy before
    // parsing ClientHello so negotiate_alpn() schedules the selected protocol
    // before the PSK extension evaluates early-data ticket eligibility.
    auto tlsadvisor = tls_advisor::get_instance();
    tlsadvisor->enable_alpn("h2");
    resumed_ret = resumed_server_records.read(&resumed_server, from_client, resumed_hello_wire);
    tlsadvisor->enable_alpn(nullptr);
    _test_case.test(resumed_ret, function_name, "validate the resumed ClientHello binder against the server-issued ticket");
    if (errorcode_t::success != resumed_ret) {
        return;
    }
    auto& resumed_server_early_state = resumed_server.get_session_info(from_server).get_keyvalue();
    _test_case.assert(0 == resumed_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                      "select the sole server-issued ticket at ClientHello identity zero");
    _test_case.assert(4096 == resumed_server_early_state.get(session_early_data_limit), function_name, "restore the same per-ticket allowance on the server");
    _test_case.assert(server_tickets[1].identity == resumed_server.get_early_data_ticket().identity, function_name,
                      "retain the selected server-issued ticket as the eligible early-data ticket");

    tls_handshake_encrypted_extensions resumed_encrypted_extensions(&resumed_server);
    // The ALPN selected while parsing ClientHello is already scheduled for
    // EncryptedExtensions; do not synthesize a second, independent selection.
    resumed_encrypted_extensions.get_extensions().add(new tls_extension_early_data(&resumed_encrypted_extensions));
    binary_t resumed_encrypted_extensions_wire;
    resumed_ret = resumed_encrypted_extensions.write(from_server, resumed_encrypted_extensions_wire);
    _test_case.test(resumed_ret, function_name, "accept early data for the selected identity-zero ticket");
    if (errorcode_t::success != resumed_ret) {
        return;
    }
    _test_case.assert(1 == resumed_server_early_state.get(session_early_data_accepted), function_name, "record the server's EncryptedExtensions early-data acceptance");

    tls_record_application_data resumed_early_data(&resumed_client);
    resumed_early_data.set_binary(binary_t(4096, 0x5a));
    binary_t resumed_early_data_wire;
    resumed_ret = resumed_early_data.write(from_client, resumed_early_data_wire);
    _test_case.test(resumed_ret, function_name, "send exactly the advertised 4096-byte early-data allowance");
    _test_case.assert(false == resumed_early_data_wire.empty(), function_name, "emit the accepted 0-RTT application-data record");
    _test_case.assert(4096 == resumed_client_early_state.get(session_early_data_sent), function_name, "account for the complete advertised allowance on the client");

    tls_records resumed_early_data_records;
    resumed_ret = resumed_early_data_records.read(&resumed_server, from_client, resumed_early_data_wire);
    _test_case.test(resumed_ret, function_name, "authenticate and accept the server-issued ticket's 0-RTT record");
    _test_case.assert(1 == resumed_early_data_records.size(), function_name, "deliver the accepted resumed 0-RTT record");
    _test_case.assert(4096 == resumed_server_early_state.get(session_early_data_received), function_name,
                      "account for exactly the advertised plaintext allowance on the server");
    if (1 == resumed_early_data_records.size()) {
        auto decoded_early_data = static_cast<tls_record_application_data*>(resumed_early_data_records.getat(0));
        _test_case.assert(binary_t(4096, 0x5a) == decoded_early_data->get_binary(), function_name, "deliver the exact plaintext protected by the server-issued ticket");
    }

    tls_record_application_data resumed_overflow(&resumed_client);
    resumed_overflow.set_binary(binary_t{0x01});
    binary_t resumed_overflow_wire;
    resumed_ret = resumed_overflow.write(from_client, resumed_overflow_wire);
    _test_case.assert(errorcode_t::overflow == resumed_ret, function_name, "reject the first client early-data byte beyond the ticket's advertised allowance");
    _test_case.assert(resumed_overflow_wire.empty(), function_name, "emit no record beyond the advertised early-data allowance");
}

static void test_tls13_new_session_ticket_early_data_allowance() {
    // Scenario under test: server-issued NewSessionTicket preserves its per-ticket early-data allowance.
    // Action: issue multiple tickets and resume with one ticket's cached allowance.
    // Expected: wire encoding, ticket caches, PSK selection, and 0-RTT accounting retain the same value.
    _test_case.begin("TLS 1.3 NewSessionTicket carries its per-ticket early-data allowance");

    tls_session server;
    tls_session client;
    binary_t expected_alpn;
    test_tls13_new_session_ticket_early_data_issue_and_cache(__FUNCTION__, server, client, expected_alpn);
    test_tls13_new_session_ticket_early_data_resumption(__FUNCTION__, server, client, expected_alpn);
}

static void test_tls13_new_session_ticket_nonce_uniqueness() {
    // Scenario under test: TLS 1.3 NewSessionTicket nonce uniqueness per connection.
    // Action: serialize another NewSessionTicket on the same connection.
    // Expected: emit a complete ticket nonce field.
    _test_case.begin("TLS 1.3 NewSessionTicket nonce uniqueness per connection");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t expected_issued_alpn{0x02, 'h', '2'};
    protection.get_secrets().assign(tls_secret_t::alpn, expected_issued_alpn);

    std::vector<binary_t> nonces;
    for (size_t i = 0; i < 3; ++i) {
        tls_handshake_new_session_ticket ticket(&session);
        binary_t wire;
        return_t ret = ticket.write(from_server, wire);
        _test_case.test(ret, __FUNCTION__, "serialize another NewSessionTicket on the same connection");
        if (errorcode_t::success != ret) {
            continue;
        }

        if (wire.size() < 13) {
            _test_case.assert(false, __FUNCTION__, "emit a complete ticket nonce field");
            continue;
        }
        uint8 nonce_length = wire[12];
        _test_case.assert(24 == nonce_length, __FUNCTION__, "encode the ticket nonce as a 16-byte random prefix and eight-byte sequence");
        if (wire.size() < static_cast<size_t>(13) + nonce_length) {
            _test_case.assert(false, __FUNCTION__, "include the complete ticket nonce in the NST body");
            continue;
        }
        nonces.emplace_back(wire.begin() + 13, wire.begin() + 13 + nonce_length);
    }

    _test_case.assert(3 == nonces.size(), __FUNCTION__, "generate all three NewSessionTicket messages");

    // RFC 8446 requires uniqueness among tickets issued on this connection.
    // The process-wide sequence additionally distinguishes connections in
    // the same process; this is stronger than the per-connection requirement.
    tls_session another_connection;
    another_connection.set_type(session_type_t::tls);
    binary_t another_nonce;
    return_t another_ret = another_connection.generate_ticket_nonce(another_nonce);
    _test_case.test(another_ret, __FUNCTION__, "generate a nonce for a separate TLS connection");
    for (const auto& nonce : nonces) {
        _test_case.assert(nonce != another_nonce, __FUNCTION__, "do not reuse a ticket nonce across connections of the same server process");
    }

    for (size_t i = 0; i < nonces.size(); ++i) {
        for (size_t j = i + 1; j < nonces.size(); ++j) {
            _test_case.assert(nonces[i] != nonces[j], __FUNCTION__, "never reuse a ticket nonce within one connection");
        }
    }

    // A failed per-ticket derivation must not publish a partially updated
    // compatibility view or retain a ticket without its derived PSK.
    {
        tls_session failed_session;
        failed_session.set_type(session_type_t::tls);
        auto& failed_protection = failed_session.get_tls_protection();
        failed_protection.set_tls_version(tls1_3);
        failed_protection.set_cipher_suite(0x1301);
        failed_protection.get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xee});
        auto& failed_kv = failed_session.get_session_info(from_server).get_keyvalue();
        failed_kv.set(session_ticket_lifetime, 77);
        failed_kv.set(session_ticket_age_add, 0x11223344);
        failed_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket failed_ticket(&failed_session);
        binary_t failed_wire;
        return_t failed_ret = failed_ticket.write(from_server, failed_wire);
        _test_case.assert(errorcode_t::success != failed_ret, __FUNCTION__, "do not issue a ticket without resumption_master_secret");
        _test_case.assert(failed_wire.empty(), __FUNCTION__, "do not serialize a partial NewSessionTicket");
        _test_case.assert(failed_session.get_resumption_tickets().empty(), __FUNCTION__, "do not retain a ticket without its derived PSK");
        _test_case.assert(binary_t{0xee} == failed_protection.get_secrets().get(tls_secret_t::new_session_ticket), __FUNCTION__,
                          "preserve the previous ticket identity when issuance fails");
        _test_case.assert(77 == failed_kv.get(session_ticket_lifetime), __FUNCTION__, "preserve the previous ticket lifetime when issuance fails");
        _test_case.assert(0x11223344 == failed_kv.get(session_ticket_age_add), __FUNCTION__, "preserve the previous ticket age_add when issuance fails");
        _test_case.assert(uint64(0x0102030405060708ULL) == failed_kv.get(session_ticket_timestamp), __FUNCTION__,
                          "preserve the previous ticket timestamp when issuance fails");
    }

    auto issued_tickets = session.get_resumption_tickets();
    _test_case.assert(nonces.size() == issued_tickets.size(), __FUNCTION__, "retain every server-issued ticket in the per-ticket store");
    if (nonces.size() == issued_tickets.size()) {
        for (size_t i = 0; i < issued_tickets.size(); ++i) {
            _test_case.assert(nonces[i] == issued_tickets[i].nonce, __FUNCTION__, "associate each issued ticket with its own nonce");
            _test_case.assert(!issued_tickets[i].identity.empty() && !issued_tickets[i].psk.empty(), __FUNCTION__, "retain each issued ticket identity and derived PSK");
            _test_case.assert(static_cast<uint16>(tls1_3) == issued_tickets[i].version, __FUNCTION__, "bind each issued ticket to TLS 1.3");
            _test_case.assert(expected_issued_alpn == issued_tickets[i].alpn, __FUNCTION__, "bind each issued ticket to the negotiated ALPN protocol");
            for (size_t j = i + 1; j < issued_tickets.size(); ++j) {
                _test_case.assert(issued_tickets[i].identity != issued_tickets[j].identity, __FUNCTION__, "issue independently addressable ticket identities");
                _test_case.assert(issued_tickets[i].psk != issued_tickets[j].psk, __FUNCTION__, "derive a distinct PSK for each issued ticket nonce");
            }
        }
    }
}

static void test_tls13_new_session_ticket_rejects_malformed_early_data_length() {
    // Action: Action: parse early_data extension vectors with invalid declared lengths and payload sizes.
    // Scenario under test: NewSessionTicket early_data must contain exactly one uint32.
    // Expected: zero-, three-, and five-byte values are rejected with fatal decode_error.
    _test_case.begin("TLS 1.3 NewSessionTicket rejects malformed early_data lengths");

    const uint16 malformed_lengths[] = {0, 3, 5};
    for (size_t i = 0; i < (sizeof(malformed_lengths) / sizeof(malformed_lengths[0])); ++i) {
        const uint16 value_length = malformed_lengths[i];
        const uint16 extension_length = static_cast<uint16>(4 + value_length);
        const uint32 body_length = static_cast<uint32>(18 + value_length);
        binary_t wire = {0x04,
                         static_cast<byte_t>(body_length >> 16),
                         static_cast<byte_t>(body_length >> 8),
                         static_cast<byte_t>(body_length),
                         0x00,
                         0x00,
                         0x0e,
                         0x10,  // ticket_lifetime = 3600
                         0x00,
                         0x00,
                         0x00,
                         0x00,  // ticket_age_add
                         0x00,  // empty ticket_nonce
                         0x00,
                         0x01,
                         0xaa,  // one-byte ticket identity
                         static_cast<byte_t>(extension_length >> 8),
                         static_cast<byte_t>(extension_length),
                         0x00,
                         0x2a,
                         static_cast<byte_t>(value_length >> 8),
                         static_cast<byte_t>(value_length)};
        for (uint16 j = 0; j < value_length; ++j) {
            wire.push_back(0x11);
        }

        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

        tls_handshake_new_session_ticket ticket(&session);
        size_t pos = 0;
        return_t ret = ticket.read(from_server, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject an early_data value that is not exactly four bytes");

        size_t decode_error_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == decode_error_count, __FUNCTION__, "queue exactly one fatal decode_error for a malformed early_data value");
        _test_case.assert(session.get_resumption_tickets().empty(), __FUNCTION__, "do not cache a ticket with a malformed early_data value");
        _test_case.assert(session.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                          "do not publish a malformed ticket identity");
    }
}

static void test_tls13_new_session_ticket_respects_advertised_psk_modes() {
    // Action: Action: vary the client's advertised PSK key-exchange modes before server ticket issuance.
    // Scenario under test: TLS 1.3 NewSessionTicket respects advertised PSK key-exchange modes.
    // Expected: decline ticket issuance when no advertised PSK mode is supported.
    _test_case.begin("TLS 1.3 NewSessionTicket respects advertised PSK key-exchange modes");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls1_3);
    session.get_tls_protection().set_cipher_suite(0x1301);
    session.get_tls_protection().get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    session.get_keyvalue().set(session_client_psk_modes_present, 1);
    session.get_keyvalue().set(session_client_psk_modes, 0);

    tls_handshake_new_session_ticket ticket(&session);
    binary_t wire;
    return_t ret = ticket.write(from_server, wire);
    _test_case.assert(errorcode_t::not_supported == ret, __FUNCTION__, "decline ticket issuance when no advertised PSK mode is supported");
    _test_case.assert(wire.empty(), __FUNCTION__, "emit no NewSessionTicket for incompatible advertised modes");
}

static void test_tls12_new_session_ticket_wire_format() {
    // Scenario under test: TLS 1.2 RFC 5077 NewSessionTicket wire format.
    // Action: serialize and parse ticket identities and the SessionTicket extension.
    // Expected: preserve the opaque ticket and encode the issuance acknowledgement as an empty extension.

    _test_case.begin("TLS 1.2 NewSessionTicket RFC 5077 wire format");

    const binary_t ticket_identity{0x10, 0x20, 0x30, 0x40};
    tls_session server_session;
    server_session.set_type(session_type_t::tls);
    auto& server_protection = server_session.get_tls_protection();
    server_protection.set_tls_version(tls1_2);
    server_protection.set_cipher_suite(0xc02f);
    server_session.update_session_status(session_status_client_finished);
    server_session.set_client_server_name(binary_t{'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    server_session.get_keyvalue().set(session_extended_master_secret, 1);
    server_session.get_keyvalue().set(session_encrypt_then_mac, 1);
    server_protection.get_secrets().assign(tls_secret_t::master, binary_t(48, 0x5a));
    server_protection.get_secrets().assign(tls_secret_t::alpn, binary_t{'h', '2'});
    server_protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket_identity);
    server_session.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 3600);

    tls_handshake_new_session_ticket outgoing(&server_session);
    binary_t wire;
    return_t ret = outgoing.write(from_server, wire);
    _test_case.test(ret, __FUNCTION__, "serialize a TLS 1.2 NewSessionTicket");
    const binary_t expected_wire{0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40};
    _test_case.assert(expected_wire == wire, __FUNCTION__, "encode lifetime_hint and uint16-length opaque ticket without TLS 1.3 fields");

    const auto server_tickets = server_session.get_tls12_resumption_tickets();
    _test_case.assert(1 == server_tickets.size(), __FUNCTION__, "retain the issued TLS 1.2 ticket in the server cache");
    _test_case.assert(server_session.get_pending_tls12_resumption_tickets().empty(), __FUNCTION__,
                      "activate a full-handshake ticket after Client Finished was already authenticated");
    if (1 == server_tickets.size()) {
        const auto& issued = server_tickets.front();
        _test_case.assert(ticket_identity == issued.identity, __FUNCTION__, "bind the server cache entry to the serialized opaque identity");
        _test_case.assert(binary_t(48, 0x5a) == issued.master_secret, __FUNCTION__, "retain the TLS 1.2 master secret");
        _test_case.assert(0xc02f == issued.cipher_suite && static_cast<uint16>(tls1_2) == issued.version, __FUNCTION__,
                          "retain the negotiated TLS 1.2 version and cipher suite");
        _test_case.assert(issued.extended_master_secret, __FUNCTION__, "retain the negotiated EMS state");
        _test_case.assert(issued.encrypt_then_mac, __FUNCTION__, "retain the negotiated EtM state");
        _test_case.assert(binary_t{'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'} == issued.server_name, __FUNCTION__, "retain the normalized SNI association");
        _test_case.assert(binary_t{'h', '2'} == issued.alpn, __FUNCTION__, "retain the negotiated ALPN association");
        _test_case.assert(3600 == issued.lifetime && 0 < issued.timestamp, __FUNCTION__, "retain ticket lifetime and issuance time");
    }

    tls_session client_session;
    client_session.set_type(session_type_t::tls);
    client_session.get_tls_protection().set_tls_version(tls1_2);
    client_session.update_session_status(session_status_client_finished);
    tls_handshake_new_session_ticket incoming(&client_session);
    size_t pos = 0;
    ret = incoming.read(from_server, wire.data(), wire.size(), pos);
    _test_case.test(ret, __FUNCTION__, "parse the serialized TLS 1.2 NewSessionTicket");
    _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete TLS 1.2 NewSessionTicket");
    auto& client_secrets = client_session.get_tls_protection().get_secrets();
    auto& client_ticket_state = client_session.get_session_info(from_server).get_keyvalue();
    _test_case.assert(client_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "do not publish the opaque ticket before Server Finished");
    _test_case.assert(ticket_identity == client_secrets.get(tls_secret_t::new_session_ticket_pending), __FUNCTION__, "retain the opaque TLS 1.2 ticket as pending");
    _test_case.assert(1 == client_ticket_state.get(session_ticket_pending), __FUNCTION__, "mark the parsed ticket pending");
    _test_case.assert(3600 == client_ticket_state.get(session_ticket_pending_lifetime), __FUNCTION__, "retain the RFC 5077 ticket_lifetime_hint as pending metadata");

    // Exercise the normal handshake factory/dispatcher, not only a directly
    // constructed NewSessionTicket object.
    tls_session dispatched_session;
    dispatched_session.set_type(session_type_t::tls);
    dispatched_session.get_tls_protection().set_tls_version(tls1_2);
    dispatched_session.update_session_status(session_status_client_finished);
    size_t dispatched_pos = 0;
    tls_handshake* dispatched = tls_handshake::read(&dispatched_session, from_server, wire.data(), wire.size(), dispatched_pos);
    _test_case.assert(nullptr != dispatched, __FUNCTION__, "dispatch a TLS 1.2 NewSessionTicket through tls_handshake::read");
    if (dispatched) {
        _test_case.assert(tls_handshake_type_t::new_session_ticket == dispatched->get_type(), __FUNCTION__, "select the NewSessionTicket implementation for TLS 1.2");
        _test_case.assert(wire.size() == dispatched_pos, __FUNCTION__, "consume the complete dispatched TLS 1.2 ticket");
        const auto& dispatched_secrets = dispatched_session.get_tls_protection().get_secrets();
        const auto& dispatched_ticket_state = dispatched_session.get_session_info(from_server).get_keyvalue();
        _test_case.assert(ticket_identity == dispatched_secrets.get(tls_secret_t::new_session_ticket_pending), __FUNCTION__,
                          "stage the opaque ticket through the normal dispatcher");
        _test_case.assert(1 == dispatched_ticket_state.get(session_ticket_pending), __FUNCTION__, "keep the dispatched ticket pending until Server Finished");
        dispatched->release();
    }

    // Exercise the enclosing TLS record reader/writer, including the
    // TLSPlaintext header and tls_record_handshake::do_read_body() dispatch.
    tls_record_handshake outgoing_record(&server_session);
    outgoing_record.add(tls_handshake_type_t::new_session_ticket, &server_session);
    binary_t record_wire;
    ret = outgoing_record.write(from_server, record_wire);
    _test_case.test(ret, __FUNCTION__, "write TLS 1.2 NewSessionTicket in a Handshake record");

    tls_session record_client_session;
    record_client_session.set_type(session_type_t::tls);
    record_client_session.get_tls_protection().set_tls_version(tls1_2);
    record_client_session.update_session_status(session_status_client_finished);
    tls_record_handshake incoming_record(&record_client_session);
    size_t record_pos = 0;
    ret = incoming_record.read(from_server, record_wire.data(), record_wire.size(), record_pos);
    _test_case.test(ret, __FUNCTION__, "read TLS 1.2 NewSessionTicket from a Handshake record");
    _test_case.assert(record_wire.size() == record_pos, __FUNCTION__, "consume the complete TLS Handshake record");
    _test_case.assert(1 == incoming_record.get_handshakes().size(), __FUNCTION__, "dispatch one handshake from the TLS record");
    auto parsed_record_handshake = incoming_record.get_handshakes().getat(0);
    _test_case.assert((nullptr != parsed_record_handshake) && (tls_handshake_type_t::new_session_ticket == parsed_record_handshake->get_type()), __FUNCTION__,
                      "dispatch NewSessionTicket through the TLS record reader");
    const auto& record_client_secrets = record_client_session.get_tls_protection().get_secrets();
    const auto& record_ticket_state = record_client_session.get_session_info(from_server).get_keyvalue();
    _test_case.assert(ticket_identity == record_client_secrets.get(tls_secret_t::new_session_ticket_pending), __FUNCTION__,
                      "stage the opaque ticket parsed from the TLS record");
    _test_case.assert(1 == record_ticket_state.get(session_ticket_pending), __FUNCTION__, "keep the record-parsed ticket pending until Server Finished");
    _test_case.assert(3600 == record_ticket_state.get(session_ticket_pending_lifetime), __FUNCTION__,
                      "retain the ticket lifetime as pending metadata from the TLS record");
}

static void test_tls12_new_session_ticket_requires_client_finished() {
    // Scenario under test: TLS 1.2 NewSessionTicket issuance requires authenticated Client Finished.
    // Action: attempt ticket issuance before and after the client's Finished.
    // Expected: reject premature issuance and allow renewal only after client authentication.

    // RFC 5077: the server issues NewSessionTicket only after authenticating
    // the client's Finished. The client must reject a ticket received earlier.
    _test_case.begin("TLS 1.2 NewSessionTicket requires client Finished");

    const binary_t ticket_identity{0x10, 0x20, 0x30, 0x40};
    tls_session premature_server;
    premature_server.set_type(session_type_t::tls);
    auto& server_protection = premature_server.get_tls_protection();
    server_protection.set_tls_version(tls1_2);
    server_protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket_identity);
    premature_server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 3600);

    tls_handshake_new_session_ticket outgoing(&premature_server);
    binary_t premature_wire;
    return_t ret = outgoing.write(from_server, premature_wire);
    _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse to issue a ticket before client Finished is authenticated");
    _test_case.assert(premature_wire.empty(), __FUNCTION__, "emit no NewSessionTicket before client Finished");

    const binary_t valid_ticket_wire{0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40};
    tls_session premature_client;
    premature_client.set_type(session_type_t::tls);
    premature_client.get_tls_protection().set_tls_version(tls1_2);
    tls_handshake_new_session_ticket incoming(&premature_client);
    size_t pos = 0;
    ret = incoming.read(from_server, valid_ticket_wire.data(), valid_ticket_wire.size(), pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject a ticket received before the client's Finished");
    _test_case.assert(premature_client.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                      "do not publish an out-of-order ticket");
    size_t unexpected_message_count = test_count_fatal_alert(premature_client, from_server, tls_alertdesc_t::unexpected_message);
    _test_case.assert(1 == unexpected_message_count, __FUNCTION__, "queue exactly one fatal unexpected_message for an out-of-order ticket");

    tls_session staged_client;
    staged_client.set_type(session_type_t::tls);
    staged_client.get_tls_protection().set_tls_version(tls1_2);
    staged_client.update_session_status(session_status_client_finished);
    tls_handshake_new_session_ticket staged_incoming(&staged_client);
    size_t staged_pos = 0;
    ret = staged_incoming.read(from_server, valid_ticket_wire.data(), valid_ticket_wire.size(), staged_pos);
    _test_case.test(ret, __FUNCTION__, "accept a TLS 1.2 ticket after the client's Finished");
    auto& staged_secrets = staged_client.get_tls_protection().get_secrets();
    auto& staged_ticket_state = staged_client.get_session_info(from_server).get_keyvalue();
    _test_case.assert(staged_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "keep the received ticket unpublished before server Finished");
    _test_case.assert(ticket_identity == staged_secrets.get(tls_secret_t::new_session_ticket_pending), __FUNCTION__, "retain the opaque ticket in pending state");
    _test_case.assert(1 == staged_ticket_state.get(session_ticket_pending), __FUNCTION__, "mark the ticket as pending authentication");
    _test_case.assert(0 == staged_ticket_state.get(session_ticket_lifetime), __FUNCTION__, "do not publish lifetime metadata before server Finished");
}

static void test_tls12_server_ticket_confirmation_store() {
    // Scenario under test: TLS 1.2 server-side ticket staging and confirmation.
    // Action: stage ticket identities and confirm or decline their cache entries.
    // Expected: expose only confirmed tickets as eligible resumption candidates.

    _test_case.begin("TLS 1.2 server ticket confirmation store");

    tls_session session;
    session.set_type(session_type_t::tls);

    tls12_resumption_ticket initial;
    initial.identity = binary_t{0x10, 0x20};
    initial.master_secret = binary_t(48, 0x11);
    initial.server_name = binary_t{'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
    initial.alpn = binary_t{'h', '2'};
    initial.lifetime = 3600;
    initial.timestamp = 1000;
    initial.version = tls1_2;
    initial.cipher_suite = 0xc02f;
    initial.extended_master_secret = true;
    initial.encrypt_then_mac = true;

    session.stage_tls12_resumption_ticket(initial);
    _test_case.assert(session.get_tls12_resumption_tickets().empty(), __FUNCTION__, "keep a newly staged TLS 1.2 ticket out of the active cache");
    _test_case.assert(1 == session.get_pending_tls12_resumption_tickets().size(), __FUNCTION__, "retain the staged TLS 1.2 ticket as pending");
    tls12_resumption_ticket cached;
    bool cached_found_at_937 = session.find_tls12_resumption_ticket(initial.identity, cached);
    _test_case.assert(false == cached_found_at_937, __FUNCTION__, "do not expose an unconfirmed TLS 1.2 ticket to lookup");

    const binary_t initial_identity{0x10, 0x20};
    bool ticket_confirmed = session.confirm_tls12_resumption_ticket(initial_identity);
    _test_case.assert(ticket_confirmed, __FUNCTION__, "activate the TLS 1.2 ticket after confirmation");
    _test_case.assert(session.get_pending_tls12_resumption_tickets().empty(), __FUNCTION__, "remove the confirmed ticket from pending state");

    bool found = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(found, __FUNCTION__, "find the confirmed TLS 1.2 ticket by opaque identity");
    if (found) {
        _test_case.assert(binary_t(48, 0x11) == cached.master_secret, __FUNCTION__, "retain the original 48-byte master secret");
        _test_case.assert(cached.extended_master_secret, __FUNCTION__, "retain the original EMS state");
        _test_case.assert(cached.encrypt_then_mac, __FUNCTION__, "retain the original EtM state");
        _test_case.assert(0xc02f == cached.cipher_suite && tls1_2 == cached.version, __FUNCTION__, "retain the negotiated TLS version and cipher suite");
        _test_case.assert(binary_t{'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'} == cached.server_name, __FUNCTION__, "retain the SNI binding");
        _test_case.assert(binary_t{'h', '2'} == cached.alpn, __FUNCTION__, "retain the ALPN binding");
        _test_case.assert(3600 == cached.lifetime && 1000 == cached.timestamp, __FUNCTION__, "retain ticket lifetime and issuance timestamp");
    }

    tls12_resumption_ticket renewal = cached;
    // Reuse the same opaque bytes deliberately: pending TLS 1.2 state must
    // not overwrite the active TLS 1.2 record before confirmation.
    renewal.identity = initial_identity;
    renewal.master_secret = binary_t(48, 0x22);
    session.stage_tls12_resumption_ticket(renewal);
    session.discard_tls12_pending_resumption_ticket(renewal.identity);
    _test_case.assert(session.get_pending_tls12_resumption_tickets().empty(), __FUNCTION__, "discard an unconfirmed TLS 1.2 ticket with a colliding identity");
    bool cached_found_at_964 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_964, __FUNCTION__, "preserve the active TLS 1.2 ticket when a colliding renewal is discarded");
    _test_case.assert(binary_t(48, 0x11) == cached.master_secret, __FUNCTION__, "retain the prior Master Secret after discarding a colliding renewal");

    tls_resumption_ticket tls13;
    tls13.identity = initial_identity;
    tls13.psk = binary_t(32, 0x33);
    session.store_resumption_ticket(tls13);
    _test_case.assert(1 == session.get_resumption_tickets().size(), __FUNCTION__, "retain the TLS 1.3 PSK ticket with the same opaque identity bytes");
    _test_case.assert(1 == session.get_tls12_resumption_tickets().size(), __FUNCTION__, "keep TLS 1.2 and TLS 1.3 ticket stores independent despite identity collision");
    tls_resumption_ticket cached_tls13;
    bool cached_tls13_found_at_975 = session.find_resumption_ticket(initial_identity, cached_tls13);
    _test_case.assert(cached_tls13_found_at_975, __FUNCTION__, "look up the TLS 1.3 ticket independently by the colliding identity");
    _test_case.assert(binary_t(32, 0x33) == cached_tls13.psk, __FUNCTION__, "retain the TLS 1.3 PSK under its own ticket-store namespace");
    bool cached_found_at_977 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_977, __FUNCTION__, "retain the TLS 1.2 ticket under its own ticket-store namespace");
    _test_case.assert(binary_t(48, 0x11) == cached.master_secret, __FUNCTION__, "preserve the TLS 1.2 Master Secret beside the TLS 1.3 PSK");

    session.remove_resumption_ticket(initial_identity);
    bool cached_tls13_found_at_981 = session.find_resumption_ticket(initial_identity, cached_tls13);
    _test_case.assert(false == cached_tls13_found_at_981, __FUNCTION__, "remove only the TLS 1.3 ticket from its own store");
    bool cached_found_at_982 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_982, __FUNCTION__, "do not remove a TLS 1.2 ticket when the TLS 1.3 identity matches");
    session.store_resumption_ticket(tls13);

    session.stage_tls12_resumption_ticket(renewal);
    session.reset_session_status();
    _test_case.assert(session.get_pending_tls12_resumption_tickets().empty(), __FUNCTION__, "discard pending TLS 1.2 server tickets on handshake reset");
    bool cached_found_at_988 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_988, __FUNCTION__, "preserve confirmed TLS 1.2 tickets across handshake reset");
    _test_case.assert(binary_t(48, 0x11) == cached.master_secret, __FUNCTION__, "do not let colliding pending state replace the confirmed TLS 1.2 Master Secret");
    _test_case.assert(1 == session.get_resumption_tickets().size(), __FUNCTION__, "preserve TLS 1.3 PSK tickets across TLS 1.2 pending-state cleanup");
    bool cached_tls13_found_at_991 = session.find_resumption_ticket(initial_identity, cached_tls13);
    _test_case.assert(cached_tls13_found_at_991, __FUNCTION__, "preserve the same-identity TLS 1.3 ticket across TLS 1.2 cleanup");

    auto shared_store = std::make_shared<tls12_resumption_ticket_store>();
    tls_session issuing_connection;
    tls_session resuming_connection;
    issuing_connection.set_tls12_resumption_ticket_store(shared_store);
    resuming_connection.set_tls12_resumption_ticket_store(shared_store);

    tls12_resumption_ticket cross_connection_ticket = initial;
    cross_connection_ticket.identity = binary_t{0x50, 0x60};
    issuing_connection.stage_tls12_resumption_ticket(cross_connection_ticket);
    bool ticket_published = issuing_connection.confirm_tls12_resumption_ticket(cross_connection_ticket.identity);
    _test_case.assert(ticket_published, __FUNCTION__, "publish a confirmed ticket to the server-wide store");

    tls12_resumption_ticket resumed_ticket;
    bool resumed_ticket_found_at_1006 = resuming_connection.find_tls12_resumption_ticket(cross_connection_ticket.identity, resumed_ticket);
    _test_case.assert(resumed_ticket_found_at_1006, __FUNCTION__, "find a ticket issued by a different TLS connection");
    _test_case.assert(cross_connection_ticket.master_secret == resumed_ticket.master_secret, __FUNCTION__,
                      "retain the master secret across independent TLS connection sessions");

    tls_session isolated_connection;
    bool resumed_ticket_found_at_1012 = isolated_connection.find_tls12_resumption_ticket(cross_connection_ticket.identity, resumed_ticket);
    _test_case.assert(false == resumed_ticket_found_at_1012, __FUNCTION__, "keep the default per-session ticket store isolated from another server store");

    issuing_connection.remove_tls12_resumption_ticket(cross_connection_ticket.identity);
    bool resumed_ticket_found_at_1016 = resuming_connection.find_tls12_resumption_ticket(cross_connection_ticket.identity, resumed_ticket);
    _test_case.assert(false == resumed_ticket_found_at_1016, __FUNCTION__, "remove a TLS 1.2 ticket from the shared server store across connection sessions");
    _test_case.assert(1 == session.get_resumption_tickets().size(), __FUNCTION__, "keep the independent TLS 1.3 ticket when removing a TLS 1.2 identity");

    // Confirmation, unlike staging or discard, may replace an active record
    // when a renewed opaque identity happens to collide with the old bytes.
    renewal.master_secret = binary_t(48, 0x22);
    renewal.lifetime = 1800;
    session.stage_tls12_resumption_ticket(renewal);
    bool cached_found_at_1025 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_1025, __FUNCTION__, "keep the old TLS 1.2 ticket visible while a colliding renewal is pending");
    _test_case.assert(binary_t(48, 0x11) == cached.master_secret, __FUNCTION__, "retain the old Master Secret until the colliding renewal is confirmed");
    bool renewal_confirmed = session.confirm_tls12_resumption_ticket(initial_identity);
    _test_case.assert(renewal_confirmed, __FUNCTION__, "confirm a renewed TLS 1.2 ticket with the same opaque identity");
    bool cached_found_at_1030 = session.find_tls12_resumption_ticket(initial_identity, cached);
    _test_case.assert(cached_found_at_1030, __FUNCTION__, "look up the confirmed replacement under its opaque identity");
    _test_case.assert(binary_t(48, 0x22) == cached.master_secret && 1800 == cached.lifetime, __FUNCTION__, "replace the active TLS 1.2 ticket only after confirmation");
}

static void test_tls12_session_ticket_extension_wire_behavior() {
    // Scenario under test: TLS 1.2 SessionTicket extension offer and acknowledgement.
    // Action: encode and parse opaque ticket identities and empty extension acknowledgements.
    // Expected: distinguish ticket offers from server acknowledgement without confusing either with rejection.

    // RFC 5077: ClientHello carries an opaque ticket (or an empty request);
    // ServerHello acknowledges issuance with an empty SessionTicket extension.
    _test_case.begin("TLS 1.2 SessionTicket extension wire behavior");

    const binary_t ticket{0x10, 0x20, 0x30, 0x40};

    tls_session client_session;
    client_session.set_type(session_type_t::tls);
    client_session.get_tls_protection().set_tls_version(tls1_2);

    tls_handshake_client_hello client_hello(&client_session);
    client_hello.get_extensions().add(tls_extension_type_t::session_ticket, from_client, &client_hello, [&](tls_extension* extension) -> return_t {
        static_cast<tls_extension_session_ticket*>(extension)->set_ticket(ticket);
        return errorcode_t::success;
    });

    binary_t client_hello_extensions;
    return_t ret = client_hello.get_extensions().write(from_client, client_hello_extensions);
    const binary_t expected_client_hello{0x00, 0x23, 0x00, 0x04, 0x10, 0x20, 0x30, 0x40};
    _test_case.test(ret, __FUNCTION__, "serialize a non-empty ClientHello SessionTicket offer");
    _test_case.assert(expected_client_hello == client_hello_extensions, __FUNCTION__, "encode the opaque ticket as extension_data");

    tls_session server_session;
    server_session.set_type(session_type_t::tls);
    server_session.get_tls_protection().set_tls_version(tls1_2);
    tls_handshake_client_hello received_client_hello(&server_session);
    ret = received_client_hello.get_extensions().read(&received_client_hello, from_client, client_hello_extensions);
    _test_case.test(ret, __FUNCTION__, "parse a non-empty ClientHello SessionTicket offer");
    auto received_ticket = static_cast<tls_extension_session_ticket*>(received_client_hello.get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != received_ticket) && (ticket == received_ticket->get_ticket()), __FUNCTION__, "retain the opaque ticket bytes");

    // Exercise SessionTicket through the complete ClientHello serializer and
    // handshake factory/parser, rather than only through tls_extensions.
    tls_session client_wire_session;
    client_wire_session.set_type(session_type_t::tls);
    client_wire_session.get_tls_protection().set_tls_version(tls1_2);
    tls_handshake_client_hello client_wire_hello(&client_wire_session);
    ret = client_wire_hello.add_ciphersuite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    _test_case.test(ret, __FUNCTION__, "configure a TLS 1.2 ClientHello cipher suite");
    client_wire_hello.get_extensions().add(tls_extension_type_t::session_ticket, from_client, &client_wire_hello, [&](tls_extension* extension) -> return_t {
        static_cast<tls_extension_session_ticket*>(extension)->set_ticket(ticket);
        return errorcode_t::success;
    });
    binary_t client_hello_wire;
    ret = client_wire_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a TLS 1.2 ClientHello carrying SessionTicket");

    tls_session parsed_client_wire_session;
    parsed_client_wire_session.set_type(session_type_t::tls);
    parsed_client_wire_session.get_tls_protection().set_tls_version(tls1_2);
    size_t client_hello_pos = 0;
    tls_handshake* parsed_client_hello =
        tls_handshake::read(&parsed_client_wire_session, from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.assert(nullptr != parsed_client_hello, __FUNCTION__, "parse a TLS 1.2 ClientHello through the handshake factory");
    if (parsed_client_hello) {
        _test_case.assert(tls_handshake_type_t::client_hello == parsed_client_hello->get_type(), __FUNCTION__, "dispatch the ClientHello message");
        auto parsed_session_ticket = static_cast<tls_extension_session_ticket*>(parsed_client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
        _test_case.assert((nullptr != parsed_session_ticket) && (ticket == parsed_session_ticket->get_ticket()), __FUNCTION__,
                          "recover the opaque ticket from the parsed ClientHello");
        _test_case.assert(client_hello_wire.size() == client_hello_pos, __FUNCTION__, "consume the complete ClientHello message");
        parsed_client_hello->release();
    }

    tls_handshake_client_hello ticket_request(&client_session);
    ticket_request.get_extensions().add(tls_extension_type_t::session_ticket, from_client, &ticket_request);
    binary_t ticket_request_wire;
    ret = ticket_request.get_extensions().write(from_client, ticket_request_wire);
    const binary_t expected_ticket_request{0x00, 0x23, 0x00, 0x00};
    _test_case.test(ret, __FUNCTION__, "serialize an empty ClientHello ticket request");
    _test_case.assert(expected_ticket_request == ticket_request_wire, __FUNCTION__, "encode an empty SessionTicket request");

    tls_handshake_server_hello server_hello(&server_session);
    server_hello.get_extensions().add(tls_extension_type_t::session_ticket, from_server, &server_hello);
    binary_t server_hello_extensions;
    ret = server_hello.get_extensions().write(from_server, server_hello_extensions);
    _test_case.test(ret, __FUNCTION__, "serialize an empty ServerHello SessionTicket acknowledgement");
    _test_case.assert(expected_ticket_request == server_hello_extensions, __FUNCTION__, "ServerHello acknowledgement has an empty body");

    tls_handshake_server_hello received_server_hello(&client_session);
    ret = received_server_hello.get_extensions().read(&received_server_hello, from_server, server_hello_extensions);
    _test_case.test(ret, __FUNCTION__, "parse an empty ServerHello SessionTicket acknowledgement");
    auto acknowledgement = static_cast<tls_extension_session_ticket*>(received_server_hello.get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != acknowledgement) && acknowledgement->get_ticket().empty(), __FUNCTION__, "retain an empty acknowledgement");

    tls_session malformed_session;
    malformed_session.set_type(session_type_t::tls);
    malformed_session.get_tls_protection().set_tls_version(tls1_2);
    tls_handshake_server_hello malformed_server_hello(&malformed_session);
    const binary_t malformed_acknowledgement{0x00, 0x23, 0x00, 0x01, 0xaa};
    ret = malformed_server_hello.get_extensions().read(&malformed_server_hello, from_server, malformed_acknowledgement);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a non-empty ServerHello acknowledgement");

    size_t illegal_parameter_count = test_count_fatal_alert(malformed_session, from_server, tls_alertdesc_t::illegal_parameter);
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue one fatal illegal_parameter for a non-empty ServerHello acknowledgement");
}

// Keep this trace local to the negotiation test so asynchronous logger timestamps
// are not needed to associate an event with its scenario or handshake phase.
using tls12_session_ticket_keyvalue_t = t_key_value<uint16, uint16>;

struct tls12_session_ticket_trace_entry {
    const char* phase;
    unsigned operation;
    uint16 key;
    bool before_exists;
    uint16 before_value;
    bool after_exists;
    uint16 after_value;
};

struct tls12_session_ticket_trace_context {
    const char* scenario;
    const char* endpoint;
    const char* phase;
    tls12_session_ticket_keyvalue_t* keyvalue;
    const void* owner;
    std::vector<tls12_session_ticket_trace_entry> events;

    ~tls12_session_ticket_trace_context() {
        if (nullptr != keyvalue) {
            keyvalue->clear_hook();
        }
        for (const auto& event : events) {
            _logger->writeln("[tls12-session-ticket-kv] scenario=%s endpoint=%s phase=%s op=%u key=0x%04x before=(%u,%u) after=(%u,%u)", scenario, endpoint, event.phase,
                             event.operation, static_cast<unsigned>(event.key), event.before_exists ? 1u : 0u, static_cast<unsigned>(event.before_value),
                             event.after_exists ? 1u : 0u, static_cast<unsigned>(event.after_value));
        }
    }
};

static void trace_tls12_session_ticket_keyvalue(const tls12_session_ticket_keyvalue_t::hook_event_t& event, void* parameter) {
    auto context = static_cast<tls12_session_ticket_trace_context*>(parameter);
    if ((nullptr == context) || (event.owner != context->owner)) {
        return;
    }
    if ((session_client_session_ticket_offered != event.key) && (session_client_session_ticket_offer_observed != event.key)) {
        return;
    }

    tls12_session_ticket_trace_entry entry = {
        context->phase,
        static_cast<unsigned>(event.operation),
        event.key,
        event.before_exists,
        event.before_exists ? *event.before_value : uint16(0),
        event.after_exists,
        event.after_exists ? *event.after_value : uint16(0),
    };
    context->events.push_back(entry);
}

static void test_tls12_session_ticket_handshake_negotiation() {
    // Scenario under test: TLS 1.2 SessionTicket negotiation across handshake records.
    // Action: vary the client offer and server acknowledgement while processing the handshake.
    // Expected: keep resumption and acknowledgement state consistent with the negotiated extension.

    // Exercise the offer/acknowledgement state through complete TLS records.
    _test_case.begin("TLS 1.2 SessionTicket offer and ServerHello acknowledgement negotiation");

    auto run_case = [](bool offer_ticket, bool force_acknowledgement, bool expect_success, bool expect_acknowledgement) -> void {
        tls_session client;
        tls_session server;
        client.set_type(session_type_t::tls);
        server.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls1_2);
        server.get_tls_protection().set_tls_version(tls1_2);
        if (offer_ticket) {
            server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xaa});
        }

        const char* scenario = offer_ticket ? "offer-auto-ack" : (force_acknowledgement ? "no-offer-forced-ack" : "no-offer-no-ack");
        tls12_session_ticket_trace_context client_trace = {scenario, "client", "setup", &client.get_keyvalue(), &client.get_keyvalue(), {}};
        tls12_session_ticket_trace_context server_trace = {scenario, "server", "setup", &server.get_keyvalue(), &server.get_keyvalue(), {}};
        client.get_keyvalue().set_hook(trace_tls12_session_ticket_keyvalue, &client_trace);
        server.get_keyvalue().set_hook(trace_tls12_session_ticket_keyvalue, &server_trace);

        auto client_hello = new tls_handshake_client_hello(&client);
        return_t ret = client_hello->add_ciphersuite(0xc02f);
        _test_case.test(ret, __FUNCTION__, "configure the TLS 1.2 ClientHello cipher suite");
        if (errorcode_t::success != ret) {
            client_hello->release();
            return;
        }
        if (offer_ticket) {
            client_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_client, client_hello);
        }
        // ClientHello parsing in this implementation requires a non-empty
        // extension vector. Keep a valid, unrelated empty extension in every
        // scenario so the negative cases reach SessionTicket negotiation.
        client_hello->get_extensions().add(tls_extension_type_t::encrypt_then_mac, from_client, client_hello);

        tls_record_handshake client_record(&client);
        client_record << client_hello;
        binary_t client_wire;
        client_trace.phase = "ClientHello write";
        ret = client_record.write(from_client, client_wire);
        _test_case.test(ret, __FUNCTION__, "write the TLS 1.2 ClientHello record");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_record_handshake received_client_record(&server);
        size_t client_pos = 0;
        server_trace.phase = "ClientHello read";
        ret = received_client_record.read(from_client, client_wire.data(), client_wire.size(), client_pos);
        _test_case.test(ret, __FUNCTION__, "server reads the TLS 1.2 ClientHello record");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(client_wire.size() == client_pos, __FUNCTION__, "consume the complete ClientHello record");

        // Match the server-side handshake cursor used by the ordinary
        // ClientHello -> ServerHello construction path.
        server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
        auto server_hello = new tls_handshake_server_hello(&server);
        server_hello->set_version(tls1_2);
        ret = server_hello->set_cipher_suite(0xc02f);
        _test_case.test(ret, __FUNCTION__, "select the TLS 1.2 cipher suite");
        if (errorcode_t::success != ret) {
            server_hello->release();
            return;
        }
        server_hello->set_random(binary_t(32, 0x5a));
        if (force_acknowledgement) {
            server_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_server, server_hello);
        }

        tls_record_handshake server_record(&server);
        server_record << server_hello;
        binary_t server_wire;
        server_trace.phase = "ServerHello write";
        ret = server_record.write(from_server, server_wire);
        _test_case.test(ret, __FUNCTION__, "write the TLS 1.2 ServerHello record");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_record_handshake received_server_record(&client);
        size_t server_pos = 0;
        client_trace.phase = "ServerHello read";
        ret = received_server_record.read(from_server, server_wire.data(), server_wire.size(), server_pos);
        _test_case.assert(expect_success ? (errorcode_t::success == ret) : (errorcode_t::handshake_failure == ret), __FUNCTION__,
                          expect_success ? "accept a valid TLS 1.2 ServerHello acknowledgement" : "reject a SessionTicket acknowledgement that was not offered");
        if (expect_success) {
            _test_case.assert(server_wire.size() == server_pos, __FUNCTION__, "consume the complete ServerHello record");
            _test_case.assert(1 == received_server_record.get_handshakes().size(), __FUNCTION__, "parse one ServerHello handshake");
            if (1 == received_server_record.get_handshakes().size()) {
                auto parsed = received_server_record.get_handshakes().getat(0);
                auto acknowledgement = static_cast<tls_extension_session_ticket*>(parsed->get_extensions().get(tls_extension_type_t::session_ticket));
                _test_case.assert(expect_acknowledgement == (nullptr != acknowledgement), __FUNCTION__,
                                  expect_acknowledgement ? "acknowledge an observed SessionTicket offer" : "do not acknowledge when SessionTicket was not offered");
                if (acknowledgement) {
                    _test_case.assert(acknowledgement->get_ticket().empty(), __FUNCTION__, "emit an empty ServerHello acknowledgement");
                }
            }
        } else {
            size_t unsupported_extension_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::unsupported_extension);
            _test_case.assert(1 == unsupported_extension_count, __FUNCTION__, "queue one fatal unsupported_extension alert");
        }
    };

    // The server acknowledges an observed offer.
    run_case(true, false, true, true);
    // A ClientHello without the extension does not trigger an automatic acknowledgement.
    run_case(false, false, true, false);
    // A peer that acknowledges an extension absent from the observed ClientHello is rejected.
    run_case(false, true, false, false);
}

static void test_tls12_client_does_not_offer_non_ems_ticket() {
    // Scenario under test: TLS 1.2 client eligibility for a ticket without Extended Master Secret.
    // Action: build ClientHello from a cached non-EMS ticket.
    // Expected: decline ticket resumption rather than offer an incompatible identity.

    _test_case.begin("TLS 1.2 client declines non-EMS ticket resumption");

    auto store = std::make_shared<tls12_resumption_ticket_store>();
    tls12_resumption_ticket ticket;
    ticket.identity = binary_t{0x31, 0x32, 0x33, 0x34};
    ticket.master_secret = binary_t(48, 0x5a);
    ticket.lifetime = 3600;
    ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    ticket.version = static_cast<uint16>(tls1_2);
    ticket.cipher_suite = 0xc02f;
    store->store(ticket);

    tls_session client;
    client.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(store);
    client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);

    auto client_hello = new tls_handshake_client_hello(&client);
    return_t ret = client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "configure a TLS 1.2 ClientHello for a non-EMS ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ClientHello without offering the non-EMS ticket identity");
    if (errorcode_t::success != ret) {
        return;
    }

    auto ticket_extension = static_cast<tls_extension_session_ticket*>(client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert(nullptr != ticket_extension, __FUNCTION__, "request a fresh ticket when no resumable EMS ticket is available");
    if (nullptr != ticket_extension) {
        _test_case.assert(ticket_extension->get_ticket().empty(), __FUNCTION__, "send an empty ticket request instead of the non-EMS identity");
    }
    _test_case.assert(0 == client.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "do not mark a non-EMS ticket as a resumption candidate");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), __FUNCTION__, "do not restore the non-EMS ticket Master Secret");
    _test_case.assert(client_hello->get_session_id().empty(), __FUNCTION__, "do not generate a resumption Session ID");
}

static void test_tls12_client_suppresses_ticket_identity_in_mixed_version_offer() {
    // Scenario under test: TLS 1.2 ticket identity in a mixed-version ClientHello.
    // Action: offer a cached TLS 1.2 ticket while negotiating multiple protocol versions.
    // Expected: suppress the TLS 1.2 identity when the offer is not safely eligible.

    _test_case.begin("TLS 1.2 client suppresses cached ticket identity in mixed-version ClientHello");

    auto store = std::make_shared<tls12_resumption_ticket_store>();
    tls12_resumption_ticket ticket;
    ticket.identity = binary_t{0x41, 0x42, 0x43, 0x44};
    ticket.master_secret = binary_t(48, 0x6b);
    ticket.lifetime = 3600;
    ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    ticket.version = static_cast<uint16>(tls1_2);
    ticket.cipher_suite = 0xc02f;
    ticket.extended_master_secret = true;
    store->store(ticket);

    tls_session client;
    client.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(store);
    client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);

    auto client_hello = new tls_handshake_client_hello(&client);
    return_t ret = client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "configure a mixed-version ClientHello cipher suite");
    if (errorcode_t::success != ret) {
        client_hello->release();
        return;
    }

    auto supported_versions = new tls_extension_client_supported_versions(client_hello);
    supported_versions->add(tls1_2);
    supported_versions->add(tls1_3);
    client_hello->get_extensions().add(supported_versions);
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    client_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_client, client_hello, [&](tls_extension* extension) -> return_t {
        static_cast<tls_extension_session_ticket*>(extension)->set_ticket(ticket.identity);
        return errorcode_t::success;
    });

    binary_t client_hello_wire;
    ret = client_hello->write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the mixed TLS 1.2/TLS 1.3 ClientHello");
    if (errorcode_t::success != ret) {
        client_hello->release();
        return;
    }

    auto ticket_extension = static_cast<tls_extension_session_ticket*>(client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != ticket_extension) && ticket_extension->get_ticket().empty(), __FUNCTION__,
                      "clear a preconfigured TLS 1.2 ticket identity from the mixed-version offer");
    _test_case.assert(0 == client.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "do not select a TLS 1.2 ticket for a mixed-version offer");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), __FUNCTION__,
                      "do not restore the TLS 1.2 Master Secret for a mixed-version offer");

    tls_session parsed_session;
    parsed_session.set_type(session_type_t::tls);
    parsed_session.get_tls_protection().set_tls_version(tls1_2);
    size_t pos = 0;
    tls_handshake* parsed = tls_handshake::read(&parsed_session, from_client, client_hello_wire.data(), client_hello_wire.size(), pos);
    _test_case.assert(nullptr != parsed, __FUNCTION__, "parse the serialized mixed-version ClientHello");
    if (parsed) {
        auto parsed_ticket = static_cast<tls_extension_session_ticket*>(parsed->get_extensions().get(tls_extension_type_t::session_ticket));
        _test_case.assert((nullptr != parsed_ticket) && parsed_ticket->get_ticket().empty(), __FUNCTION__,
                          "transmit only an empty SessionTicket request, never the cached TLS 1.2 identity");
        parsed->release();
    }
    _test_case.assert(client_hello_wire.size() == pos, __FUNCTION__, "consume the complete mixed-version ClientHello");
    client_hello->release();
}

static void test_tls12_ticket_context_binding() {
    // Scenario under test: TLS 1.2 resumption ticket is bound to its original session context.
    // Action: vary SNI, ALPN, cipher suite, and Encrypt-then-MAC context during ticket lookup.
    // Expected: decline resumption when the cached context does not match the current offer.

    _test_case.begin("TLS 1.2 ticket resumption enforces cached session context");

    auto run_case = [](bool mismatch_sni, bool mismatch_alpn, bool mismatch_cipher, bool ticket_etm, bool offered_etm, uint16 ticket_cipher_suite, bool expect_candidate,
                       const char* description) {
        auto store = std::make_shared<tls12_resumption_ticket_store>();
        tls12_resumption_ticket ticket;
        ticket.identity = binary_t{0x71, 0x72, 0x73, 0x74};
        ticket.master_secret = binary_t(48, 0x5a);
        ticket.server_name = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
        ticket.alpn = {0x02, 'h', '2'};
        ticket.lifetime = 3600;
        ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        ticket.version = static_cast<uint16>(tls1_2);
        ticket.cipher_suite = ticket_cipher_suite;
        ticket.extended_master_secret = true;
        ticket.encrypt_then_mac = ticket_etm;
        store->store(ticket);

        tls_session client;
        tls_session server;
        client.set_type(session_type_t::tls);
        server.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls1_2);
        server.get_tls_protection().set_tls_version(tls1_2);
        server.set_tls12_resumption_ticket_store(store);

        auto client_hello = new tls_handshake_client_hello(&client);
        client_hello->set_session_id(binary_t(32, 0x44));
        return_t ret = client_hello->add_ciphersuite(mismatch_cipher ? ((ticket.cipher_suite == 0xc027) ? 0xc02f : 0xc030) : ticket.cipher_suite);
        _test_case.test(ret, __FUNCTION__, "configure the ClientHello cipher-suite offer");
        if (errorcode_t::success != ret) {
            client_hello->release();
            return;
        }

        client_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_client, client_hello, [&](tls_extension* extension) -> return_t {
            static_cast<tls_extension_session_ticket*>(extension)->set_ticket(ticket.identity);
            return errorcode_t::success;
        });
        client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
        if (offered_etm) {
            client_hello->get_extensions().add(tls_extension_type_t::encrypt_then_mac, from_client, client_hello, nullptr);
        }

        auto sni = new tls_extension_sni(client_hello);
        sni->set_hostname(mismatch_sni ? "other.example.com" : "example.com");
        client_hello->get_extensions().add(sni);

        auto alpn = new tls_extension_alpn(client_hello);
        alpn->set_protocols(mismatch_alpn ? binary_t{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'} : ticket.alpn);
        client_hello->get_extensions().add(alpn);

        tls_record_handshake outgoing_client_hello(&client);
        outgoing_client_hello << client_hello;
        binary_t client_hello_wire;
        ret = outgoing_client_hello.write(from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "serialize ClientHello with the cached ticket identity");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_record_handshake incoming_client_hello(&server);
        size_t client_hello_pos = 0;
        ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
        _test_case.test(ret, __FUNCTION__, description);
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(expect_candidate == (1 == server.get_keyvalue().get(session_tls12_ticket_candidate)), __FUNCTION__,
                          "accept a TLS 1.2 ticket only when all cached session bindings match");
        if (expect_candidate) {
            _test_case.assert(ticket.master_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::master), __FUNCTION__,
                              "restore the original Master Secret for a context-matched ticket");
        } else {
            _test_case.assert(server.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), __FUNCTION__,
                              "do not restore the Master Secret for a context-mismatched ticket");

            // A rejected ticket must also be declined on the wire: the
            // ServerHello must not echo the Session ID that signals resumption.
            server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
            auto server_hello = new tls_handshake_server_hello(&server);
            server_hello->set_version(tls1_2);
            ret = server_hello->set_cipher_suite(mismatch_cipher ? 0xc030 : ticket.cipher_suite);
            _test_case.test(ret, __FUNCTION__, "select an offered cipher suite for the full-handshake fallback");
            if (errorcode_t::success == ret) {
                server_hello->set_random(binary_t(32, 0x6a));
                tls_record_handshake outgoing_server_hello(&server);
                outgoing_server_hello << server_hello;
                binary_t server_hello_wire;
                ret = outgoing_server_hello.write(from_server, server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello after rejecting a context-mismatched ticket");
                if (errorcode_t::success == ret) {
                    _test_case.assert(server_hello->get_session_id().empty(), __FUNCTION__, "do not echo the offered Session ID when cached session context differs");
                    _test_case.assert(0 == server.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__,
                                      "keep the server on the full-handshake path after declining the ticket");
                }
            }
        }
    };

    run_case(false, false, false, false, false, 0xc02f, true, "accept a ticket when SNI, ALPN, and AEAD cipher suite match");
    run_case(true, false, false, false, false, 0xc02f, false, "decline a ticket when the ClientHello SNI differs from the cached SNI");
    run_case(false, true, false, false, false, 0xc02f, false, "decline a ticket when the ClientHello ALPN differs from the cached ALPN");
    run_case(false, false, false, true, false, 0xc027, false, "decline a CBC EtM ticket when ClientHello omits encrypt_then_mac");
    run_case(false, false, true, false, false, 0xc02f, false, "decline a ticket when its cipher suite is absent from ClientHello");
    run_case(false, false, false, true, true, 0xc027, true, "accept a CBC ticket when both sessions negotiate EtM");
    run_case(false, false, false, false, true, 0xc027, false, "preserve a CBC ticket's MAC-then-encrypt state during resumption");
    run_case(false, false, false, false, true, 0xc02f, true, "ignore an EtM offer when the ticket uses an AEAD cipher suite");
}

static void test_tls12_server_enforces_ticket_ems_transitions() {
    // Scenario under test: TLS 1.2 server enforces Extended Master Secret ticket transitions.
    // Action: vary the ticket's EMS state and the client's EMS offer.
    // Expected: accept only transitions consistent with the cached ticket's EMS state.

    _test_case.begin("TLS 1.2 server enforces SessionTicket EMS transitions");

    auto run_case = [](bool original_ems, bool offered_ems, bool expect_abort, bool expect_candidate, const char* description) {
        auto store = std::make_shared<tls12_resumption_ticket_store>();
        tls12_resumption_ticket ticket;
        ticket.identity = binary_t{0x61, 0x62, 0x63, static_cast<byte_t>(original_ems ? 0x01 : 0x00)};
        ticket.master_secret = binary_t(48, 0x5a);
        ticket.lifetime = 3600;
        ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        ticket.version = static_cast<uint16>(tls1_2);
        ticket.cipher_suite = 0xc02f;
        ticket.extended_master_secret = original_ems;
        store->store(ticket);

        tls_session client;
        tls_session server;
        client.set_type(session_type_t::tls);
        server.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls1_2);
        server.get_tls_protection().set_tls_version(tls1_2);
        server.set_tls12_resumption_ticket_store(store);

        auto client_hello = new tls_handshake_client_hello(&client);
        client_hello->set_session_id(binary_t(32, 0x44));
        return_t ret = client_hello->add_ciphersuite(ticket.cipher_suite);
        _test_case.test(ret, __FUNCTION__, "configure the TLS 1.2 ClientHello cipher suite");
        if (errorcode_t::success != ret) {
            client_hello->release();
            return;
        }
        client_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_client, client_hello, [&](tls_extension* extension) -> return_t {
            static_cast<tls_extension_session_ticket*>(extension)->set_ticket(ticket.identity);
            return errorcode_t::success;
        });
        if (offered_ems) {
            client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
        }

        tls_record_handshake outgoing_client_hello(&client);
        outgoing_client_hello << client_hello;
        binary_t client_hello_wire;
        ret = outgoing_client_hello.write(from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "serialize a ClientHello carrying the cached ticket identity");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_record_handshake incoming_client_hello(&server);
        size_t client_hello_pos = 0;
        ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
        if (expect_abort) {
            _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, description);
        } else {
            _test_case.test(ret, __FUNCTION__, description);
        }

        _test_case.assert(expect_candidate == (1 == server.get_keyvalue().get(session_tls12_ticket_candidate)), __FUNCTION__,
                          "only an EMS-to-EMS offer may become a TLS 1.2 resumption candidate");
        if (expect_candidate) {
            _test_case.assert(ticket.master_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::master), __FUNCTION__,
                              "restore the original Master Secret for an EMS-compatible ticket");
        } else {
            _test_case.assert(server.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), __FUNCTION__,
                              "do not restore a Master Secret for a rejected or incompatible ticket");
        }

        size_t handshake_failure_count = test_count_fatal_alert(server, from_client, tls_alertdesc_t::handshake_failure);
        _test_case.assert((expect_abort ? 1u : 0u) == handshake_failure_count, __FUNCTION__,
                          "queue exactly one fatal handshake_failure only for the selected abort cases");

        if ((false == original_ems) && offered_ems && (false == expect_abort)) {
            server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
            auto server_hello = new tls_handshake_server_hello(&server);
            server_hello->set_version(tls1_2);
            ret = server_hello->set_cipher_suite(ticket.cipher_suite);
            _test_case.test(ret, __FUNCTION__, "select the original suite for the EMS full-handshake fallback");
            if (errorcode_t::success == ret) {
                tls_record_handshake outgoing_server_hello(&server);
                outgoing_server_hello << server_hello;
                binary_t server_hello_wire;
                ret = outgoing_server_hello.write(from_server, server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello for non-EMS-ticket to EMS full-handshake fallback");
                if (errorcode_t::success == ret) {
                    _test_case.assert(nullptr != server_hello->get_extensions().get(tls_extension_type_t::extended_master_secret), __FUNCTION__,
                                      "include EMS in ServerHello when the full-handshake ClientHello offered EMS");
                }
            }
        }
    };

    run_case(true, false, true, false, "abort resumption when an EMS ticket is offered without EMS (RFC 7627 MUST)");
    run_case(false, false, true, false, "abort non-EMS-to-non-EMS resumption under the chosen RFC 7627 SHOULD policy");
    run_case(false, true, false, false, "fall back to a full handshake when a non-EMS ticket is offered with EMS");
    run_case(true, true, false, true, "accept resumption when both the original session and ClientHello use EMS");
}

static void test_tls12_client_rejects_server_ems_mismatch() {
    // Scenario under test: TLS 1.2 client receives a resumed ServerHello with mismatched EMS state.
    // Action: process ServerHello after offering an EMS-bound ticket.
    // Expected: abort resumption when the server changes the EMS state.

    _test_case.begin("TLS 1.2 client aborts when resumed ServerHello changes EMS state");

    auto store = std::make_shared<tls12_resumption_ticket_store>();
    tls12_resumption_ticket ticket;
    ticket.identity = binary_t{0x71, 0x72, 0x73, 0x74};
    ticket.master_secret = binary_t(48, 0x5a);
    ticket.lifetime = 3600;
    ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    ticket.version = static_cast<uint16>(tls1_2);
    ticket.cipher_suite = 0xc02f;
    ticket.extended_master_secret = true;
    store->store(ticket);

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    server.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(store);
    server.set_tls12_resumption_ticket_store(store);

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    return_t ret = client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "configure the EMS-enabled TLS 1.2 ticket offer");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ClientHello with the confirmed EMS ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_client_hello(&server);
    size_t client_hello_pos = 0;
    ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.test(ret, __FUNCTION__, "recognize the ticket on the server");
    if (errorcode_t::success != ret) {
        return;
    }
    server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "retain the client's confirmed EMS ticket candidate");
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "recognize the same ticket on the server");

    // Simulate a non-conforming server that echoes the resumption Session ID
    // but omits EMS from ServerHello. Model the server as having incorrectly
    // classified the ticket as non-EMS so its own writer emits the echo.
    server.get_keyvalue().set(session_extended_master_secret, 0);
    server.get_keyvalue().set(session_tls12_ticket_ems, 0);
    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_version(tls1_2);
    ret = server_hello->set_cipher_suite(ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "select the ticket's original cipher suite");
    server_hello->set_random(binary_t(32, 0x7c));

    tls_record_handshake outgoing_server_hello(&server);
    outgoing_server_hello << server_hello;
    binary_t server_hello_wire;
    ret = outgoing_server_hello.write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write the deliberately inconsistent resumed ServerHello");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(client_hello->get_session_id() == server_hello->get_session_id(), __FUNCTION__, "echo the offered Session ID to signal abbreviated resumption");

    tls_record_handshake incoming_server_hello(&client);
    size_t server_hello_pos = 0;
    ret = incoming_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "abort instead of silently falling back when resumed ServerHello omits EMS");
    _test_case.assert(0 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__, "do not mark the mismatched EMS session as resumed");
    _test_case.assert(0 == client.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "retire the incompatible ticket candidate");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), __FUNCTION__,
                      "clear the cached Master Secret after the fatal mismatch");

    size_t fatal_handshake_failure_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::handshake_failure);
    _test_case.assert(1 == fatal_handshake_failure_count, __FUNCTION__, "queue exactly one fatal handshake_failure for the EMS mismatch");
}

static bool test_tls12_client_hello_session_id_length_bounds(const char* function_name) {
    // Scenario under test: TLS 1.2 ClientHello Session ID length boundary.
    // Action: serialize a 32-byte identifier and construct a malformed 33-byte vector.
    // Expected: accept the inclusive 32-byte limit and reject longer identifiers with decode_error.
    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    server.get_tls_protection().set_tls_version(tls1_2);

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->set_session_id(binary_t(32, 0x44));
    return_t ret = client_hello->add_ciphersuite(0xc02f);
    _test_case.test(ret, function_name, "configure ClientHello with a 32-byte Session ID");
    if (errorcode_t::success != ret) {
        client_hello->release();
        return false;
    }
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    client_hello->get_extensions().add(tls_extension_type_t::session_ticket, from_client, client_hello, [](tls_extension* extension) -> return_t {
        static_cast<tls_extension_session_ticket*>(extension)->set_ticket(binary_t{0x91, 0x92});
        return errorcode_t::success;
    });

    tls_session oversized_client_session;
    oversized_client_session.set_type(session_type_t::tls);
    oversized_client_session.get_tls_protection().set_tls_version(tls1_2);
    auto oversized_client_hello = new tls_handshake_client_hello(&oversized_client_session);
    oversized_client_hello->set_session_id(binary_t(33, 0x44));
    ret = oversized_client_hello->add_ciphersuite(0xc02f);
    _test_case.test(ret, function_name, "configure ClientHello with an oversized Session ID");
    if (errorcode_t::success != ret) {
        oversized_client_hello->release();
        return false;
    }
    tls_record_handshake outgoing_oversized_client_hello(&oversized_client_session);
    outgoing_oversized_client_hello << oversized_client_hello;
    binary_t oversized_client_hello_wire;
    ret = outgoing_oversized_client_hello.write(from_client, oversized_client_hello_wire);
    _test_case.assert(errorcode_t::invalid_parameter == ret, function_name, "refuse to serialize a ClientHello Session ID longer than 32 bytes");

    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, function_name, "serialize a 32-byte ClientHello Session ID");
    if (errorcode_t::success != ret) {
        return false;
    }

    // Build malformed input by changing only a valid 32-byte ClientHello
    // vector; the local writer must never emit the invalid 33-byte form.
    binary_t malformed_client_hello_wire = client_hello_wire;
    constexpr size_t client_record_header_size = 5;
    constexpr size_t client_handshake_header_size = 4;
    constexpr size_t client_hello_fixed_fields_size = 2 + 32;
    const size_t client_session_id_length_offset = client_record_header_size + client_handshake_header_size + client_hello_fixed_fields_size;
    const size_t client_cipher_suite_length_offset = client_session_id_length_offset + 1 + 32;
    if ((malformed_client_hello_wire.size() <= client_cipher_suite_length_offset) || (malformed_client_hello_wire[client_session_id_length_offset] != 32)) {
        _test_case.assert(false, function_name, "locate the 32-byte Session ID in the serialized ClientHello");
        return false;
    }
    malformed_client_hello_wire[client_session_id_length_offset] = 33;
    malformed_client_hello_wire.insert(malformed_client_hello_wire.begin() + client_cipher_suite_length_offset, 0x67);
    uint16 client_record_length = static_cast<uint16>((static_cast<uint16>(malformed_client_hello_wire[3]) << 8) | malformed_client_hello_wire[4]);
    ++client_record_length;
    malformed_client_hello_wire[3] = static_cast<byte_t>(client_record_length >> 8);
    malformed_client_hello_wire[4] = static_cast<byte_t>(client_record_length & 0xff);
    uint32 client_handshake_length =
        (static_cast<uint32>(malformed_client_hello_wire[6]) << 16) | (static_cast<uint32>(malformed_client_hello_wire[7]) << 8) | malformed_client_hello_wire[8];
    ++client_handshake_length;
    malformed_client_hello_wire[6] = static_cast<byte_t>((client_handshake_length >> 16) & 0xff);
    malformed_client_hello_wire[7] = static_cast<byte_t>((client_handshake_length >> 8) & 0xff);
    malformed_client_hello_wire[8] = static_cast<byte_t>(client_handshake_length & 0xff);

    tls_record_handshake incoming_client_hello(&server);
    size_t client_hello_pos = 0;
    ret = incoming_client_hello.read(from_client, malformed_client_hello_wire.data(), malformed_client_hello_wire.size(), client_hello_pos);
    _test_case.assert(errorcode_t::bad_format == ret, function_name, "reject a ClientHello Session ID longer than 32 bytes");

    size_t client_decode_error_count = test_count_fatal_alert(server, from_client, tls_alertdesc_t::decode_error);
    _test_case.assert(1 == client_decode_error_count, function_name, "queue exactly one fatal decode_error for oversized ClientHello Session ID");

    return true;
}

static void test_tls12_server_hello_session_id_length_bounds(const char* function_name) {
    // Scenario under test: TLS 1.2 ServerHello Session ID length boundary.
    // Action: serialize and parse the 32-byte limit, then mutate the wire vector to 33 bytes.
    // Expected: accept 32 bytes and reject oversized ServerHello input with decode_error.
    return_t ret = errorcode_t::success;
    tls_session server_hello_session;
    tls_session valid_client_hello_session;
    tls_session valid_receiving_client;
    server_hello_session.set_type(session_type_t::tls);
    valid_client_hello_session.set_type(session_type_t::tls);
    valid_receiving_client.set_type(session_type_t::tls);
    server_hello_session.get_tls_protection().set_tls_version(tls1_2);
    valid_client_hello_session.get_tls_protection().set_tls_version(tls1_2);
    valid_receiving_client.get_tls_protection().set_tls_version(tls1_2);
    server_hello_session.update_session_status(session_status_client_hello);
    server_hello_session.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);

    // Build and exchange a real ClientHello first so both endpoints
    // derive the secure-renegotiation offer state from the SCSV.
    auto valid_client_hello = new tls_handshake_client_hello(&valid_client_hello_session);
    valid_client_hello->set_session_id(binary_t(32, 0x44));
    ret = valid_client_hello->add_ciphersuite(0xc02f);
    _test_case.test(ret, function_name, "configure a matching ClientHello for the maximum-length ServerHello case");
    if (errorcode_t::success != ret) {
        valid_client_hello->release();
        return;
    }
    valid_client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, valid_client_hello, nullptr);

    tls_record_handshake outgoing_valid_client_hello(&valid_client_hello_session);
    outgoing_valid_client_hello << valid_client_hello;
    binary_t valid_client_hello_wire;
    ret = outgoing_valid_client_hello.write(from_client, valid_client_hello_wire);
    _test_case.test(ret, function_name, "serialize a matching ClientHello for the maximum-length ServerHello case");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_record_handshake incoming_server_client_hello(&server_hello_session);
    size_t server_client_hello_pos = 0;
    ret = incoming_server_client_hello.read(from_client, valid_client_hello_wire.data(), valid_client_hello_wire.size(), server_client_hello_pos);
    _test_case.test(ret, function_name, "server parses the matching ClientHello before constructing ServerHello");
    if (errorcode_t::success != ret) {
        return;
    }

    auto server_hello = new tls_handshake_server_hello(&server_hello_session);
    server_hello->set_version(tls1_2);
    server_hello->set_random(binary_t(32, 0x55));
    server_hello->set_session_id(binary_t(32, 0x66));
    ret = server_hello->set_cipher_suite(0xc02f);
    _test_case.test(ret, function_name, "configure ServerHello with a 32-byte Session ID");
    if (errorcode_t::success != ret) {
        return;
    }
    server_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_server, server_hello, nullptr);

    tls_record_handshake outgoing_server_hello(&server_hello_session);
    outgoing_server_hello << server_hello;
    binary_t server_hello_wire;
    ret = outgoing_server_hello.write(from_server, server_hello_wire);
    _test_case.test(ret, function_name, "serialize a valid ServerHello before mutating its Session ID length");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session oversized_server_hello_session;
    oversized_server_hello_session.set_type(session_type_t::tls);
    oversized_server_hello_session.get_tls_protection().set_tls_version(tls1_2);
    oversized_server_hello_session.update_session_status(session_status_client_hello);
    oversized_server_hello_session.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    auto oversized_server_hello = new tls_handshake_server_hello(&oversized_server_hello_session);
    oversized_server_hello->set_version(tls1_2);
    oversized_server_hello->set_random(binary_t(32, 0x55));
    oversized_server_hello->set_session_id(binary_t(33, 0x66));
    ret = oversized_server_hello->set_cipher_suite(0xc02f);
    _test_case.test(ret, function_name, "configure ServerHello with an oversized Session ID");
    if (errorcode_t::success != ret) {
        oversized_server_hello->release();
        return;
    }
    oversized_server_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_server, oversized_server_hello, nullptr);
    tls_record_handshake outgoing_oversized_server_hello(&oversized_server_hello_session);
    outgoing_oversized_server_hello << oversized_server_hello;
    binary_t oversized_server_hello_wire;
    ret = outgoing_oversized_server_hello.write(from_server, oversized_server_hello_wire);
    _test_case.assert(errorcode_t::invalid_parameter == ret, function_name, "refuse to serialize a ServerHello Session ID longer than 32 bytes");

    // The protocol boundary is inclusive: a 32-byte Session ID must
    // remain readable before the malformed 33-byte variant is constructed.
    tls_record_handshake incoming_valid_client_hello(&valid_receiving_client);
    size_t valid_client_hello_pos = 0;
    ret = incoming_valid_client_hello.read(from_client, valid_client_hello_wire.data(), valid_client_hello_wire.size(), valid_client_hello_pos);
    _test_case.test(ret, function_name, "parse the matching ClientHello before receiving ServerHello");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_valid_server_hello(&valid_receiving_client);
    size_t valid_server_hello_pos = 0;
    ret = incoming_valid_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), valid_server_hello_pos);
    _test_case.assert(errorcode_t::success == ret, function_name, "accept a ServerHello Session ID of exactly 32 bytes");
    if (errorcode_t::success != ret) {
        return;
    }

    // Preserve a valid record/handshake structure, then mutate only the
    // ServerHello Session ID vector to create the malformed 33-byte input.
    constexpr size_t record_header_size = 5;
    constexpr size_t handshake_header_size = 4;
    constexpr size_t server_hello_fixed_fields_size = 2 + 32;
    const size_t session_id_length_offset = record_header_size + handshake_header_size + server_hello_fixed_fields_size;
    const size_t cipher_suite_offset = session_id_length_offset + 1 + 32;
    if ((server_hello_wire.size() < cipher_suite_offset) || (server_hello_wire[session_id_length_offset] != 32)) {
        _test_case.assert(false, function_name, "locate the 32-byte Session ID in the serialized ServerHello");
        return;
    }
    server_hello_wire[session_id_length_offset] = 33;
    server_hello_wire.insert(server_hello_wire.begin() + cipher_suite_offset, 0x67);
    uint16 record_length = static_cast<uint16>((static_cast<uint16>(server_hello_wire[3]) << 8) | server_hello_wire[4]);
    ++record_length;
    server_hello_wire[3] = static_cast<byte_t>(record_length >> 8);
    server_hello_wire[4] = static_cast<byte_t>(record_length & 0xff);
    uint32 handshake_length = (static_cast<uint32>(server_hello_wire[6]) << 16) | (static_cast<uint32>(server_hello_wire[7]) << 8) | server_hello_wire[8];
    ++handshake_length;
    server_hello_wire[6] = static_cast<byte_t>((handshake_length >> 16) & 0xff);
    server_hello_wire[7] = static_cast<byte_t>((handshake_length >> 8) & 0xff);
    server_hello_wire[8] = static_cast<byte_t>(handshake_length & 0xff);

    tls_record_handshake incoming_server_hello(&valid_receiving_client);
    size_t server_hello_pos = 0;
    ret = incoming_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.assert(errorcode_t::bad_format == ret, function_name, "reject a ServerHello Session ID longer than 32 bytes");

    size_t server_decode_error_count = test_count_fatal_alert(valid_receiving_client, from_server, tls_alertdesc_t::decode_error);
    _test_case.assert(1 == server_decode_error_count, function_name, "queue exactly one fatal decode_error for oversized ServerHello Session ID");
}

static void test_tls12_session_id_length_bounds() {
    // Scenario under test: TLS 1.2 Session ID length is limited to 32 bytes.
    // Action: exercise ClientHello and ServerHello serialization and parsing boundaries.
    // Expected: accept 32-byte identifiers and reject 33-byte identifiers.
    _test_case.begin("TLS Session ID length is limited to 32 bytes");

    if (false == test_tls12_client_hello_session_id_length_bounds(__FUNCTION__)) {
        return;
    }
    test_tls12_server_hello_session_id_length_bounds(__FUNCTION__);
}

struct tls12_abbreviated_ticket_test_context {
    std::shared_ptr<tls12_resumption_ticket_store> client_store;
    std::shared_ptr<tls12_resumption_ticket_store> server_store;
    tls12_resumption_ticket ticket;
    binary_t renewal_identity;
    tls12_resumption_ticket client_renewal;
};

static bool test_tls12_abbreviated_ticket_initial_handshake(const char* function_name, tls12_abbreviated_ticket_test_context& context) {
    // Scenario under test: initial TLS 1.2 ticket resumption and renewal.
    // Action: resume with a cached ticket and exchange Finished messages.
    // Expected: authenticate both Finished messages before publishing renewed tickets.
    tls_session first_time_client;
    first_time_client.set_type(session_type_t::tls);
    first_time_client.get_tls_protection().set_tls_version(tls1_2);
    first_time_client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
    auto first_time_client_hello = new tls_handshake_client_hello(&first_time_client);
    return_t ret = first_time_client_hello->add_ciphersuite(0xc02f);
    _test_case.test(ret, function_name, "configure a first-time TLS 1.2 client");
    tls_record_handshake first_time_client_record(&first_time_client);
    first_time_client_record << first_time_client_hello;
    binary_t first_time_client_wire;
    ret = first_time_client_record.write(from_client, first_time_client_wire);
    _test_case.test(ret, function_name, "write a first-time ClientHello with an empty SessionTicket extension");
    if (errorcode_t::success != ret) {
        return false;
    }
    auto empty_ticket_offer = static_cast<tls_extension_session_ticket*>(first_time_client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != empty_ticket_offer) && empty_ticket_offer->get_ticket().empty(), function_name,
                      "request ticket issuance when the client has no cached identity");

    context.client_store = std::make_shared<tls12_resumption_ticket_store>();
    auto& client_store = context.client_store;
    context.server_store = std::make_shared<tls12_resumption_ticket_store>();
    auto& server_store = context.server_store;
    auto& ticket = context.ticket;
    ticket.identity = binary_t{0x91, 0x92, 0x93, 0x94};
    ticket.master_secret = binary_t(48, 0x5a);
    ticket.lifetime = 3600;
    ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    ticket.version = static_cast<uint16>(tls1_2);
    ticket.cipher_suite = 0xc02f;
    ticket.extended_master_secret = true;

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    server.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(client_store);
    server.set_tls12_resumption_ticket_store(server_store);
    client.stage_tls12_resumption_ticket(ticket);
    server.stage_tls12_resumption_ticket(ticket);
    bool client_ticket_confirmed = client.confirm_tls12_resumption_ticket(ticket.identity);
    _test_case.assert(client_ticket_confirmed, function_name, "activate the client-side cached ticket");
    bool server_ticket_confirmed = server.confirm_tls12_resumption_ticket(ticket.identity);
    _test_case.assert(server_ticket_confirmed, function_name, "activate the server-side cached ticket");

    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    client_hello->get_extensions().add(tls_extension_type_t::encrypt_then_mac, from_client, client_hello, nullptr);
    ret = client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, function_name, "configure the ticket's TLS 1.2 cipher suite");
    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, function_name, "write ClientHello with the cached TLS 1.2 ticket");
    if (errorcode_t::success != ret) {
        return false;
    }
    auto offered_ticket = static_cast<tls_extension_session_ticket*>(client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != offered_ticket) && (ticket.identity == offered_ticket->get_ticket()), function_name,
                      "automatically offer the cached opaque ticket identity");
    _test_case.assert((false == client_hello->get_session_id().empty()), function_name, "generate a non-empty Session ID for RFC 5077 resumption");
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_candidate), function_name, "retain the local ticket candidate");

    tls_record_handshake incoming_client_hello(&server);
    size_t client_hello_pos = 0;
    ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.test(ret, function_name, "read ClientHello and find the ticket in the server cache");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(client_hello_wire.size() == client_hello_pos, function_name, "consume the complete ticket-bearing ClientHello");
    server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_candidate), function_name, "validate the server-side ticket candidate");
    _test_case.assert(ticket.master_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::master), function_name,
                      "restore the cached Master Secret on the server");

    context.renewal_identity = binary_t{0xa1, 0xa2, 0xa3, 0xa4};
    const auto& renewal_identity = context.renewal_identity;
    server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, renewal_identity);
    server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 1800);
    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_version(tls1_2);
    ret = server_hello->set_cipher_suite(ticket.cipher_suite);
    _test_case.test(ret, function_name, "select the ticket's original cipher suite");
    server_hello->set_random(binary_t(32, 0x6a));
    tls_record_handshake outgoing_server_hello(&server);
    outgoing_server_hello << server_hello;
    binary_t server_hello_wire;
    ret = outgoing_server_hello.write(from_server, server_hello_wire);
    _test_case.test(ret, function_name, "write ServerHello echoing the accepted ticket Session ID");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake incoming_server_hello(&client);
    size_t server_hello_pos = 0;
    ret = incoming_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, function_name, "read ServerHello and confirm ticket resumption by Session ID echo");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(server_hello_wire.size() == server_hello_pos, function_name, "consume the complete ServerHello");
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), function_name, "recognize the abbreviated handshake on the client");
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_resumed), function_name, "commit ticket acceptance on the server");
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_acknowledged), function_name, "observe the separate ticket-issuance acknowledgement");
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_acknowledged), function_name, "record the ticket-issuance acknowledgement on the server");
    _test_case.assert(ticket.master_secret == client.get_tls_protection().get_secrets().get(tls_secret_t::master), function_name,
                      "retain the cached Master Secret on the client");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::client_key) == server.get_tls_protection().get_secrets().get(tls_secret_t::client_key),
                      function_name, "derive matching client write keys from the ticket Master Secret");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::server_key) == server.get_tls_protection().get_secrets().get(tls_secret_t::server_key),
                      function_name, "derive matching server write keys from the ticket Master Secret");

    tls_handshake_new_session_ticket outgoing_ticket(&server);
    binary_t ticket_wire;
    ret = outgoing_ticket.write(from_server, ticket_wire);
    _test_case.test(ret, function_name, "write a replacement ticket before Server Finished");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(1 == server.get_pending_tls12_resumption_tickets().size(), function_name, "keep the server's replacement ticket pending");

    tls_handshake_new_session_ticket incoming_ticket(&client);
    size_t ticket_pos = 0;
    ret = incoming_ticket.read(from_server, ticket_wire.data(), ticket_wire.size(), ticket_pos);
    _test_case.test(ret, function_name, "accept replacement ticket before Client Finished in abbreviated flow");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(renewal_identity == client.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket_pending), function_name,
                      "keep the replacement ticket pending until Server Finished authentication");
    tls12_resumption_ticket client_ticket_before_finished;
    bool client_ticket_before_finished_found_at_2055 = client.find_tls12_resumption_ticket(renewal_identity, client_ticket_before_finished);
    _test_case.assert(false == client_ticket_before_finished_found_at_2055, function_name,
                      "do not expose the client's replacement ticket before Server Finished authentication");

    tls_record_change_cipher_spec server_ccs(&server);
    binary_t server_ccs_wire;
    ret = server_ccs.write(from_server, server_ccs_wire);
    _test_case.test(ret, function_name, "write server CCS before Client Finished");
    if (errorcode_t::success != ret) {
        return false;
    }
    tls_records incoming_server_ccs;
    ret = incoming_server_ccs.read(&client, from_server, server_ccs_wire);
    _test_case.test(ret, function_name, "read server CCS before Client Finished");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake outgoing_server_finished(&server);
    outgoing_server_finished << new tls_handshake_finished(&server);
    binary_t server_finished_wire;
    ret = outgoing_server_finished.write(from_server, server_finished_wire);
    _test_case.test(ret, function_name, "write Server Finished first in the abbreviated handshake");
    if (errorcode_t::success != ret) {
        return false;
    }
    tls12_resumption_ticket not_yet_confirmed;
    _test_case.assert(1 == server.get_pending_tls12_resumption_tickets().size(), function_name, "keep the server's renewed ticket pending after its own Finished");
    bool not_yet_confirmed_found_at_2082 = server.find_tls12_resumption_ticket(renewal_identity, not_yet_confirmed);
    _test_case.assert(false == not_yet_confirmed_found_at_2082, function_name, "do not expose the server's renewed ticket before Client Finished authentication");
    tls_records incoming_server_finished;
    ret = incoming_server_finished.read(&client, from_server, server_finished_wire);
    _test_case.test(ret, function_name, "verify Server Finished before the client sends Finished");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(0 != (client.get_session_status() & session_status_server_finished), function_name, "record authenticated Server Finished");
    _test_case.assert(renewal_identity == client.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket), function_name,
                      "activate the replacement ticket after Server Finished authentication");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket_pending).empty(), function_name,
                      "clear pending replacement ticket bytes");
    auto& client_renewal = context.client_renewal;
    bool client_renewal_found_at_2096 = client.find_tls12_resumption_ticket(renewal_identity, client_renewal);
    _test_case.assert(client_renewal_found_at_2096, function_name, "publish the replacement ticket in the client cache after Server Finished");

    tls_record_change_cipher_spec client_ccs(&client);
    binary_t client_ccs_wire;
    ret = client_ccs.write(from_client, client_ccs_wire);
    _test_case.test(ret, function_name, "write client CCS after Server Finished");
    if (errorcode_t::success != ret) {
        return false;
    }
    tls_records incoming_client_ccs;
    ret = incoming_client_ccs.read(&server, from_client, client_ccs_wire);
    _test_case.test(ret, function_name, "read client CCS after Server Finished");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake outgoing_client_finished(&client);
    outgoing_client_finished << new tls_handshake_finished(&client);
    binary_t client_finished_wire;
    ret = outgoing_client_finished.write(from_client, client_finished_wire);
    _test_case.test(ret, function_name, "write Client Finished after Server Finished");
    if (errorcode_t::success != ret) {
        return false;
    }
    tls_records incoming_client_finished;
    ret = incoming_client_finished.read(&server, from_client, client_finished_wire);
    _test_case.test(ret, function_name, "verify Client Finished last in the abbreviated handshake");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(0 == server.get_pending_tls12_resumption_tickets().size(), function_name,
                      "activate the server's replacement ticket after Client Finished authentication");
    tls12_resumption_ticket cached_renewal;
    bool cached_renewal_found_at_2130 = server.find_tls12_resumption_ticket(renewal_identity, cached_renewal);
    _test_case.assert(cached_renewal_found_at_2130, function_name, "publish the replacement ticket in the shared server cache");

    return true;
}

static bool test_tls12_abbreviated_ticket_renewed_resumption(const char* function_name, tls12_abbreviated_ticket_test_context& context) {
    // Scenario under test: reuse of a ticket renewed by an abbreviated handshake.
    // Action: establish a subsequent connection with the renewed ticket identity.
    // Expected: accept the renewed identity and restore the original Master Secret.
    return_t ret = errorcode_t::success;
    auto& client_renewal = context.client_renewal;
    const auto& renewal_identity = context.renewal_identity;
    auto& server_store = context.server_store;
    // Reuse the renewed identity from a separate connection. The client-side
    // cache was populated by authenticated Server Finished above; the server
    // cache was populated only after authenticated Client Finished.
    auto renewed_client_store = std::make_shared<tls12_resumption_ticket_store>();
    renewed_client_store->store(client_renewal);
    tls_session renewed_client;
    tls_session renewed_server;
    renewed_client.set_type(session_type_t::tls);
    renewed_server.set_type(session_type_t::tls);
    renewed_client.get_tls_protection().set_tls_version(tls1_2);
    renewed_server.get_tls_protection().set_tls_version(tls1_2);
    renewed_client.set_tls12_resumption_ticket_store(renewed_client_store);
    renewed_server.set_tls12_resumption_ticket_store(server_store);
    renewed_client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);

    auto renewed_client_hello = new tls_handshake_client_hello(&renewed_client);
    renewed_client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, renewed_client_hello, nullptr);
    ret = renewed_client_hello->add_ciphersuite(client_renewal.cipher_suite);
    _test_case.test(ret, function_name, "configure a new connection for the renewed ticket");
    tls_record_handshake renewed_outgoing_client_hello(&renewed_client);
    renewed_outgoing_client_hello << renewed_client_hello;
    binary_t renewed_client_hello_wire;
    ret = renewed_outgoing_client_hello.write(from_client, renewed_client_hello_wire);
    _test_case.test(ret, function_name, "offer the renewed ticket on a subsequent connection");
    if (errorcode_t::success != ret) {
        return false;
    }
    auto renewed_offer = static_cast<tls_extension_session_ticket*>(renewed_client_hello->get_extensions().get(tls_extension_type_t::session_ticket));
    _test_case.assert((nullptr != renewed_offer) && (renewal_identity == renewed_offer->get_ticket()), function_name,
                      "select the renewed identity from the client cache");

    tls_record_handshake renewed_incoming_client_hello(&renewed_server);
    size_t renewed_client_hello_pos = 0;
    ret = renewed_incoming_client_hello.read(from_client, renewed_client_hello_wire.data(), renewed_client_hello_wire.size(), renewed_client_hello_pos);
    _test_case.test(ret, function_name, "look up the renewed identity in the server cache on a new connection");
    if (errorcode_t::success != ret) {
        return false;
    }
    renewed_server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(1 == renewed_server.get_keyvalue().get(session_tls12_ticket_candidate), function_name, "accept the renewed ticket from the shared server cache");
    _test_case.assert(client_renewal.master_secret == renewed_server.get_tls_protection().get_secrets().get(tls_secret_t::master), function_name,
                      "restore the renewed ticket's original Master Secret");

    auto renewed_server_hello = new tls_handshake_server_hello(&renewed_server);
    renewed_server_hello->set_version(tls1_2);
    ret = renewed_server_hello->set_cipher_suite(client_renewal.cipher_suite);
    _test_case.test(ret, function_name, "select the renewed ticket's original cipher suite");
    renewed_server_hello->set_random(binary_t(32, 0x7b));
    tls_record_handshake renewed_outgoing_server_hello(&renewed_server);
    renewed_outgoing_server_hello << renewed_server_hello;
    binary_t renewed_server_hello_wire;
    ret = renewed_outgoing_server_hello.write(from_server, renewed_server_hello_wire);
    _test_case.test(ret, function_name, "write ServerHello for renewed-ticket resumption");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake renewed_incoming_server_hello(&renewed_client);
    size_t renewed_server_hello_pos = 0;
    ret = renewed_incoming_server_hello.read(from_server, renewed_server_hello_wire.data(), renewed_server_hello_wire.size(), renewed_server_hello_pos);
    _test_case.test(ret, function_name, "accept ServerHello for renewed-ticket resumption");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(1 == renewed_client.get_keyvalue().get(session_tls12_ticket_resumed), function_name, "resume the subsequent connection with the renewed identity");
    _test_case.assert(client_renewal.master_secret == renewed_client.get_tls_protection().get_secrets().get(tls_secret_t::master), function_name,
                      "restore the renewed Master Secret on the client");
    _test_case.assert(renewed_client.get_tls_protection().get_secrets().get(tls_secret_t::client_key) ==
                          renewed_server.get_tls_protection().get_secrets().get(tls_secret_t::client_key),
                      function_name, "derive matching client write keys from the renewed ticket");
    _test_case.assert(renewed_client.get_tls_protection().get_secrets().get(tls_secret_t::server_key) ==
                          renewed_server.get_tls_protection().get_secrets().get(tls_secret_t::server_key),
                      function_name, "derive matching server write keys from the renewed ticket");

    return true;
}

static bool test_tls12_abbreviated_ticket_unknown_identity_fallback(const char* function_name, tls12_abbreviated_ticket_test_context& context) {
    // Scenario under test: a server receives a ticket identity absent from its cache.
    // Action: offer a locally cached identity to a server without the matching entry.
    // Expected: decline resumption and continue with the full-handshake path.
    return_t ret = errorcode_t::success;
    auto& client_store = context.client_store;
    auto& ticket = context.ticket;
    // A client may offer a cached identity that this server no longer has.
    // The server must decline resumption by not echoing the Session ID.
    tls_session fallback_client;
    tls_session fallback_server;
    fallback_client.set_type(session_type_t::tls);
    fallback_server.set_type(session_type_t::tls);
    fallback_client.get_tls_protection().set_tls_version(tls1_2);
    fallback_server.get_tls_protection().set_tls_version(tls1_2);
    fallback_client.set_tls12_resumption_ticket_store(client_store);

    auto fallback_client_hello = new tls_handshake_client_hello(&fallback_client);
    fallback_client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, fallback_client_hello, nullptr);
    ret = fallback_client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, function_name, "configure a TLS 1.2 ClientHello for an unknown-ticket fallback");
    tls_record_handshake fallback_outgoing_client_hello(&fallback_client);
    fallback_outgoing_client_hello << fallback_client_hello;
    binary_t fallback_client_hello_wire;
    ret = fallback_outgoing_client_hello.write(from_client, fallback_client_hello_wire);
    _test_case.test(ret, function_name, "offer a locally cached ticket to a server without that ticket");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake fallback_incoming_client_hello(&fallback_server);
    size_t fallback_client_hello_pos = 0;
    ret = fallback_incoming_client_hello.read(from_client, fallback_client_hello_wire.data(), fallback_client_hello_wire.size(), fallback_client_hello_pos);
    _test_case.test(ret, function_name, "read the unknown ticket identity on the server");
    if (errorcode_t::success != ret) {
        return false;
    }
    fallback_server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(0 == fallback_server.get_keyvalue().get(session_tls12_ticket_candidate), function_name, "decline a ticket identity absent from the server cache");

    auto fallback_server_hello = new tls_handshake_server_hello(&fallback_server);
    fallback_server_hello->set_version(tls1_2);
    ret = fallback_server_hello->set_cipher_suite(ticket.cipher_suite);
    _test_case.test(ret, function_name, "select the TLS 1.2 cipher suite for full-handshake fallback");
    fallback_server_hello->set_random(binary_t(32, 0x7a));
    tls_record_handshake fallback_outgoing_server_hello(&fallback_server);
    fallback_outgoing_server_hello << fallback_server_hello;
    binary_t fallback_server_hello_wire;
    ret = fallback_outgoing_server_hello.write(from_server, fallback_server_hello_wire);
    _test_case.test(ret, function_name, "write ServerHello without echoing a rejected ticket Session ID");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(fallback_server_hello->get_session_id().empty(), function_name, "do not echo the Session ID for an unknown ticket");

    tls_record_handshake fallback_incoming_server_hello(&fallback_client);
    size_t fallback_server_hello_pos = 0;
    ret = fallback_incoming_server_hello.read(from_server, fallback_server_hello_wire.data(), fallback_server_hello_wire.size(), fallback_server_hello_pos);
    _test_case.test(ret, function_name, "read ServerHello and fall back from the unknown ticket");
    _test_case.assert(0 == fallback_client.get_keyvalue().get(session_tls12_ticket_resumed), function_name,
                      "keep the client on the full-handshake path after ticket rejection");
    _test_case.assert(0 == fallback_client.get_keyvalue().get(session_tls12_ticket_acknowledged), function_name,
                      "do not mistake ticket rejection for a ticket-issuance acknowledgement");
    _test_case.assert(fallback_client.get_tls_protection().get_secrets().get(tls_secret_t::master).empty(), function_name,
                      "discard the cached Master Secret after ticket rejection");

    return true;
}

static bool test_tls12_abbreviated_ticket_expired_server_identity(const char* function_name, tls12_abbreviated_ticket_test_context& context) {
    // Scenario under test: a server receives an expired cached TLS 1.2 ticket.
    // Action: offer a still-cached client identity whose server-side copy has expired.
    // Expected: reject and evict the expired server-side ticket.
    return_t ret = errorcode_t::success;
    auto& client_store = context.client_store;
    auto& ticket = context.ticket;
    tls12_resumption_ticket expired_ticket = ticket;
    expired_ticket.timestamp = 1;
    expired_ticket.lifetime = 1;
    auto expired_server_store = std::make_shared<tls12_resumption_ticket_store>();
    expired_server_store->store(expired_ticket);

    tls_session expired_client;
    tls_session expired_server;
    expired_client.set_type(session_type_t::tls);
    expired_server.set_type(session_type_t::tls);
    expired_client.get_tls_protection().set_tls_version(tls1_2);
    expired_server.get_tls_protection().set_tls_version(tls1_2);
    expired_client.set_tls12_resumption_ticket_store(client_store);
    expired_client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
    expired_server.set_tls12_resumption_ticket_store(expired_server_store);

    auto expired_client_hello = new tls_handshake_client_hello(&expired_client);
    expired_client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, expired_client_hello, nullptr);
    ret = expired_client_hello->add_ciphersuite(ticket.cipher_suite);
    _test_case.test(ret, function_name, "configure ClientHello for an expired server-side ticket");
    tls_record_handshake expired_outgoing_client_hello(&expired_client);
    expired_outgoing_client_hello << expired_client_hello;
    binary_t expired_client_hello_wire;
    ret = expired_outgoing_client_hello.write(from_client, expired_client_hello_wire);
    _test_case.test(ret, function_name, "offer the still-cached client identity to a server with an expired copy");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_record_handshake expired_incoming_client_hello(&expired_server);
    size_t expired_client_hello_pos = 0;
    ret = expired_incoming_client_hello.read(from_client, expired_client_hello_wire.data(), expired_client_hello_wire.size(), expired_client_hello_pos);
    _test_case.test(ret, function_name, "read ClientHello and reject the expired server-side ticket");
    if (errorcode_t::success != ret) {
        return false;
    }
    _test_case.assert(0 == expired_server.get_keyvalue().get(session_tls12_ticket_candidate), function_name, "decline an expired TLS 1.2 ticket");
    tls12_resumption_ticket evicted_ticket;
    bool evicted_ticket_found_at_2302 = expired_server.find_tls12_resumption_ticket(expired_ticket.identity, evicted_ticket);
    _test_case.assert(false == evicted_ticket_found_at_2302, function_name, "evict an expired TLS 1.2 ticket from the shared server-side store");

    return true;
}

static void test_tls12_abbreviated_ticket_handshake() {
    // RFC 5077: a cached ticket and echoed Session ID select the abbreviated
    // handshake. The server Finished precedes the client Finished.
    // Scenario under test: abbreviated TLS 1.2 SessionTicket handshake.
    // Action: resume, renew, reuse, and reject ticket identities across connections.
    // Expected: enforce ticket acceptance and Finished-authenticated renewal transitions.
    _test_case.begin("TLS 1.2 abbreviated SessionTicket handshake");

    tls12_abbreviated_ticket_test_context context;
    if (false == test_tls12_abbreviated_ticket_initial_handshake(__FUNCTION__, context)) {
        return;
    }
    if (false == test_tls12_abbreviated_ticket_renewed_resumption(__FUNCTION__, context)) {
        return;
    }
    if (false == test_tls12_abbreviated_ticket_unknown_identity_fallback(__FUNCTION__, context)) {
        return;
    }
    if (false == test_tls12_abbreviated_ticket_expired_server_identity(__FUNCTION__, context)) {
        return;
    }
}

static void test_tls12_composer_abbreviated_handshake_records() {
    // Scenario under test: TLS 1.2 composer record ordering for abbreviated SessionTicket handshakes.
    // Action: compose abbreviated flights with no renewal, an acknowledged renewal, and a deferred renewal.
    // Expected: emit ServerHello first, then the optional ticket, CCS, and protected Server Finished without duplication.

    // Exercise the actual server composer path for RFC 5077 abbreviated handshakes.
    // Expected: ServerHello is emitted first, followed by an optional renewal
    // ticket, CCS, and protected Server Finished. A later Client Finished
    // notification must not cause a second Server Finished.
    _test_case.begin("TLS 1.2 composer emits abbreviated SessionTicket record sequence");

    auto run_case = [](bool issue_ticket, bool defer_ticket_until_after_server_hello) -> void {
        auto client_store = std::make_shared<tls12_resumption_ticket_store>();
        auto server_store = std::make_shared<tls12_resumption_ticket_store>();

        tls12_resumption_ticket ticket;
        ticket.identity = binary_t{0x91, 0x92, 0x93, 0x94};
        ticket.master_secret = binary_t(48, 0x5a);
        ticket.lifetime = 3600;
        ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        ticket.version = static_cast<uint16>(tls1_2);
        ticket.cipher_suite = 0xc02f;
        ticket.extended_master_secret = true;

        tls_session client;
        tls_session server;
        client.set_type(session_type_t::tls);
        server.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls1_2);
        server.get_tls_protection().set_tls_version(tls1_2);
        client.set_tls12_resumption_ticket_store(client_store);
        server.set_tls12_resumption_ticket_store(server_store);
        client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
        client.stage_tls12_resumption_ticket(ticket);
        server.stage_tls12_resumption_ticket(ticket);
        bool client_ticket_confirmed = client.confirm_tls12_resumption_ticket(ticket.identity);
        _test_case.assert(client_ticket_confirmed, __FUNCTION__, "activate the client-side ticket for composer coverage");
        bool server_ticket_confirmed = server.confirm_tls12_resumption_ticket(ticket.identity);
        _test_case.assert(server_ticket_confirmed, __FUNCTION__, "activate the server-side ticket for composer coverage");

        auto client_hello = new tls_handshake_client_hello(&client);
        client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
        auto supported_groups = new tls_extension_supported_groups(client_hello);
        supported_groups->add("secp256r1");
        client_hello->get_extensions().add(supported_groups);
        return_t ret = client_hello->add_ciphersuite(ticket.cipher_suite);
        _test_case.test(ret, __FUNCTION__, "configure the abbreviated-handshake ClientHello cipher suite");
        if (errorcode_t::success != ret) {
            return;
        }
        tls_record_handshake outgoing_client_hello(&client);
        outgoing_client_hello << client_hello;
        binary_t client_hello_wire;
        ret = outgoing_client_hello.write(from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "serialize the ticket-bearing ClientHello for the composer");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_records incoming_client_hello;
        ret = incoming_client_hello.read(&server, from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "parse ClientHello and recover the server-side ticket candidate");
        if (errorcode_t::success != ret) {
            return;
        }
        server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__,
                          "retain the validated ticket candidate before composer negotiation");
        const auto& server_secrets = server.get_tls_protection().get_secrets();
        const auto& server_ticket_state = server.get_keyvalue();
        _test_case.assert(1 == server_ticket_state.get(session_tls12_ticket_identity_present), __FUNCTION__, "retain the non-empty ticket identity from ClientHello");
        _test_case.assert(false == server_secrets.get(tls_secret_t::session_id).empty(), __FUNCTION__,
                          "retain the non-empty ClientHello Session ID required for RFC 5077 resumption");
        _test_case.assert(ticket.cipher_suite == server_ticket_state.get(session_tls12_ticket_cipher_suite), __FUNCTION__,
                          "retain the ticket cipher suite for ServerHello negotiation");
        _test_case.assert(server_secrets.get(tls_secret_t::tls12_resumption_alpn) == server_secrets.get(tls_secret_t::alpn), __FUNCTION__,
                          "match the ticket ALPN state against the negotiated ALPN state");
        _test_case.assert(ticket.extended_master_secret == (0 != server_ticket_state.get(session_tls12_ticket_ems)), __FUNCTION__,
                          "retain the ticket Extended Master Secret setting");
        _test_case.assert(ticket.encrypt_then_mac == (0 != server_ticket_state.get(session_tls12_ticket_etm)), __FUNCTION__,
                          "retain the ticket Encrypt-then-MAC setting");
        if (issue_ticket && (false == defer_ticket_until_after_server_hello)) {
            server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xa1, 0xa2, 0xa3, 0xa4});
            server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 1800);
        }

        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);

        std::vector<binary_t> chunks;
        auto capture = [&](tls_session*, binary_t& wire) {
            chunks.push_back(wire);
            // A ticket made available only after ServerHello cannot be
            // acknowledged in that ServerHello. The composer must therefore
            // omit it from the abbreviated flight.
            if (defer_ticket_until_after_server_hello && (1 == chunks.size())) {
                server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0xa1, 0xa2, 0xa3, 0xa4});
                server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 1800);
            }
        };

        ret = composer.session_status_changed(session_status_client_hello, from_server, 0, capture);
        _test_case.test(ret, __FUNCTION__, "compose the ServerHello and abbreviated server flight");
        if (errorcode_t::success != ret) {
            _test_case.assert(0 != chunks.size(), __FUNCTION__, "capture the ServerHello callback before the composer failure");
            _test_case.assert(0 == server.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__,
                              "identify whether ticket resumption was rejected before the composer failure");
            // The composer drains queued fatal alerts while serializing the
            // alert record, so querying the session alert queue here is too late.
            return;
        }
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__, "select abbreviated resumption in the composed ServerHello");
        _test_case.assert(2 == chunks.size(), __FUNCTION__, "emit ServerHello and the remaining abbreviated flight separately");
        if (2 != chunks.size()) {
            return;
        }

        auto parse_record_types = [](const binary_t& wire, std::vector<uint8>& types, std::vector<size_t>& offsets, std::vector<uint16>& fragment_sizes) -> bool {
            size_t pos = 0;
            while (pos < wire.size()) {
                if (wire.size() - pos < 5) {
                    return false;
                }
                uint16 fragment_size = test_read_u16(wire, pos + 3);
                size_t record_size = static_cast<size_t>(5) + fragment_size;
                if (record_size > wire.size() - pos) {
                    return false;
                }
                types.push_back(wire[pos]);
                offsets.push_back(pos);
                fragment_sizes.push_back(fragment_size);
                pos += record_size;
            }
            return pos == wire.size();
        };

        std::vector<uint8> server_hello_types;
        std::vector<size_t> server_hello_offsets;
        std::vector<uint16> server_hello_fragment_sizes;
        bool server_hello_records_valid = parse_record_types(chunks[0], server_hello_types, server_hello_offsets, server_hello_fragment_sizes);
        _test_case.assert(server_hello_records_valid, __FUNCTION__, "parse complete TLS record boundaries in the ServerHello callback");
        _test_case.assert((server_hello_types == std::vector<uint8>{0x16}) && (server_hello_offsets.size() == 1) && (server_hello_fragment_sizes.size() == 1) &&
                              (server_hello_fragment_sizes[0] >= 4) && (0x02 == chunks[0][server_hello_offsets[0] + 5]),
                          __FUNCTION__, "emit exactly one plaintext ServerHello handshake record first");
        if (server_hello_records_valid && (server_hello_fragment_sizes.size() == 1) && (server_hello_fragment_sizes[0] >= 4)) {
            _test_case.assert(4 + test_read_u24(chunks[0], server_hello_offsets[0] + 6) == server_hello_fragment_sizes[0], __FUNCTION__,
                              "match the ServerHello handshake length to its TLS record fragment");
        }

        std::vector<uint8> flight_types;
        std::vector<size_t> flight_offsets;
        std::vector<uint16> flight_fragment_sizes;
        bool flight_records_valid = parse_record_types(chunks[1], flight_types, flight_offsets, flight_fragment_sizes);
        _test_case.assert(flight_records_valid, __FUNCTION__, "parse complete TLS record boundaries in the abbreviated server flight");

        bool expect_ticket = issue_ticket && (false == defer_ticket_until_after_server_hello);
        _test_case.assert((expect_ticket ? 1 : 0) == server.get_keyvalue().get(session_tls12_ticket_acknowledged), __FUNCTION__,
                          "record whether ServerHello acknowledged the SessionTicket extension");
        const std::vector<uint8> expected_types = expect_ticket ? std::vector<uint8>{0x16, 0x14, 0x16} : std::vector<uint8>{0x14, 0x16};
        _test_case.assert(expected_types == flight_types, __FUNCTION__, "emit optional NewSessionTicket before CCS and protected Server Finished");
        if (flight_records_valid && (flight_offsets.size() == expected_types.size()) && (flight_fragment_sizes.size() == expected_types.size())) {
            const size_t ccs_index = expect_ticket ? 1 : 0;
            const size_t finished_index = expect_ticket ? 2 : 1;
            const size_t ccs_offset = flight_offsets[ccs_index];

            _test_case.assert((1 == flight_fragment_sizes[ccs_index]) && (0x01 == chunks[1][ccs_offset + 5]), __FUNCTION__,
                              "encode ChangeCipherSpec as the single-byte value 0x01");
            _test_case.assert(0 != flight_fragment_sizes[finished_index], __FUNCTION__, "emit a non-empty protected Server Finished record");

            if (expect_ticket) {
                const size_t ticket_offset = flight_offsets[0];
                const uint16 ticket_fragment_size = flight_fragment_sizes[0];
                _test_case.assert((ticket_fragment_size >= 4) && (0x04 == chunks[1][ticket_offset + 5]), __FUNCTION__,
                                  "place NewSessionTicket as the first handshake message in the abbreviated flight");
                if (ticket_fragment_size >= 4) {
                    _test_case.assert(4 + test_read_u24(chunks[1], ticket_offset + 6) == ticket_fragment_size, __FUNCTION__,
                                      "match the NewSessionTicket handshake length to its TLS record fragment");
                }
            }
        }

        size_t callback_count = chunks.size();
        ret = composer.session_status_changed(session_status_client_finished, from_server, 0, capture);
        _test_case.test(ret, __FUNCTION__, "process Client Finished after the abbreviated server flight");
        _test_case.assert(callback_count == chunks.size(), __FUNCTION__, "do not compose a duplicate Server Finished after Client Finished in abbreviated resumption");
    };

    run_case(false, false);  // no renewal ticket configured
    run_case(true, false);   // renewal ticket acknowledged
    run_case(true, true);    // renewal ticket appears after ServerHello and was not acknowledged
}

class tls12_invalid_finished_handshake : public tls_handshake {
   public:
    explicit tls12_invalid_finished_handshake(tls_session* session) : tls_handshake(tls_handshake_type_t::finished, session) {}

   protected:
    return_t do_write_body(tls_direction_t, binary_t& bin) override {
        // Emit a structurally valid TLS 1.2 Finished body with invalid verify_data.
        bin.assign(12, 0x00);
        return errorcode_t::success;
    }
};

static void test_tls12_abbreviated_ticket_discards_renewal_on_invalid_server_finished() {
    // Scenario under test: client discards an abbreviated-handshake ticket after invalid Server Finished.
    // Action: receive a replacement ticket and then fail Server Finished authentication.
    // Expected: discard the pending renewal instead of publishing it to the client cache.

    // A replacement ticket received in the abbreviated server flight must
    // remain pending until Server Finished has been authenticated.
    _test_case.begin("TLS 1.2 abbreviated renewal is discarded after invalid Server Finished");

    auto client_store = std::make_shared<tls12_resumption_ticket_store>();
    auto server_store = std::make_shared<tls12_resumption_ticket_store>();

    tls12_resumption_ticket original_ticket;
    original_ticket.identity = binary_t{0x91, 0x92, 0x93, 0x94};
    original_ticket.master_secret = binary_t(48, 0x5a);
    original_ticket.lifetime = 3600;
    original_ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    original_ticket.version = static_cast<uint16>(tls1_2);
    original_ticket.cipher_suite = 0xc02f;
    original_ticket.extended_master_secret = true;

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    server.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(client_store);
    server.set_tls12_resumption_ticket_store(server_store);
    client.stage_tls12_resumption_ticket(original_ticket);
    server.stage_tls12_resumption_ticket(original_ticket);
    bool client_original_ticket_confirmed = client.confirm_tls12_resumption_ticket(original_ticket.identity);
    _test_case.assert(client_original_ticket_confirmed, __FUNCTION__, "activate the client's original ticket");
    bool server_original_ticket_confirmed = server.confirm_tls12_resumption_ticket(original_ticket.identity);
    _test_case.assert(server_original_ticket_confirmed, __FUNCTION__, "activate the server's original ticket");

    client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    return_t ret = client_hello->add_ciphersuite(original_ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "configure the abbreviated ClientHello");
    if (errorcode_t::success != ret) {
        client_hello->release();
        return;
    }

    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ClientHello with the confirmed ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_client_hello(&server);
    size_t client_hello_pos = 0;
    ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept the original ticket on the server");
    if (errorcode_t::success != ret) {
        return;
    }
    server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "select the original ticket for abbreviated resumption");

    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_version(tls1_2);
    ret = server_hello->set_cipher_suite(original_ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "select the original cipher suite");
    server_hello->set_random(binary_t(32, 0x6a));
    tls_record_handshake outgoing_server_hello(&server);
    outgoing_server_hello << server_hello;
    binary_t server_hello_wire;
    ret = outgoing_server_hello.write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ServerHello for abbreviated resumption");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_server_hello(&client);
    size_t server_hello_pos = 0;
    ret = incoming_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept ServerHello and confirm abbreviated resumption");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__, "recognize abbreviated resumption on the client");

    const binary_t renewal_identity{0xa1, 0xa2, 0xa3, 0xa4};
    server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, renewal_identity);
    server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 1800);
    tls_handshake_new_session_ticket outgoing_ticket(&server);
    binary_t ticket_wire;
    ret = outgoing_ticket.write(from_server, ticket_wire);
    _test_case.test(ret, __FUNCTION__, "write a replacement ticket before Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_handshake_new_session_ticket incoming_ticket(&client);
    size_t ticket_pos = 0;
    ret = incoming_ticket.read(from_server, ticket_wire.data(), ticket_wire.size(), ticket_pos);
    _test_case.test(ret, __FUNCTION__, "receive the replacement ticket in the abbreviated flight");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(renewal_identity == client.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket_pending), __FUNCTION__,
                      "keep the replacement ticket pending before Server Finished");

    tls_record_change_cipher_spec server_ccs(&server);
    binary_t server_ccs_wire;
    ret = server_ccs.write(from_server, server_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "write server CCS");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records incoming_server_ccs;
    ret = incoming_server_ccs.read(&client, from_server, server_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "read server CCS");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake outgoing_invalid_server_finished(&server);
    outgoing_invalid_server_finished << new tls12_invalid_finished_handshake(&server);
    binary_t invalid_server_finished_wire;
    ret = outgoing_invalid_server_finished.write(from_server, invalid_server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write a protected Server Finished with invalid verify_data");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records incoming_invalid_server_finished;
    ret = incoming_invalid_server_finished.read(&client, from_server, invalid_server_finished_wire);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject Server Finished whose verify_data does not authenticate the abbreviated handshake");

    const auto& client_secrets = client.get_tls_protection().get_secrets();
    const auto& pending_state = client.get_session_info(from_server).get_keyvalue();
    _test_case.assert(client_secrets.get(tls_secret_t::new_session_ticket_pending).empty(), __FUNCTION__,
                      "discard pending replacement ticket bytes after Server Finished authentication fails");
    _test_case.assert(0 == pending_state.get(session_ticket_pending), __FUNCTION__,
                      "clear the pending replacement ticket flag after Server Finished authentication fails");
    _test_case.assert(0 == pending_state.get(session_ticket_pending_lifetime), __FUNCTION__,
                      "clear pending replacement lifetime after Server Finished authentication fails");
    _test_case.assert(0 == pending_state.get(session_ticket_pending_timestamp), __FUNCTION__,
                      "clear pending replacement timestamp after Server Finished authentication fails");
    tls12_resumption_ticket unconfirmed_renewal;
    bool unconfirmed_renewal_found_at_2650 = client.find_tls12_resumption_ticket(renewal_identity, unconfirmed_renewal);
    _test_case.assert(false == unconfirmed_renewal_found_at_2650, __FUNCTION__, "do not publish the unauthenticated replacement ticket");
    tls12_resumption_ticket retained_original;
    bool retained_original_found_at_2653 = client.find_tls12_resumption_ticket(original_ticket.identity, retained_original);
    _test_case.assert(retained_original_found_at_2653, __FUNCTION__, "preserve the previously confirmed client ticket");
    if (retained_original_found_at_2653) {
        _test_case.assert(original_ticket.master_secret == retained_original.master_secret, __FUNCTION__,
                          "preserve the original Master Secret after failed replacement authentication");
    }

    size_t handshake_failure_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::handshake_failure);
    _test_case.assert(1 == handshake_failure_count, __FUNCTION__, "queue exactly one fatal handshake_failure for invalid Server Finished");
}

static void test_tls12_abbreviated_ticket_discards_renewal_on_invalid_client_finished() {
    // Scenario under test: server discards an abbreviated-handshake renewal after invalid Client Finished.
    // Action: stage a replacement ticket and then fail Client Finished authentication.
    // Expected: keep the renewal unpublished and discard it after authentication failure.

    // RFC 5077: a server-side renewal remains pending until the abbreviated
    // handshake's Client Finished has been authenticated.
    _test_case.begin("TLS 1.2 abbreviated renewal is discarded after invalid Client Finished");

    auto client_store = std::make_shared<tls12_resumption_ticket_store>();
    auto server_store = std::make_shared<tls12_resumption_ticket_store>();

    tls12_resumption_ticket original_ticket;
    original_ticket.identity = binary_t{0x91, 0x92, 0x93, 0x94};
    original_ticket.master_secret = binary_t(48, 0x5a);
    original_ticket.lifetime = 3600;
    original_ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    original_ticket.version = static_cast<uint16>(tls1_2);
    original_ticket.cipher_suite = 0xc02f;
    original_ticket.extended_master_secret = true;

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);
    client.get_tls_protection().set_tls_version(tls1_2);
    server.get_tls_protection().set_tls_version(tls1_2);
    client.set_tls12_resumption_ticket_store(client_store);
    server.set_tls12_resumption_ticket_store(server_store);
    client.stage_tls12_resumption_ticket(original_ticket);
    server.stage_tls12_resumption_ticket(original_ticket);
    bool client_original_ticket_confirmed = client.confirm_tls12_resumption_ticket(original_ticket.identity);
    _test_case.assert(client_original_ticket_confirmed, __FUNCTION__, "activate the client's original ticket");
    bool server_original_ticket_confirmed = server.confirm_tls12_resumption_ticket(original_ticket.identity);
    _test_case.assert(server_original_ticket_confirmed, __FUNCTION__, "retain the server's original confirmed ticket");

    client.get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->get_extensions().add(tls_extension_type_t::extended_master_secret, from_client, client_hello, nullptr);
    return_t ret = client_hello->add_ciphersuite(original_ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "configure the abbreviated-resumption ClientHello");
    tls_record_handshake outgoing_client_hello(&client);
    outgoing_client_hello << client_hello;
    binary_t client_hello_wire;
    ret = outgoing_client_hello.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ClientHello with the confirmed ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_client_hello(&server);
    size_t client_hello_pos = 0;
    ret = incoming_client_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept the original ticket on the server");
    if (errorcode_t::success != ret) {
        return;
    }
    server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
    _test_case.assert(1 == server.get_keyvalue().get(session_tls12_ticket_candidate), __FUNCTION__, "select the original ticket for abbreviated resumption");

    const binary_t renewal_identity{0xa1, 0xa2, 0xa3, 0xa4};
    server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, renewal_identity);
    server.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 1800);

    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_version(tls1_2);
    ret = server_hello->set_cipher_suite(original_ticket.cipher_suite);
    _test_case.test(ret, __FUNCTION__, "select the original cipher suite");
    server_hello->set_random(binary_t(32, 0x6a));
    tls_record_handshake outgoing_server_hello(&server);
    outgoing_server_hello << server_hello;
    binary_t server_hello_wire;
    ret = outgoing_server_hello.write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write ServerHello for abbreviated resumption");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake incoming_server_hello(&client);
    size_t server_hello_pos = 0;
    ret = incoming_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept ServerHello and confirm abbreviated resumption");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__, "recognize abbreviated resumption on the client");

    tls_handshake_new_session_ticket outgoing_ticket(&server);
    binary_t ticket_wire;
    ret = outgoing_ticket.write(from_server, ticket_wire);
    _test_case.test(ret, __FUNCTION__, "write a replacement ticket before Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == server.get_pending_tls12_resumption_tickets().size(), __FUNCTION__, "keep the server's replacement ticket pending");

    tls_handshake_new_session_ticket incoming_ticket(&client);
    size_t ticket_pos = 0;
    ret = incoming_ticket.read(from_server, ticket_wire.data(), ticket_wire.size(), ticket_pos);
    _test_case.test(ret, __FUNCTION__, "receive the replacement ticket in the abbreviated flight");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_change_cipher_spec server_ccs(&server);
    binary_t server_ccs_wire;
    ret = server_ccs.write(from_server, server_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "write server CCS");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records incoming_server_ccs;
    ret = incoming_server_ccs.read(&client, from_server, server_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "read server CCS");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_handshake outgoing_server_finished(&server);
    outgoing_server_finished << new tls_handshake_finished(&server);
    binary_t server_finished_wire;
    ret = outgoing_server_finished.write(from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Server Finished before Client Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records incoming_server_finished;
    ret = incoming_server_finished.read(&client, from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "authenticate Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == server.get_pending_tls12_resumption_tickets().size(), __FUNCTION__, "keep the server's replacement pending after its own Finished");
    tls12_resumption_ticket unconfirmed_renewal;
    bool unconfirmed_renewal_found_at_2793 = server.find_tls12_resumption_ticket(renewal_identity, unconfirmed_renewal);
    _test_case.assert(false == unconfirmed_renewal_found_at_2793, __FUNCTION__, "do not expose the replacement before Client Finished authentication");

    tls_record_change_cipher_spec client_ccs(&client);
    binary_t client_ccs_wire;
    ret = client_ccs.write(from_client, client_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "write client CCS");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records incoming_client_ccs;
    ret = incoming_client_ccs.read(&server, from_client, client_ccs_wire);
    _test_case.test(ret, __FUNCTION__, "read client CCS");
    if (errorcode_t::success != ret) {
        return;
    }

    // The custom message preserves the Finished handshake framing and record
    // protection, but deliberately sends an invalid 12-byte verify_data value.
    tls_record_handshake outgoing_invalid_client_finished(&client);
    outgoing_invalid_client_finished << new tls12_invalid_finished_handshake(&client);
    binary_t invalid_client_finished_wire;
    ret = outgoing_invalid_client_finished.write(from_client, invalid_client_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write a protected Client Finished with invalid verify_data");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records incoming_invalid_client_finished;
    ret = incoming_invalid_client_finished.read(&server, from_client, invalid_client_finished_wire);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject Client Finished whose verify_data does not authenticate the abbreviated handshake");

    _test_case.assert(server.get_pending_tls12_resumption_tickets().empty(), __FUNCTION__,
                      "discard the unconfirmed renewal immediately after Client Finished authentication fails");
    bool unconfirmed_renewal_found_at_2827 = server.find_tls12_resumption_ticket(renewal_identity, unconfirmed_renewal);
    _test_case.assert(false == unconfirmed_renewal_found_at_2827, __FUNCTION__, "keep the failed renewal out of the active server ticket store");
    tls12_resumption_ticket retained_original;
    bool retained_original_found_at_2830 = server.find_tls12_resumption_ticket(original_ticket.identity, retained_original);
    _test_case.assert(retained_original_found_at_2830, __FUNCTION__, "preserve the previously confirmed ticket after failed renewal");
    if (retained_original_found_at_2830) {
        _test_case.assert(original_ticket.master_secret == retained_original.master_secret, __FUNCTION__,
                          "preserve the original ticket's master secret after failed renewal");
    }
    _test_case.assert(0 == server.get_session_status(), __FUNCTION__, "reset handshake status after invalid Client Finished");

    size_t handshake_failure_count = test_count_fatal_alert(server, from_client, tls_alertdesc_t::handshake_failure);
    _test_case.assert(1 == handshake_failure_count, __FUNCTION__, "queue exactly one fatal handshake_failure for invalid Client Finished");
}

void testcase_gpt_session_ticket() {
    test_tls12_new_session_ticket_wire_format();
    test_tls12_new_session_ticket_requires_client_finished();
    test_tls12_server_ticket_confirmation_store();
    test_tls12_session_ticket_extension_wire_behavior();
    test_tls12_session_ticket_handshake_negotiation();
    test_tls12_client_does_not_offer_non_ems_ticket();
    test_tls12_client_suppresses_ticket_identity_in_mixed_version_offer();
    test_tls12_ticket_context_binding();
    test_tls12_server_enforces_ticket_ems_transitions();
    test_tls12_client_rejects_server_ems_mismatch();
    test_tls12_session_id_length_bounds();
    test_tls12_abbreviated_ticket_handshake();
    test_tls12_composer_abbreviated_handshake_records();
    test_tls12_abbreviated_ticket_discards_renewal_on_invalid_server_finished();
    test_tls12_abbreviated_ticket_discards_renewal_on_invalid_client_finished();
    test_tls13_new_session_ticket_rejects_malformed_early_data_length();
    test_tls13_new_session_ticket_respects_advertised_psk_modes();
    test_tls13_new_session_ticket_lifetime();
    test_tls13_new_session_ticket_early_data_allowance();
    test_tls13_multiple_new_session_tickets_are_cached_independently();
    test_tls13_new_session_ticket_nonce_uniqueness();
}
