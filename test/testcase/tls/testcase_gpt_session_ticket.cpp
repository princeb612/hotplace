/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_session_ticket.cpp
 * @author GPT
 * @desc   TLS 1.3 NewSessionTicket lifecycle tests.
 */

#include <algorithm>
#include <chrono>

#include "testcase_gpt_common.hpp"

static void test_tls13_new_session_ticket_lifetime() {
    // Scenario under test: TLS 1.3 NewSessionTicket lifetime limit.
    // Action: read NewSessionTicket lifetime boundary.
    // Expected: cap cached ticket lifetime at seven days.
    _test_case.begin("TLS 1.3 NewSessionTicket lifetime limit");

    const uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
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
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x22));
        if (0 != lifetime) {
            protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        }

        tls_handshake_new_session_ticket ticket(&session);
        size_t pos = 0;
        return_t ret = ticket.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read NewSessionTicket lifetime boundary");
        if (errorcode_t::success != ret) {
            continue;
        }

        uint32 expected_lifetime = (lifetime > max_ticket_lifetime) ? max_ticket_lifetime : lifetime;
        uint32 stored_lifetime = t_narrow_cast(session.get_session_info(from_server).get_keyvalue().get(session_ticket_lifetime));
        _test_case.assert(expected_lifetime == stored_lifetime, __FUNCTION__, "cap cached ticket lifetime at seven days");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume complete NewSessionTicket message");

        const binary_t& stored_ticket = session.get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket);
        if (0 == lifetime) {
            _test_case.assert(stored_ticket.empty(), __FUNCTION__, "discard a zero-lifetime ticket immediately");
            _test_case.assert(binary_t(32, 0x22) == session.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                              "leave the active early secret untouched when discarding a zero-lifetime ticket");
            const auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
            _test_case.assert(0 == ticket_kv.get(session_ticket_lifetime), __FUNCTION__, "clear zero-lifetime ticket lifetime metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_age_add), __FUNCTION__, "clear zero-lifetime ticket age_add metadata");
            _test_case.assert(0 == ticket_kv.get(session_ticket_timestamp), __FUNCTION__, "clear zero-lifetime ticket issuance timestamp");
        } else {
            _test_case.assert(binary_t{0xaa} == stored_ticket, __FUNCTION__, "retain a nonzero-lifetime ticket");
        }
    }

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
        empty_identity_protection.set_tls_version(tls_13);
        empty_identity_protection.set_cipher_suite(0x1301);
        empty_identity_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        auto& empty_identity_kv = empty_identity_session.get_session_info(from_server).get_keyvalue();
        empty_identity_kv.set(session_ticket_lifetime, 1234);
        empty_identity_kv.set(session_ticket_age_add, 0x11223344);
        empty_identity_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket empty_identity_message(&empty_identity_session);
        size_t empty_identity_pos = 0;
        return_t empty_identity_ret = empty_identity_message.read(from_server, empty_identity_ticket.data(), empty_identity_ticket.size(), empty_identity_pos);
        _test_case.assert(errorcode_t::success != empty_identity_ret, __FUNCTION__, "reject a NewSessionTicket with an empty ticket identity");
        _test_case.assert(empty_identity_session.get_resumption_tickets().empty(), __FUNCTION__, "do not cache an empty ticket identity");
        _test_case.assert(empty_identity_protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                          "do not publish an empty ticket identity as the legacy ticket");
        _test_case.assert(1234 == empty_identity_kv.get(session_ticket_lifetime), __FUNCTION__, "preserve prior lifetime metadata for an invalid empty identity");
        _test_case.assert(0x11223344 == empty_identity_kv.get(session_ticket_age_add), __FUNCTION__, "preserve prior age_add metadata for an invalid empty identity");
        _test_case.assert(uint64(0x0102030405060708ULL) == empty_identity_kv.get(session_ticket_timestamp), __FUNCTION__,
                          "preserve prior timestamp metadata for an invalid empty identity");
    }

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
        missing_secret_protection.set_tls_version(tls_13);
        missing_secret_protection.set_cipher_suite(0x1301);
        auto& missing_secret_kv = missing_secret_session.get_session_info(from_server).get_keyvalue();
        missing_secret_kv.set(session_ticket_lifetime, 1234);
        missing_secret_kv.set(session_ticket_age_add, 0x11223344);
        missing_secret_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket missing_secret_message(&missing_secret_session);
        size_t missing_secret_pos = 0;
        return_t missing_secret_ret =
            missing_secret_message.read(from_server, valid_identity_missing_secret.data(), valid_identity_missing_secret.size(), missing_secret_pos);
        _test_case.assert(errorcode_t::success != missing_secret_ret, __FUNCTION__, "reject a NewSessionTicket when its resumption master secret is unavailable");
        _test_case.assert(missing_secret_session.get_resumption_tickets().empty(), __FUNCTION__, "do not cache a ticket whose PSK could not be derived");
        _test_case.assert(missing_secret_protection.get_secrets().get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                          "do not publish a ticket identity whose PSK could not be derived");
        _test_case.assert(1234 == missing_secret_kv.get(session_ticket_lifetime), __FUNCTION__, "preserve prior lifetime metadata when PSK derivation fails");
        _test_case.assert(0x11223344 == missing_secret_kv.get(session_ticket_age_add), __FUNCTION__, "preserve prior age_add metadata when PSK derivation fails");
        _test_case.assert(uint64(0x0102030405060708ULL) == missing_secret_kv.get(session_ticket_timestamp), __FUNCTION__,
                          "preserve prior timestamp metadata when PSK derivation fails");
    }

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
        malformed_protection.set_tls_version(tls_13);
        malformed_protection.set_cipher_suite(0x1301);
        malformed_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
        auto& malformed_ticket_kv = malformed_session.get_session_info(from_server).get_keyvalue();
        malformed_ticket_kv.set(session_ticket_lifetime, 1234);
        malformed_ticket_kv.set(session_ticket_age_add, 0x11223344);
        malformed_ticket_kv.set(session_ticket_timestamp, uint64(0x0102030405060708ULL));

        tls_handshake_new_session_ticket malformed_ticket(&malformed_session);
        size_t malformed_pos = 0;
        return_t malformed_ret = malformed_ticket.read(from_server, malformed_ticket_extension.data(), malformed_ticket_extension.size(), malformed_pos);
        _test_case.assert(errorcode_t::success != malformed_ret, __FUNCTION__, "reject a NewSessionTicket whose early_data extension body is malformed");
        _test_case.assert(malformed_session.get_resumption_tickets().empty(), __FUNCTION__, "do not cache a ticket after its extension list fails to parse");
        _test_case.assert(1234 == malformed_ticket_kv.get(session_ticket_lifetime), __FUNCTION__, "preserve prior ticket lifetime metadata when extension parsing fails");
        _test_case.assert(0x11223344 == malformed_ticket_kv.get(session_ticket_age_add), __FUNCTION__,
                          "preserve prior ticket age_add metadata when extension parsing fails");
        _test_case.assert(uint64(0x0102030405060708ULL) == malformed_ticket_kv.get(session_ticket_timestamp), __FUNCTION__,
                          "preserve prior ticket timestamp when extension parsing fails");
    }

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
        early_data_protection.set_tls_version(tls_13);
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
        _test_case.test(first_ret, __FUNCTION__, "parse the first ticket's early-data allowance");
        _test_case.test(second_ret, __FUNCTION__, "parse the second ticket's early-data allowance");
        _test_case.assert(first_wire.size() == first_pos, __FUNCTION__, "consume the complete first early-data ticket");
        _test_case.assert(second_wire.size() == second_pos, __FUNCTION__, "consume the complete second early-data ticket");

        tls_resumption_ticket cached_first;
        tls_resumption_ticket cached_second;
        bool found_first = early_data_session.find_resumption_ticket(binary_t{0xa1}, cached_first);
        bool found_second = early_data_session.find_resumption_ticket(binary_t{0xa2}, cached_second);
        _test_case.assert(found_first && found_second, __FUNCTION__, "cache both tickets with their independent identities");
        if (found_first && found_second) {
            _test_case.assert(4096 == cached_first.max_early_data_size, __FUNCTION__, "retain the first ticket's max_early_data_size");
            _test_case.assert(8192 == cached_second.max_early_data_size, __FUNCTION__, "retain the second ticket's max_early_data_size");
        }
    }

    // The fixed and length-prefixed fields of NewSessionTicket must all be
    // present; a truncated body must not be treated as a partially decoded ticket.
    {
        // The body ends immediately after ticket_age_add, before ticket_nonce_len.
        binary_t truncated_ticket = {0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02};
        tls_session truncated_session;
        truncated_session.set_type(session_type_t::tls);
        auto& truncated_protection = truncated_session.get_tls_protection();
        truncated_protection.set_tls_version(tls_13);
        truncated_protection.set_cipher_suite(0x1301);

        tls_handshake_new_session_ticket truncated_message(&truncated_session);
        size_t truncated_pos = 0;
        return_t truncated_ret = truncated_message.read(from_server, truncated_ticket.data(), truncated_ticket.size(), truncated_pos);
        _test_case.assert(errorcode_t::success != truncated_ret, __FUNCTION__, "reject a truncated NewSessionTicket body");
        _test_case.assert(truncated_session.get_resumption_tickets().empty(), __FUNCTION__, "do not cache a partially decoded NewSessionTicket");
    }

    // Verify the server's generated NewSessionTicket on the serialized
    // handshake wire, not only the client-side lifetime handling.
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

        tls_handshake_new_session_ticket ticket(&session);
        binary_t wire;
        return_t ret = ticket.write(from_server, wire);
        _test_case.test(ret, __FUNCTION__, "serialize a server-issued TLS 1.3 NewSessionTicket");
        if (errorcode_t::success == ret) {
            _test_case.assert(wire.size() >= 8, __FUNCTION__, "emit a complete NewSessionTicket handshake header and lifetime");
            if (wire.size() >= 8) {
                uint32 body_size = (static_cast<uint32>(wire[1]) << 16) | (static_cast<uint32>(wire[2]) << 8) | wire[3];
                uint32 wire_lifetime = (static_cast<uint32>(wire[4]) << 24) | (static_cast<uint32>(wire[5]) << 16) | (static_cast<uint32>(wire[6]) << 8) | wire[7];
                _test_case.assert(static_cast<uint8>(tls_handshake_type_t::new_session_ticket) == wire[0], __FUNCTION__,
                                  "serialize the NewSessionTicket handshake message type");
                _test_case.assert(wire.size() == 4 + body_size, __FUNCTION__, "handshake length matches the serialized ticket body");
                _test_case.assert(wire_lifetime <= max_ticket_lifetime, __FUNCTION__, "server does not advertise a ticket lifetime greater than seven days");
                uint32 stored_lifetime = t_narrow_cast(session.get_session_info(from_server).get_keyvalue().get(session_ticket_lifetime));
                _test_case.assert(wire_lifetime == stored_lifetime, __FUNCTION__, "store the same ticket lifetime that was serialized on the wire");
            }
        }
    }
}

static void test_tls13_multiple_new_session_tickets_are_cached_independently() {
    // Scenario under test: TLS 1.3 client caches multiple NewSessionTicket messages independently.
    // Action: receive the first NewSessionTicket.
    // Expected: consume the first complete NewSessionTicket.
    _test_case.begin("TLS 1.3 client caches multiple NewSessionTicket messages independently");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
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
    _test_case.assert(session.find_resumption_ticket(identity1, cached1), __FUNCTION__, "find the first ticket by its identity");
    _test_case.assert(session.find_resumption_ticket(identity2, cached2), __FUNCTION__, "find the second ticket by its identity");
    if (session.find_resumption_ticket(identity1, cached1) && session.find_resumption_ticket(identity2, cached2)) {
        _test_case.assert(nonce1 == cached1.nonce, __FUNCTION__, "retain the first ticket nonce");
        _test_case.assert(nonce2 == cached2.nonce, __FUNCTION__, "retain the second ticket nonce");
        _test_case.assert(cached1.psk != cached2.psk, __FUNCTION__, "retain independently derived PSKs for the two ticket nonces");
        _test_case.assert(3600 == cached1.lifetime && 1800 == cached2.lifetime, __FUNCTION__, "retain each ticket's own lifetime");
        const binary_t expected_server_name = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
        _test_case.assert(expected_server_name == cached1.server_name && expected_server_name == cached2.server_name, __FUNCTION__,
                          "associate each received NewSessionTicket with the normalized ClientHello SNI");
        _test_case.assert(expected_alpn == cached1.alpn && expected_alpn == cached2.alpn, __FUNCTION__,
                          "associate each received NewSessionTicket with the negotiated ALPN protocol");
        _test_case.assert(static_cast<uint16>(tls_13) == cached1.version && static_cast<uint16>(tls_13) == cached2.version, __FUNCTION__,
                          "retain the TLS version associated with each received ticket");
        _test_case.assert(0x10203040 == cached1.age_add && 0x50607080 == cached2.age_add, __FUNCTION__, "retain each ticket's own age_add");
    }
    _test_case.assert(identity2 == protection.get_secrets().get(tls_secret_t::new_session_ticket), __FUNCTION__,
                      "keep the legacy singleton view pointed at the most recently received ticket");
}

static void test_tls13_new_session_ticket_nonce_uniqueness() {
    // Scenario under test: TLS 1.3 NewSessionTicket nonce uniqueness per connection.
    // Action: serialize another NewSessionTicket on the same connection.
    // Expected: emit a complete ticket nonce field.
    _test_case.begin("TLS 1.3 NewSessionTicket nonce uniqueness per connection");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
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
        failed_protection.set_tls_version(tls_13);
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
            _test_case.assert(static_cast<uint16>(tls_13) == issued_tickets[i].version, __FUNCTION__, "bind each issued ticket to TLS 1.3");
            _test_case.assert(expected_issued_alpn == issued_tickets[i].alpn, __FUNCTION__, "bind each issued ticket to the negotiated ALPN protocol");
            for (size_t j = i + 1; j < issued_tickets.size(); ++j) {
                _test_case.assert(issued_tickets[i].identity != issued_tickets[j].identity, __FUNCTION__, "issue independently addressable ticket identities");
                _test_case.assert(issued_tickets[i].psk != issued_tickets[j].psk, __FUNCTION__, "derive a distinct PSK for each issued ticket nonce");
            }
        }
    }
}

static void test_tls13_new_session_ticket_respects_advertised_psk_modes() {
    // Scenario under test: TLS 1.3 NewSessionTicket respects advertised PSK key-exchange modes.
    // Expected: decline ticket issuance when no advertised PSK mode is supported.
    _test_case.begin("TLS 1.3 NewSessionTicket respects advertised PSK key-exchange modes");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls_13);
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

void testcase_gpt_session_ticket() {
    test_tls13_new_session_ticket_respects_advertised_psk_modes();
    test_tls13_new_session_ticket_lifetime();
    test_tls13_multiple_new_session_tickets_are_cached_independently();
    test_tls13_new_session_ticket_nonce_uniqueness();
}
