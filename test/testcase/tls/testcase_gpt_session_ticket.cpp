/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_session_ticket.cpp
 * @author GPT
 * @desc
 */

#include <algorithm>
#include <chrono>

#include "testcase_gpt_common.hpp"

static void test_tls13_server_rejects_early_data_for_nonzero_selected_identity() {
    _test_case.begin("TLS 1.3 server early-data acceptance requires selected_identity zero");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);
    protection.reset_transcript_hash(&session);
    session.get_keyvalue().set(session_server_psk_selected_identity, 1);

    // EncryptedExtensions containing an empty early_data extension.
    const binary_t wire = {0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
    tls_handshake_encrypted_extensions encrypted_extensions(&session);
    size_t pos = 0;
    return_t ret = encrypted_extensions.read(from_server, wire.data(), wire.size(), pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject server early-data acceptance when selected_identity is not zero");
    _test_case.assert(wire.size() == pos, __FUNCTION__, "parse the complete EncryptedExtensions before rejecting the early-data PSK rule");

    size_t illegal_parameter_count = 0;
    session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++illegal_parameter_count;
        }
    });
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue one fatal illegal_parameter alert");

    tls_session unsolicited_session;
    unsolicited_session.set_type(session_type_t::tls);
    auto& unsolicited_protection = unsolicited_session.get_tls_protection();
    unsolicited_protection.set_tls_version(tls_13);
    unsolicited_protection.set_cipher_suite(0x1301);
    unsolicited_protection.set_flow(tls_flow_t::zero_rtt);
    unsolicited_protection.reset_transcript_hash(&unsolicited_session);
    unsolicited_session.get_keyvalue().set(session_server_psk_selected_identity, 0);
    tls_handshake_encrypted_extensions unsolicited_encrypted_extensions(&unsolicited_session);
    size_t unsolicited_pos = 0;
    ret = unsolicited_encrypted_extensions.read(from_server, wire.data(), wire.size(), unsolicited_pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject early-data acceptance when ClientHello did not offer early_data");
}

static void test_tls13_server_requires_early_data_ticket_permission() {
    _test_case.begin("TLS 1.3 server advertises early-data acceptance only for an eligible ticket");

    auto verify_server_acceptance = [](uint16 selected_identity, uint64 early_data_limit, uint64 early_data_offered, uint16 negotiated_suite, uint16 ticket_suite,
                                       bool expect_success, const char* description) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(negotiated_suite);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.reset_transcript_hash(&session);
        session.get_keyvalue().set(session_server_psk_selected_identity, selected_identity);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, ticket_suite);
        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, early_data_offered);
        early_state.set(session_early_data_limit, early_data_limit);

        tls_handshake_encrypted_extensions encrypted_extensions(&session);
        encrypted_extensions.get_extensions().add(new tls_extension_early_data(&encrypted_extensions));
        binary_t wire;
        return_t ret = encrypted_extensions.write(from_server, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, description);
        bool early_data_emitted = (wire.size() >= 10);
        _test_case.assert(expect_success == early_data_emitted, __FUNCTION__, "emit early_data only when the selected ticket and ClientHello permit 0-RTT");
    };

    verify_server_acceptance(0, 4096, 1, 0x1301, 0x1301, true, "accept early data for the first offered PSK with a matching suite and nonzero ticket allowance");
    verify_server_acceptance(0, 0, 1, 0x1301, 0x1301, false, "do not accept early data when the selected ticket has no allowance");
    verify_server_acceptance(0, 4096, 0, 0x1301, 0x1301, false, "do not accept early data when ClientHello omitted the early_data extension");
    verify_server_acceptance(1, 4096, 1, 0x1301, 0x1301, false, "do not accept early data when the selected PSK identity is not zero");
    verify_server_acceptance(0, 4096, 1, 0x1303, 0x1301, false, "do not accept early data when the negotiated cipher suite differs from the ticket suite");
}

static void test_tls13_new_session_ticket_lifetime() {
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
    _test_case.begin("TLS 1.3 client caches multiple NewSessionTicket messages independently");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

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
        _test_case.assert(0x10203040 == cached1.age_add && 0x50607080 == cached2.age_add, __FUNCTION__, "retain each ticket's own age_add");
    }
    _test_case.assert(identity2 == protection.get_secrets().get(tls_secret_t::new_session_ticket), __FUNCTION__,
                      "keep the legacy singleton view pointed at the most recently received ticket");
}

static void test_tls13_new_session_ticket_nonce_uniqueness() {
    _test_case.begin("TLS 1.3 NewSessionTicket nonce uniqueness per connection");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

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
            for (size_t j = i + 1; j < issued_tickets.size(); ++j) {
                _test_case.assert(issued_tickets[i].identity != issued_tickets[j].identity, __FUNCTION__, "issue independently addressable ticket identities");
                _test_case.assert(issued_tickets[i].psk != issued_tickets[j].psk, __FUNCTION__, "derive a distinct PSK for each issued ticket nonce");
            }
        }
    }
}

static void test_tls13_server_client_ticket_psk_roundtrip() {
    _test_case.begin("TLS 1.3 server-issued tickets derive identical per-ticket PSKs on the client");

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls_13);
    server_protection.set_cipher_suite(0x1301);
    server_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t server_active_early_secret(32, 0xa5);
    server_protection.get_secrets().assign(tls_secret_t::resumption_early, server_active_early_secret);

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls_13);
    client_protection.set_cipher_suite(0x1301);
    client_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t client_active_early_secret(32, 0x5a);
    client_protection.get_secrets().assign(tls_secret_t::resumption_early, client_active_early_secret);

    for (size_t i = 0; i < 2; ++i) {
        tls_handshake_new_session_ticket issued(&server);
        binary_t wire;
        return_t ret = issued.write(from_server, wire);
        _test_case.test(ret, __FUNCTION__, "server issues another NewSessionTicket");
        if (errorcode_t::success != ret) {
            continue;
        }

        tls_handshake_new_session_ticket received(&client);
        size_t pos = 0;
        ret = received.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "client receives the server-issued NewSessionTicket");
        if (errorcode_t::success != ret) {
            continue;
        }
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete server-issued NewSessionTicket");
    }

    auto server_tickets = server.get_resumption_tickets();
    auto client_tickets = client.get_resumption_tickets();
    _test_case.assert(2 == server_tickets.size(), __FUNCTION__, "server retains both independently issued tickets");
    _test_case.assert(2 == client_tickets.size(), __FUNCTION__, "client caches both received tickets independently");
    _test_case.assert(server_active_early_secret == server_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                      "issuing tickets does not overwrite the server's active early secret");
    _test_case.assert(client_active_early_secret == client_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                      "receiving tickets does not overwrite the client's active early secret");

    for (const auto& server_ticket : server_tickets) {
        tls_resumption_ticket client_ticket;
        bool found = client.find_resumption_ticket(server_ticket.identity, client_ticket);
        _test_case.assert(found, __FUNCTION__, "client retains the identity issued by the server");
        if (found) {
            _test_case.assert(server_ticket.nonce == client_ticket.nonce, __FUNCTION__, "server and client associate the same nonce with a ticket");
            _test_case.assert(server_ticket.psk == client_ticket.psk, __FUNCTION__, "server and client derive exactly the same RFC 8446 resumption PSK");
            _test_case.assert(server_ticket.psk.size() == 32, __FUNCTION__, "TLS_AES_128_GCM_SHA256 ticket PSK has a 32-byte hash length");
        }
    }

    // Model a new connection on both endpoints. The client restores its
    // cached tickets, while the server restores its independently retained
    // ticket records into a fresh tls_session before validating the binder.
    tls_session resumed_client;
    resumed_client.set_type(session_type_t::tls);
    auto& resumed_client_protection = resumed_client.get_tls_protection();
    resumed_client_protection.set_tls_version(tls_13);
    resumed_client_protection.set_cipher_suite(0x1301);
    resumed_client.get_keyvalue().set(session_tls_version, tls_13);
    resumed_client.update_session_status(session_status_server_finished);
    resumed_client.update_session_status(session_status_client_finished);
    resumed_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    resumed_client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    for (const auto& ticket : client_tickets) {
        resumed_client.store_resumption_ticket(ticket);
    }

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "prepare the empty transcript hash for a fresh-connection PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    resumed_client_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto resumed_client_hello = new tls_handshake_client_hello(&resumed_client);
    resumed_client_hello->add_ciphersuite(0x1301);
    auto resumed_supported_versions = new tls_extension_client_supported_versions(resumed_client_hello);
    resumed_supported_versions->add(tls_13);
    resumed_client_hello->get_extensions().add(resumed_supported_versions);
    auto resumed_psk_modes = new tls_extension_psk_key_exchange_modes(resumed_client_hello);
    resumed_psk_modes->add(1);  // psk_dhe_ke
    resumed_client_hello->get_extensions().add(resumed_psk_modes);
    resumed_client_hello->get_extensions().add(new tls_extension_client_psk(resumed_client_hello));

    tls_record_handshake resumed_client_hello_record(&resumed_client);
    resumed_client_hello_record << resumed_client_hello;
    binary_t resumed_client_hello_wire;
    ret = resumed_client_hello_record.write(from_client, resumed_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a PSK ClientHello from a fresh client connection using restored ticket records");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session resumed_server;
    resumed_server.set_type(session_type_t::tls);
    auto& resumed_server_protection = resumed_server.get_tls_protection();
    resumed_server_protection.set_tls_version(tls_13);
    resumed_server_protection.set_cipher_suite(0x1301);
    resumed_server_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    resumed_server.get_keyvalue().set(session_tls_version, tls_13);
    resumed_server.update_session_status(session_status_server_finished);
    resumed_server.update_session_status(session_status_client_finished);
    resumed_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    resumed_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    for (const auto& ticket : server_tickets) {
        resumed_server.store_resumption_ticket(ticket);
    }

    tls_records resumed_server_records;
    ret = resumed_server_records.read(&resumed_server, from_client, resumed_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "validate a fresh-connection ClientHello binder using restored server ticket records");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::zero_rtt == resumed_server_protection.get_flow(), __FUNCTION__,
                          "resume on a new server connection without relying on the issuing tls_session");
        _test_case.assert(0 == resumed_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "select the first restored ticket identity");
        _test_case.assert(0x1301 == resumed_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "retain the original cipher suite metadata from the restored ticket");
        _test_case.assert(resumed_server.get_resumption_tickets().size() == server_tickets.size(), __FUNCTION__,
                          "keep the restored per-ticket server records available on the new connection");
        const auto& selected_ticket = server_tickets.front();
        binary_t expected_early_secret;
        ret = resumed_server_protection.calc_resumption_early_secret(selected_ticket.psk, expected_early_secret);
        _test_case.test(ret, __FUNCTION__, "derive the expected early secret from the selected ticket PSK");
        if (errorcode_t::success == ret) {
            _test_case.assert(expected_early_secret == resumed_server_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                              "derive the active early secret from the selected ticket rather than stale session state");
        }
    }

    // Exercise the second cached ticket as selected_identity=1. The server
    // restores only that ticket, so the first offered identity is unknown.
    if ((server_tickets.size() < 2) || (client_tickets.size() < 2)) {
        _test_case.assert(false, __FUNCTION__, "prepare two independently retained tickets for second-identity resumption");
        return;
    }

    tls_session resumed_client_second;
    resumed_client_second.set_type(session_type_t::tls);
    auto& resumed_client_second_protection = resumed_client_second.get_tls_protection();
    resumed_client_second_protection.set_tls_version(tls_13);
    resumed_client_second_protection.set_cipher_suite(0x1301);
    resumed_client_second.get_keyvalue().set(session_tls_version, tls_13);
    resumed_client_second.update_session_status(session_status_server_finished);
    resumed_client_second.update_session_status(session_status_client_finished);
    resumed_client_second.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    resumed_client_second.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    for (const auto& ticket : client_tickets) {
        resumed_client_second.store_resumption_ticket(ticket);
    }
    resumed_client_second_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto resumed_client_hello_second = new tls_handshake_client_hello(&resumed_client_second);
    resumed_client_hello_second->add_ciphersuite(0x1301);
    auto resumed_supported_versions_second = new tls_extension_client_supported_versions(resumed_client_hello_second);
    resumed_supported_versions_second->add(tls_13);
    resumed_client_hello_second->get_extensions().add(resumed_supported_versions_second);
    auto resumed_psk_modes_second = new tls_extension_psk_key_exchange_modes(resumed_client_hello_second);
    resumed_psk_modes_second->add(1);  // psk_dhe_ke
    resumed_client_hello_second->get_extensions().add(resumed_psk_modes_second);
    resumed_client_hello_second->get_extensions().add(new tls_extension_client_psk(resumed_client_hello_second));

    tls_record_handshake resumed_client_hello_record_second(&resumed_client_second);
    resumed_client_hello_record_second << resumed_client_hello_second;
    binary_t resumed_client_hello_wire_second;
    ret = resumed_client_hello_record_second.write(from_client, resumed_client_hello_wire_second);
    _test_case.test(ret, __FUNCTION__, "serialize a ClientHello offering both restored tickets in their cached order");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session resumed_server_second;
    resumed_server_second.set_type(session_type_t::tls);
    auto& resumed_server_second_protection = resumed_server_second.get_tls_protection();
    resumed_server_second_protection.set_tls_version(tls_13);
    resumed_server_second_protection.set_cipher_suite(0x1301);
    resumed_server_second_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    resumed_server_second.get_keyvalue().set(session_tls_version, tls_13);
    resumed_server_second.update_session_status(session_status_server_finished);
    resumed_server_second.update_session_status(session_status_client_finished);
    resumed_server_second.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    resumed_server_second.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    resumed_server_second.store_resumption_ticket(server_tickets[1]);

    tls_records resumed_server_records_second;
    ret = resumed_server_records_second.read(&resumed_server_second, from_client, resumed_client_hello_wire_second);
    _test_case.test(ret, __FUNCTION__, "validate the second offered ticket binder using its independently restored server record");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::zero_rtt == resumed_server_second_protection.get_flow(), __FUNCTION__,
                          "resume with the second cached ticket on a fresh server connection");
        _test_case.assert(1 == resumed_server_second.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "select the second offered ticket identity");
        _test_case.assert(0x1301 == resumed_server_second.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "retain the second ticket's original cipher suite metadata");
        binary_t expected_second_early_secret;
        ret = resumed_server_second_protection.calc_resumption_early_secret(server_tickets[1].psk, expected_second_early_secret);
        _test_case.test(ret, __FUNCTION__, "derive the expected early secret from the second ticket PSK");
        if (errorcode_t::success == ret) {
            _test_case.assert(expected_second_early_secret == resumed_server_second_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                              "derive the active early secret from the second selected ticket");
        }
    }

    // A zero-lifetime ticket with a different identity is discarded, but
    // must not clear the compatibility metadata for the latest usable ticket.
    tls_handshake_new_session_ticket zero_lifetime_issued(&server);
    binary_t zero_lifetime_wire;
    ret = zero_lifetime_issued.write(from_server, zero_lifetime_wire);
    _test_case.test(ret, __FUNCTION__, "issue a ticket that will be changed to zero lifetime for the discard-path test");
    if (errorcode_t::success == ret && zero_lifetime_wire.size() >= 8) {
        zero_lifetime_wire[4] = 0;
        zero_lifetime_wire[5] = 0;
        zero_lifetime_wire[6] = 0;
        zero_lifetime_wire[7] = 0;

        const auto latest_ticket_before_discard = client_tickets.back();
        auto& client_ticket_kv = client.get_session_info(from_server).get_keyvalue();
        tls_handshake_new_session_ticket zero_lifetime_received(&client);
        size_t zero_lifetime_pos = 0;
        ret = zero_lifetime_received.read(from_server, zero_lifetime_wire.data(), zero_lifetime_wire.size(), zero_lifetime_pos);
        _test_case.test(ret, __FUNCTION__, "discard a zero-lifetime ticket without disturbing other cached tickets");
        if (errorcode_t::success == ret) {
            _test_case.assert(2 == client.get_resumption_tickets().size(), __FUNCTION__, "do not retain the zero-lifetime ticket or remove unrelated cached tickets");
            _test_case.assert(latest_ticket_before_discard.identity == client_protection.get_secrets().get(tls_secret_t::new_session_ticket), __FUNCTION__,
                              "preserve the latest usable ticket identity when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.lifetime == client_ticket_kv.get(session_ticket_lifetime), __FUNCTION__,
                              "preserve the latest usable ticket lifetime when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.age_add == client_ticket_kv.get(session_ticket_age_add), __FUNCTION__,
                              "preserve the latest usable ticket age_add when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.timestamp == client_ticket_kv.get(session_ticket_timestamp), __FUNCTION__,
                              "preserve the latest usable ticket timestamp when discarding an unrelated ticket");
        }
    } else if (errorcode_t::success == ret) {
        _test_case.assert(false, __FUNCTION__, "serialize a complete ticket before testing zero-lifetime discard");
    }
}

static void test_tls13_ticket_nonce_resumption_psk() {
    _test_case.begin("TLS 1.3 ticket nonce resumption PSK derivation");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));

    const binary_t nonce1 = {0x00, 0x01};
    const binary_t nonce2 = {0x00, 0x02};

    binary_t psk1;
    return_t ret = protection.calc_resumption_ticket_psk(nonce1, psk1);
    _test_case.test(ret, __FUNCTION__, "derive ticket PSK using first ticket nonce");
    const binary_t expected_psk1 = base16_decode_rfc("621010f65bfa3fbdf588e7062df98031447a0a60a412282936b041a085819f32");
    _test_case.assert(expected_psk1 == psk1, __FUNCTION__, "match the RFC 8446 HKDF-Expand-Label ticket PSK known-answer value");

    binary_t derived_early_secret;
    ret = protection.calc_resumption_early_secret(psk1, derived_early_secret);
    _test_case.test(ret, __FUNCTION__, "extract the early secret from the derived ticket PSK");
    ret = protection.calc_resumption_psk(nonce1);
    _test_case.test(ret, __FUNCTION__, "store the early secret derived from the ticket PSK");
    const binary_t stored_early_secret = protection.get_secrets().get(tls_secret_t::resumption_early);
    _test_case.assert(derived_early_secret == stored_early_secret, __FUNCTION__, "store the HKDF-Extract result for the ticket PSK");

    // RFC 8448 Section 4 supplies the PSK as the HKDF-Extract IKM.
    // Its early-secret vector is independent of the synthetic resumption_master_secret above.
    const binary_t rfc8448_psk = base16_decode_rfc("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    binary_t rfc8448_early_secret;
    ret = protection.calc_resumption_early_secret(rfc8448_psk, rfc8448_early_secret);
    _test_case.test(ret, __FUNCTION__, "derive the RFC 8448 resumed-handshake early secret");
    const binary_t expected_early_secret = base16_decode_rfc("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
    _test_case.assert(expected_early_secret == rfc8448_early_secret, __FUNCTION__, "match the RFC 8448 resumed-handshake early-secret value");

    binary_t repeated_psk1;
    ret = protection.calc_resumption_ticket_psk(nonce1, repeated_psk1);
    _test_case.test(ret, __FUNCTION__, "derive the same ticket PSK deterministically");
    _test_case.assert(psk1 == repeated_psk1, __FUNCTION__, "same resumption master secret and nonce produce the same PSK");

    binary_t psk2;
    ret = protection.calc_resumption_ticket_psk(nonce2, psk2);
    _test_case.test(ret, __FUNCTION__, "derive ticket PSK using a different ticket nonce");
    _test_case.assert(psk1 != psk2, __FUNCTION__, "different ticket nonces produce different PSKs");

    protection.set_cipher_suite(0x1302);
    protection.get_secrets().assign(tls_secret_t::res_master, binary_t(48, 0x11));
    binary_t psk_sha384;
    ret = protection.calc_resumption_ticket_psk(nonce1, psk_sha384);
    _test_case.test(ret, __FUNCTION__, "derive ticket PSK using SHA-384 cipher suite hash");
    const binary_t expected_psk_sha384 = base16_decode_rfc("49353858f953d0420cee0ab73989f5032a86d7c7def71877801780a56f814aecf6b85454d10221cbe7e73fdee48ba79a");
    _test_case.assert(48 == psk_sha384.size(), __FUNCTION__, "SHA-384 ticket PSK has a 48-byte digest");
    _test_case.assert(expected_psk_sha384 == psk_sha384, __FUNCTION__, "match the SHA-384 HKDF-Expand-Label ticket PSK known-answer value");

    // Exercise the SHA-384 hash through the complete NewSessionTicket
    // issuance and receipt path, not only through the derivation helper.
    tls_handshake_new_session_ticket issued_sha384(&session);
    binary_t sha384_wire;
    ret = issued_sha384.write(from_server, sha384_wire);
    _test_case.test(ret, __FUNCTION__, "issue a NewSessionTicket under TLS_AES_256_GCM_SHA384");
    if (errorcode_t::success == ret) {
        tls_session sha384_client;
        sha384_client.set_type(session_type_t::tls);
        auto& sha384_client_protection = sha384_client.get_tls_protection();
        sha384_client_protection.set_tls_version(tls_13);
        sha384_client_protection.set_cipher_suite(0x1302);
        sha384_client_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(48, 0x11));

        tls_handshake_new_session_ticket received_sha384(&sha384_client);
        size_t sha384_pos = 0;
        ret = received_sha384.read(from_server, sha384_wire.data(), sha384_wire.size(), sha384_pos);
        _test_case.test(ret, __FUNCTION__, "receive and derive the SHA-384 ticket PSK");
        if (errorcode_t::success == ret) {
            auto sha384_server_tickets = session.get_resumption_tickets();
            _test_case.assert(1 == sha384_server_tickets.size(), __FUNCTION__, "retain the issued SHA-384 ticket on the server");
            if (1 == sha384_server_tickets.size()) {
                tls_resumption_ticket server_ticket;
                tls_resumption_ticket client_ticket;
                bool server_found = session.find_resumption_ticket(sha384_server_tickets.front().identity, server_ticket);
                bool client_found = sha384_client.find_resumption_ticket(server_ticket.identity, client_ticket);
                _test_case.assert(server_found && client_found, __FUNCTION__, "retain the SHA-384 ticket on both endpoints");
                if (server_found && client_found) {
                    _test_case.assert(0x1302 == server_ticket.cipher_suite && 0x1302 == client_ticket.cipher_suite, __FUNCTION__,
                                      "retain the original SHA-384 cipher suite with the ticket");
                    _test_case.assert(48 == server_ticket.psk.size() && 48 == client_ticket.psk.size(), __FUNCTION__, "retain a 48-byte SHA-384 PSK on both endpoints");
                    _test_case.assert(server_ticket.nonce == client_ticket.nonce, __FUNCTION__, "retain the same SHA-384 ticket nonce");
                    _test_case.assert(server_ticket.psk == client_ticket.psk, __FUNCTION__, "derive the same SHA-384 PSK on server and client");
                }
            }
        }
    }
}

static void test_tls13_psk_binder_rfc8448_vector() {
    _test_case.begin("TLS 1.3 PSK binder RFC 8448 known-answer vector");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);

    const binary_t resumption_psk = base16_decode_rfc("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
    const binary_t binder_hash = base16_decode_rfc("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    const binary_t expected_binder = base16_decode_rfc("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "derive the RFC 8448 empty transcript hash");
    if (errorcode_t::success != ret) {
        return;
    }

    protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    binary_t binder;
    ret = protection.calc_psk_binder(&session, binder_hash, binder);
    _test_case.test(ret, __FUNCTION__, "calculate the RFC 8448 resumption PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(expected_binder == binder, __FUNCTION__, "match the RFC 8448 PSK binder known-answer value");

    ret = protection.calc_psk(&session, binder_hash, expected_binder);
    _test_case.test(ret, __FUNCTION__, "validate the RFC 8448 PSK binder with the shared calculation");

    const std::array<size_t, 3> modified_offsets = {0, expected_binder.size() / 2, expected_binder.size() - 1};
    for (size_t offset : modified_offsets) {
        binary_t modified_binder = expected_binder;
        modified_binder[offset] ^= 0x01;
        ret = protection.calc_psk(&session, binder_hash, modified_binder);
        _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a modified RFC 8448 PSK binder at every tested offset");
    }
    binary_t truncated_binder = expected_binder;
    truncated_binder.pop_back();
    ret = protection.calc_psk(&session, binder_hash, truncated_binder);
    _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a truncated RFC 8448 PSK binder");
}

static void test_tls13_psk_binder_hrr_transcript() {
    _test_case.begin("TLS 1.3 ClientHello2 PSK binder transcript after HRR");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::hello_retry_request);

    openssl_digest digest;
    binary_t client_hello1_hash(32, 0x11);
    binary_t synthetic_message_hash;
    synthetic_message_hash << uint8(tls_handshake_type_t::message_hash) << uint24_t(32) << client_hello1_hash;
    const binary_t hello_retry_request = {0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0xaa, 0xbb};
    binary_t transcript_prefix = synthetic_message_hash;
    transcript_prefix.insert(transcript_prefix.end(), hello_retry_request.begin(), hello_retry_request.end());

    return_t ret = protection.reset_transcript_hash(&session);
    _test_case.test(ret, __FUNCTION__, "reset the transcript before the HRR prefix");
    ret = protection.update_transcript_hash(&session, transcript_prefix.data(), transcript_prefix.size());
    _test_case.test(ret, __FUNCTION__, "seed the transcript with message_hash and HelloRetryRequest");

    // This buffer ends immediately before the binders vector length field.
    const binary_t truncated_client_hello2 = {0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0xcc, 0xdd};
    auto tlsadvisor = tls_advisor::get_instance();
    const tls_cipher_suite_t* suite = tlsadvisor->hintof_cipher_suite(0x1301);
    if (nullptr == suite) {
        _test_case.assert(false, __FUNCTION__, "resolve the TLS_AES_128_GCM_SHA256 cipher suite");
        return;
    }
    binary_t actual_binder_hash;
    ret = protection.calc_context_hash(&session, suite->mac, truncated_client_hello2.data(), truncated_client_hello2.size(), actual_binder_hash);
    _test_case.test(ret, __FUNCTION__, "calculate ClientHello2 binder hash using the existing HRR transcript");

    binary_t expected_transcript = transcript_prefix;
    expected_transcript.insert(expected_transcript.end(), truncated_client_hello2.begin(), truncated_client_hello2.end());
    binary_t expected_binder_hash;
    ret = digest.digest("sha256", expected_transcript, expected_binder_hash);
    _test_case.test(ret, __FUNCTION__, "calculate the expected message_hash, HRR, and truncated ClientHello2 digest");
    _test_case.assert(expected_binder_hash == actual_binder_hash, __FUNCTION__, "include the HRR transcript prefix in the ClientHello2 binder hash");

    // Verify the binder itself against an independent known-answer value for
    // this synthetic message_hash || HRR || truncated ClientHello2 transcript.
    const binary_t resumption_psk(32, 0x11);
    const binary_t expected_binder = base16_decode_rfc("9bf67dcb83f8988a0f1f92a9909855b2bfa508deb36f33e01e758f3cc56b4808");
    binary_t empty;
    binary_t empty_hash;
    ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "derive the empty transcript hash for the resumption binder key");
    protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    binary_t actual_binder;
    ret = protection.calc_psk_binder(&session, actual_binder_hash, actual_binder);
    _test_case.test(ret, __FUNCTION__, "calculate the ClientHello2 PSK binder after HRR");
    _test_case.assert(expected_binder == actual_binder, __FUNCTION__, "match the expected ClientHello2 binder after HRR");

    ret = protection.calc_psk(&session, actual_binder_hash, expected_binder);
    _test_case.test(ret, __FUNCTION__, "validate the ClientHello2 binder after HRR");
    const std::array<size_t, 3> modified_offsets = {0, expected_binder.size() / 2, expected_binder.size() - 1};
    for (size_t offset : modified_offsets) {
        binary_t modified_binder = expected_binder;
        modified_binder[offset] ^= 0x01;
        ret = protection.calc_psk(&session, actual_binder_hash, modified_binder);
        _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a modified ClientHello2 binder at every tested offset");
    }

    auto transcript = protection.get_transcript_hash();
    binary_t preserved_transcript_hash;
    if (transcript) {
        transcript->digest(preserved_transcript_hash);
        transcript->release();
    }
    binary_t expected_prefix_hash;
    ret = digest.digest("sha256", transcript_prefix, expected_prefix_hash);
    _test_case.test(ret, __FUNCTION__, "calculate the expected HRR prefix digest");
    _test_case.assert(expected_prefix_hash == preserved_transcript_hash, __FUNCTION__, "leave the live transcript unchanged while calculating the binder hash");
}

static void test_tls13_psk_ticket_age_limit() {
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
        // Keep the server-side issuance age just inside the cap while preserving
        // an exactly-seven-day obfuscated_ticket_age in the wire vector; a live
        // clock cannot deterministically exercise equality at millisecond precision.
        uint64 server_ticket_age_ms = vector.ticket_age_ms;
        if (vector.ticket_age_ms == static_cast<uint32>(max_ticket_lifetime * 1000)) {
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

static void test_tls13_server_psk_selected_identity_encoding() {
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

static void test_tls13_server_psk_selected_identity_range() {
    _test_case.begin("TLS 1.3 ServerHello PSK selected_identity range");

    constexpr uint32 ticket_age_add = 0x50607080;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0xaa, 0xbb, 0xcc};
    const binary_t resumption_psk(32, 0x11);

    auto prepare_client = [&](tls_session& client, uint8 offered_mode) -> return_t {
        client.set_type(session_type_t::tls);
        auto& protection = client.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        client.get_keyvalue().set(session_tls_version, tls_13);
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
        auto supported_versions = new tls_extension_client_supported_versions(client_hello);
        supported_versions->add(tls_13);
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
    };

    auto make_server_hello = [](uint16 selected_identity, uint16 cipher_suite, bool hello_retry_request) -> binary_t {
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
    };

    auto verify_case = [&](uint16 offered_count, uint16 selected_identity, uint8 offered_mode, uint16 cipher_suite, bool hello_retry_request,
                           bool expect_illegal_parameter, const char* description) {
        tls_session client;
        return_t ret = prepare_client(client, offered_mode);
        _test_case.test(ret, __FUNCTION__, "prepare a ClientHello with a PSK offer");
        if (errorcode_t::success != ret) {
            return;
        }

        client.get_keyvalue().set(session_client_psk_identity_count, offered_count);
        binary_t server_hello_wire = make_server_hello(selected_identity, cipher_suite, hello_retry_request);
        tls_handshake_server_hello server_hello(&client);
        size_t pos = 0;
        ret = server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), pos);

        size_t illegal_parameter_count = 0;
        client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(expect_illegal_parameter ? (1 == illegal_parameter_count) : (0 == illegal_parameter_count), __FUNCTION__, description);
        if (expect_illegal_parameter) {
            _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an out-of-range selected_identity");
        } else if (errorcode_t::success == ret) {
            _test_case.assert(server_hello_wire.size() == pos, __FUNCTION__, "consume the complete valid ServerHello");
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
}

static void test_tls13_client_psk_writer_ticket_lifetime() {
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

static void test_tls13_client_psk_binder_roundtrip() {
    _test_case.begin("TLS 1.3 client PSK binder serialization and server round-trip");

    constexpr uint32 ticket_age_add = 0x50607080;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0xaa, 0xbb, 0xcc};
    const binary_t resumption_psk(32, 0x11);

    auto configure_resumption = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
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
    };

    {
        tls_session missing_modes_client;
        configure_resumption(missing_modes_client);
        auto missing_modes_hello = new tls_handshake_client_hello(&missing_modes_client);
        missing_modes_hello->add_ciphersuite(0x1301);
        auto missing_modes_version = new tls_extension_client_supported_versions(missing_modes_hello);
        missing_modes_version->add(tls_13);
        missing_modes_hello->get_extensions().add(missing_modes_version);
        missing_modes_hello->get_extensions().add(new tls_extension_client_psk(missing_modes_hello));

        tls_record_handshake missing_modes_record(&missing_modes_client);
        missing_modes_record << missing_modes_hello;
        binary_t missing_modes_wire;
        return_t missing_modes_ret = missing_modes_record.write(from_client, missing_modes_wire);
        _test_case.assert(errorcode_t::success != missing_modes_ret, __FUNCTION__, "reject a PSK ClientHello without psk_key_exchange_modes");
        _test_case.assert(missing_modes_wire.empty(), __FUNCTION__, "emit no ClientHello with an incomplete PSK offer");
    }

    {
        tls_session non_final_client;
        configure_resumption(non_final_client);
        auto non_final_hello = new tls_handshake_client_hello(&non_final_client);
        non_final_hello->add_ciphersuite(0x1301);
        auto non_final_modes = new tls_extension_psk_key_exchange_modes(non_final_hello);
        non_final_modes->add(1);
        non_final_hello->get_extensions().add(non_final_modes);
        non_final_hello->get_extensions().add(new tls_extension_client_psk(non_final_hello));
        auto trailing_version = new tls_extension_client_supported_versions(non_final_hello);
        trailing_version->add(tls_13);
        non_final_hello->get_extensions().add(trailing_version);

        tls_record_handshake non_final_record(&non_final_client);
        non_final_record << non_final_hello;
        binary_t non_final_wire;
        return_t non_final_ret = non_final_record.write(from_client, non_final_wire);
        _test_case.assert(errorcode_t::success != non_final_ret, __FUNCTION__, "reject a ClientHello that places pre_shared_key before another extension");
        _test_case.assert(non_final_wire.empty(), __FUNCTION__, "emit no ClientHello with a non-final pre_shared_key extension");
    }

    tls_session client;
    configure_resumption(client);

    // tls_handshakes owns registered handshake objects and releases them when
    // the record is destroyed. Allocate the message on the heap accordingly.
    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);

    auto supported_versions = new tls_extension_client_supported_versions(client_hello);
    supported_versions->add(tls_13);
    client_hello->get_extensions().add(supported_versions);

    auto psk_modes = new tls_extension_psk_key_exchange_modes(client_hello);
    psk_modes->add(1);  // psk_dhe_ke
    client_hello->get_extensions().add(psk_modes);

    auto psk = new tls_extension_client_psk(client_hello);
    client_hello->get_extensions().add(psk);

    return_t ret = errorcode_t::success;
    tls_record_handshake record(&client);
    record << client_hello;
    binary_t wire;
    ret = record.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize a ClientHello with a computed PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    bool binder_nonzero = false;
    if (wire.size() >= 32) {
        for (size_t i = wire.size() - 32; i < wire.size(); ++i) {
            binder_nonzero = binder_nonzero || (0 != wire[i]);
        }
    }
    _test_case.assert(binder_nonzero, __FUNCTION__, "replace the placeholder binder before record serialization");

    // Move the PSK extension ahead of the other ClientHello extensions.
    // The server must reject this before attempting to validate the binder.
    size_t extension_block = 5 + 4 + 2 + 32;
    extension_block += 1 + wire[extension_block];  // legacy_session_id
    uint16 cipher_suites_size = (static_cast<uint16>(wire[extension_block]) << 8) | wire[extension_block + 1];
    extension_block += 2 + cipher_suites_size;
    extension_block += 1 + wire[extension_block];  // legacy_compression_methods
    extension_block += 2;                          // extensions length
    size_t psk_offset = extension_block;
    size_t psk_size = 0;
    while (psk_offset + 4 <= wire.size()) {
        uint16 extension_type = (static_cast<uint16>(wire[psk_offset]) << 8) | wire[psk_offset + 1];
        uint16 extension_size = (static_cast<uint16>(wire[psk_offset + 2]) << 8) | wire[psk_offset + 3];
        if (static_cast<uint16>(tls_extension_type_t::pre_shared_key) == extension_type) {
            psk_size = 4 + extension_size;
            break;
        }
        psk_offset += 4 + extension_size;
    }
    _test_case.assert((psk_size > 0) && (psk_offset + psk_size == wire.size()), __FUNCTION__, "locate the final pre_shared_key extension in the serialized ClientHello");
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t non_final_psk = wire;
        binary_t psk_extension(non_final_psk.begin() + psk_offset, non_final_psk.end());
        non_final_psk.erase(non_final_psk.begin() + psk_offset, non_final_psk.end());
        non_final_psk.insert(non_final_psk.begin() + extension_block, psk_extension.begin(), psk_extension.end());

        tls_session ordering_server;
        configure_resumption(ordering_server);
        tls_records ordering_records;
        ret = ordering_records.read(&ordering_server, from_client, non_final_psk);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject pre_shared_key when it is not the final ClientHello extension");

        size_t illegal_parameter_count = 0;
        ordering_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report illegal_parameter for a non-final pre_shared_key extension");
    }

    // Corrupt the PSK identity length so the vector extends beyond the
    // enclosing extension body. The payload decoder must not silently accept
    // its default-initialized fields.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t malformed_psk = wire;
        malformed_psk[psk_offset + 6] = 0xff;
        malformed_psk[psk_offset + 7] = 0xff;
        tls_session malformed_server;
        configure_resumption(malformed_server);
        tls_records malformed_records;
        ret = malformed_records.read(&malformed_server, from_client, malformed_psk);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a PSK identity length that exceeds the extension body");
    }

    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        // A PSK identity must not be empty.
        binary_t empty_identity = wire;
        empty_identity[psk_offset + 6] = 0;
        empty_identity[psk_offset + 7] = 0;
        tls_session empty_identity_server;
        configure_resumption(empty_identity_server);
        tls_records empty_identity_records;
        ret = empty_identity_records.read(&empty_identity_server, from_client, empty_identity);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an empty PSK identity");

        // TLS 1.3 binder entries must contain the complete hash-sized value.
        uint16 identities_length = (static_cast<uint16>(wire[psk_offset + 4]) << 8) | wire[psk_offset + 5];
        size_t binders_length_offset = psk_offset + 4 + 2 + identities_length;
        if (binders_length_offset + 3 <= wire.size()) {
            binary_t short_binder = wire;
            short_binder[binders_length_offset + 2] = 31;
            tls_session short_binder_server;
            configure_resumption(short_binder_server);
            tls_records short_binder_records;
            ret = short_binder_records.read(&short_binder_server, from_client, short_binder);
            _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a PSK binder shorter than the minimum 32 bytes");
        }
    }

    tls_session server;
    configure_resumption(server);
    tls_records records;
    ret = records.read(&server, from_client, wire);
    _test_case.test(ret, __FUNCTION__, "server parses and validates the generated ClientHello binder");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "accept the matching PSK and enter the resumption flow");
        _test_case.assert(!server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash).empty(), __FUNCTION__,
                          "retain the validated binder transcript hash");
        _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the single identity offered in the ClientHello");
    }

    // Offer an unknown identity first and the cached ticket second. The
    // corresponding second binder must be selected and validated.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        auto append_u16 = [](binary_t& out, uint16 value) {
            out.push_back(static_cast<byte_t>(value >> 8));
            out.push_back(static_cast<byte_t>(value));
        };
        auto append_u32 = [](binary_t& out, uint32 value) {
            out.push_back(static_cast<byte_t>(value >> 24));
            out.push_back(static_cast<byte_t>(value >> 16));
            out.push_back(static_cast<byte_t>(value >> 8));
            out.push_back(static_cast<byte_t>(value));
        };

        const binary_t unknown_ticket = {0x91, 0x92, 0x93};
        binary_t identities;
        append_u16(identities, t_narrow_cast(unknown_ticket.size()));
        identities.insert(identities.end(), unknown_ticket.begin(), unknown_ticket.end());
        append_u32(identities, 0);
        append_u16(identities, t_narrow_cast(ticket.size()));
        identities.insert(identities.end(), ticket.begin(), ticket.end());
        append_u32(identities, ticket_age_add + 25);

        binary_t psk_body;
        append_u16(psk_body, t_narrow_cast(identities.size()));
        psk_body.insert(psk_body.end(), identities.begin(), identities.end());
        append_u16(psk_body, 66);  // two SHA-256 binder entries
        psk_body.push_back(32);
        psk_body.insert(psk_body.end(), 32, 0);
        psk_body.push_back(32);
        psk_body.insert(psk_body.end(), 32, 0);

        binary_t multi_identity_wire(wire.begin(), wire.begin() + psk_offset);
        multi_identity_wire.insert(multi_identity_wire.end(), {0x00, 0x29, static_cast<byte_t>(psk_body.size() >> 8), static_cast<byte_t>(psk_body.size())});
        multi_identity_wire.insert(multi_identity_wire.end(), psk_body.begin(), psk_body.end());
        const size_t delta = multi_identity_wire.size() - wire.size();
        test_write_u16(multi_identity_wire, psk_offset + 2, t_narrow_cast(psk_body.size()));
        test_write_u16(multi_identity_wire, extension_block - 2, static_cast<uint16>(test_read_u16(wire, extension_block - 2) + delta));
        test_write_u24(multi_identity_wire, 6, test_read_u24(wire, 6) + static_cast<uint32>(delta));
        test_write_u16(multi_identity_wire, 3, static_cast<uint16>(test_read_u16(wire, 3) + delta));

        const size_t binders_length_offset = psk_offset + 4 + 2 + identities.size();
        tls_session binder_session;
        configure_resumption(binder_session);
        auto tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t* suite = tlsadvisor->hintof_cipher_suite(0x1301);
        if (nullptr == suite) {
            _test_case.assert(false, __FUNCTION__, "resolve cipher suite for the second PSK binder");
        } else {
            binary_t binder_hash;
            ret = binder_session.get_tls_protection().calc_context_hash(&binder_session, suite->mac, multi_identity_wire.data() + 5, binders_length_offset - 5,
                                                                        binder_hash);
            _test_case.test(ret, __FUNCTION__, "hash a ClientHello offering multiple PSK identities");
            if (errorcode_t::success == ret) {
                binary_t selected_binder;
                ret = binder_session.get_tls_protection().calc_psk_binder(&binder_session, binder_hash, selected_binder);
                _test_case.test(ret, __FUNCTION__, "calculate the binder for the second offered PSK identity");
                if (errorcode_t::success == ret && selected_binder.size() == 32) {
                    const size_t second_binder_offset = binders_length_offset + 2 + 1 + 32 + 1;
                    std::copy(selected_binder.begin(), selected_binder.end(), multi_identity_wire.begin() + second_binder_offset);

                    tls_session multi_identity_server;
                    configure_resumption(multi_identity_server);
                    tls_records multi_identity_records;
                    ret = multi_identity_records.read(&multi_identity_server, from_client, multi_identity_wire);
                    _test_case.test(ret, __FUNCTION__, "select and validate the binder matching the second PSK identity");
                    if (errorcode_t::success == ret) {
                        _test_case.assert(tls_flow_t::zero_rtt == multi_identity_server.get_tls_protection().get_flow(), __FUNCTION__,
                                          "resume when the cached ticket is offered after an unknown identity");
                        const binary_t& server_hash = multi_identity_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
                        _test_case.assert(!server_hash.empty() && binder_hash == server_hash, __FUNCTION__,
                                          "retain the transcript hash used to validate the selected second binder");
                        _test_case.assert(2 == multi_identity_server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                                          "record both identities from the multi-identity ClientHello");
                    }

                    // A duplicated cached identity can carry different ticket ages.
                    // Skip an expired occurrence and accept a later usable one.
                    binary_t duplicate_identity_wire = multi_identity_wire;
                    std::copy(ticket.begin(), ticket.end(), duplicate_identity_wire.begin() + psk_offset + 8);
                    auto write_u32 = [](binary_t& out, size_t offset, uint32 value) {
                        out[offset] = static_cast<byte_t>(value >> 24);
                        out[offset + 1] = static_cast<byte_t>(value >> 16);
                        out[offset + 2] = static_cast<byte_t>(value >> 8);
                        out[offset + 3] = static_cast<byte_t>(value);
                    };
                    write_u32(duplicate_identity_wire, psk_offset + 11, ticket_age_add + ticket_lifetime * 1000 + 1000);
                    write_u32(duplicate_identity_wire, psk_offset + 20, ticket_age_add + 25);

                    tls_session duplicate_binder_session;
                    configure_resumption(duplicate_binder_session);
                    binary_t duplicate_binder_hash;
                    ret = duplicate_binder_session.get_tls_protection().calc_context_hash(&duplicate_binder_session, suite->mac, duplicate_identity_wire.data() + 5,
                                                                                          binders_length_offset - 5, duplicate_binder_hash);
                    _test_case.test(ret, __FUNCTION__, "hash a ClientHello with duplicate PSK identities and different ages");
                    if (errorcode_t::success == ret) {
                        binary_t duplicate_binder;
                        ret = duplicate_binder_session.get_tls_protection().calc_psk_binder(&duplicate_binder_session, duplicate_binder_hash, duplicate_binder);
                        _test_case.test(ret, __FUNCTION__, "calculate binders for duplicate PSK identities");
                        if (errorcode_t::success == ret && duplicate_binder.size() == 32) {
                            const size_t first_binder_offset = binders_length_offset + 3;
                            const size_t second_duplicate_binder_offset = first_binder_offset + 33;
                            std::copy(duplicate_binder.begin(), duplicate_binder.end(), duplicate_identity_wire.begin() + first_binder_offset);
                            std::copy(duplicate_binder.begin(), duplicate_binder.end(), duplicate_identity_wire.begin() + second_duplicate_binder_offset);

                            tls_session duplicate_identity_server;
                            configure_resumption(duplicate_identity_server);
                            tls_records duplicate_identity_records;
                            ret = duplicate_identity_records.read(&duplicate_identity_server, from_client, duplicate_identity_wire);
                            _test_case.test(ret, __FUNCTION__, "process duplicate PSK identities when a later occurrence has a valid ticket age");
                            if (errorcode_t::success == ret) {
                                _test_case.assert(tls_flow_t::zero_rtt == duplicate_identity_server.get_tls_protection().get_flow(), __FUNCTION__,
                                                  "skip the expired duplicate and resume with the later valid occurrence");
                            }
                        }
                    }

                    // When duplicate identities are both within lifetime, the first
                    // eligible occurrence is selected and its corresponding binder
                    // must be validated; a later valid binder cannot mask it.
                    const size_t first_binder_offset = binders_length_offset + 3;
                    const size_t second_duplicate_binder_offset = first_binder_offset + 33;
                    binary_t first_usable_duplicate_wire = duplicate_identity_wire;
                    write_u32(first_usable_duplicate_wire, psk_offset + 11, ticket_age_add + 25);

                    tls_session first_usable_duplicate_binder_session;
                    configure_resumption(first_usable_duplicate_binder_session);
                    binary_t first_usable_duplicate_hash;
                    ret = first_usable_duplicate_binder_session.get_tls_protection().calc_context_hash(&first_usable_duplicate_binder_session, suite->mac,
                                                                                                       first_usable_duplicate_wire.data() + 5, binders_length_offset - 5,
                                                                                                       first_usable_duplicate_hash);
                    _test_case.test(ret, __FUNCTION__, "hash duplicate usable PSK identities with the first occurrence eligible");
                    if (errorcode_t::success == ret) {
                        binary_t first_usable_duplicate_binder;
                        ret = first_usable_duplicate_binder_session.get_tls_protection().calc_psk_binder(&first_usable_duplicate_binder_session,
                                                                                                         first_usable_duplicate_hash, first_usable_duplicate_binder);
                        _test_case.test(ret, __FUNCTION__, "calculate the binder for duplicate usable PSK identities");
                        if (errorcode_t::success == ret && first_usable_duplicate_binder.size() == 32) {
                            std::copy(first_usable_duplicate_binder.begin(), first_usable_duplicate_binder.end(),
                                      first_usable_duplicate_wire.begin() + first_binder_offset);
                            std::copy(first_usable_duplicate_binder.begin(), first_usable_duplicate_binder.end(),
                                      first_usable_duplicate_wire.begin() + second_duplicate_binder_offset);
                            first_usable_duplicate_wire[first_binder_offset] ^= 0x01;

                            tls_session first_usable_duplicate_server;
                            configure_resumption(first_usable_duplicate_server);
                            tls_records first_usable_duplicate_records;
                            ret = first_usable_duplicate_records.read(&first_usable_duplicate_server, from_client, first_usable_duplicate_wire);
                            _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an invalid binder for the first eligible duplicate identity");
                        }
                    }

                    // The parser must validate the complete identities vector,
                    // even when an earlier identity is already eligible.
                    binary_t malformed_later_identity = multi_identity_wire;
                    test_write_u16(malformed_later_identity, psk_offset + 15, 0xffff);
                    tls_session malformed_later_identity_server;
                    configure_resumption(malformed_later_identity_server);
                    tls_records malformed_later_identity_records;
                    ret = malformed_later_identity_records.read(&malformed_later_identity_server, from_client, malformed_later_identity);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an out-of-bounds later PSK identity after an eligible identity");

                    // A later identity with an incomplete obfuscated_ticket_age
                    // must not be accepted by borrowing bytes from the binder vector.
                    binary_t truncated_later_ticket_age = multi_identity_wire;
                    test_write_u16(truncated_later_ticket_age, psk_offset + 4, 17);
                    tls_session truncated_later_ticket_age_server;
                    configure_resumption(truncated_later_ticket_age_server);
                    tls_records truncated_later_ticket_age_records;
                    ret = truncated_later_ticket_age_records.read(&truncated_later_ticket_age_server, from_client, truncated_later_ticket_age);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a later PSK identity with a truncated ticket age");

                    // Validate every binder entry, including entries after
                    // the binder corresponding to the selected identity.
                    binary_t malformed_later_binder = multi_identity_wire;
                    malformed_later_binder[second_binder_offset - 1] = 31;
                    tls_session malformed_later_binder_server;
                    configure_resumption(malformed_later_binder_server);
                    tls_records malformed_later_binder_records;
                    ret = malformed_later_binder_records.read(&malformed_later_binder_server, from_client, malformed_later_binder);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a malformed binder after an otherwise usable PSK identity");

                    // Two identities cannot be paired with only one binder.
                    binary_t mismatched_binder_count = multi_identity_wire;
                    test_write_u16(mismatched_binder_count, binders_length_offset, 33);
                    tls_session mismatched_binder_count_server;
                    configure_resumption(mismatched_binder_count_server);
                    tls_records mismatched_binder_count_records;
                    ret = mismatched_binder_count_records.read(&mismatched_binder_count_server, from_client, mismatched_binder_count);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a binder vector that does not match the identity vector");
                } else if (errorcode_t::success == ret) {
                    _test_case.assert(false, __FUNCTION__, "produce a 32-byte SHA-256 binder for the second identity");
                }
            }
        }
    }

    // An identity unknown to this server must be ignored rather than treated
    // as a fatal protocol error; continue with the full-handshake path.
    tls_session unknown_identity_server;
    configure_resumption(unknown_identity_server);
    unknown_identity_server.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, binary_t{0x99, 0x88});
    tls_records unknown_identity_records;
    ret = unknown_identity_records.read(&unknown_identity_server, from_client, wire);
    _test_case.test(ret, __FUNCTION__, "ignore an unknown PSK identity and continue ClientHello processing");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::one_rtt == unknown_identity_server.get_tls_protection().get_flow(), __FUNCTION__,
                          "decline an unknown PSK and select the full-handshake path");
        _test_case.assert(0 == unknown_identity_server.get_keyvalue().get(session_tls_version), __FUNCTION__,
                          "clear the previous negotiated TLS version when the PSK identity is unknown");
    }

    binary_t tampered = wire;
    tampered.back() ^= 0x01;
    tls_session rejecting_server;
    configure_resumption(rejecting_server);
    tls_records rejecting_records;
    ret = rejecting_records.read(&rejecting_server, from_client, tampered);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ClientHello with a modified PSK binder");

    size_t decrypt_error_count = 0;
    rejecting_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decrypt_error == desc)) {
            ++decrypt_error_count;
        }
    });
    _test_case.assert(1 == decrypt_error_count, __FUNCTION__, "report decrypt_error for a modified binder");
}

static void test_tls13_clienthello2_psk_binder_hrr_roundtrip() {
    _test_case.begin("TLS 1.3 ClientHello1-HRR-ClientHello2 PSK binder integration");

    constexpr uint32 ticket_age_add = 0x10203040;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0x11, 0x22, 0x33};
    const binary_t resumption_psk(32, 0x22);
    const binary_t hrr_random = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

    auto configure_resumption = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        // Model a cached session whose original handshake completed. After
        // HRR, ServerHello processing uses this flag to restore the resumption
        // flow instead of treating ClientHello2 as a fresh full handshake.
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
        ticket_kv.set(session_ticket_lifetime, ticket_lifetime);
        ticket_kv.set(session_ticket_age_add, ticket_age_add);
        ticket_kv.set(session_ticket_timestamp, now_ms - 25);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
        protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    };

    tls_session client;
    configure_resumption(client);

    // ClientHello1 offers the group but deliberately omits its key share,
    // forcing the server to select the group through a real HelloRetryRequest.
    auto client_hello1 = new tls_handshake_client_hello(&client);
    client_hello1->add_ciphersuite(0x1301);

    auto supported_versions1 = new tls_extension_client_supported_versions(client_hello1);
    supported_versions1->add(tls_13);
    client_hello1->get_extensions().add(supported_versions1);

    auto supported_groups1 = new tls_extension_supported_groups(client_hello1);
    supported_groups1->add("x25519");
    client_hello1->get_extensions().add(supported_groups1);

    auto psk_modes1 = new tls_extension_psk_key_exchange_modes(client_hello1);
    psk_modes1->add(1);  // psk_dhe_ke
    client_hello1->get_extensions().add(psk_modes1);

    auto psk1 = new tls_extension_client_psk(client_hello1);
    client_hello1->get_extensions().add(psk1);

    tls_record_handshake client_hello1_record(&client);
    client_hello1_record << client_hello1;
    binary_t client_hello1_wire;
    return_t ret = client_hello1_record.write(from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "serialize PSK ClientHello1 without a key share");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the PSK identity count from ClientHello1");

    tls_session server;
    configure_resumption(server);
    // ClientHello1 intentionally has no key_share, so the server must
    // explicitly select an offered group when constructing the HRR.
    auto tlsadvisor = tls_advisor::get_instance();
    server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
    tls_records server_clienthello1_records;
    ret = server_clienthello1_records.read(&server, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "server validates the ClientHello1 PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the PSK identity count received in ClientHello1");

    // Build and serialize a genuine HRR-form ServerHello. The server key_share
    // extension emits only selected_group because ClientHello1 had no share.
    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_random(hrr_random);
    ret = server_hello->set_cipher_suite(0x1301);
    _test_case.test(ret, __FUNCTION__, "select the TLS 1.3 cipher suite for HRR");
    if (errorcode_t::success != ret) {
        server_hello->release();
        return;
    }

    auto supported_versions2 = new tls_extension_server_supported_versions(server_hello);
    supported_versions2->set(tls_13);
    server_hello->get_extensions().add(supported_versions2);

    auto server_key_share = new tls_extension_server_key_share(server_hello);
    ret = server_key_share->add_keyshare();
    _test_case.test(ret, __FUNCTION__, "select x25519 for the retry");
    if (errorcode_t::success != ret) {
        server_hello->release();
        return;
    }
    server_hello->get_extensions().add(server_key_share);

    tls_record_handshake server_hello_record(&server);
    server_hello_record << server_hello;
    binary_t hrr_wire;
    ret = server_hello_record.write(from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "serialize HelloRetryRequest from the live ClientHello1 state");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), __FUNCTION__,
                      "server enters the HRR flow after processing ClientHello1");

    tls_records client_hrr_records;
    ret = client_hrr_records.read(&client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "client processes the actual HelloRetryRequest message");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::hello_retry_request == client.get_tls_protection().get_flow(), __FUNCTION__, "client enters the HRR flow after receiving the retry");

    // ClientHello2 carries the requested key share and a binder over the
    // transcript produced by processing the real ClientHello1 and HRR messages.
    auto client_hello2 = new tls_handshake_client_hello(&client);
    client_hello2->add_ciphersuite(0x1301);

    auto supported_versions3 = new tls_extension_client_supported_versions(client_hello2);
    supported_versions3->add(tls_13);
    client_hello2->get_extensions().add(supported_versions3);

    auto supported_groups2 = new tls_extension_supported_groups(client_hello2);
    supported_groups2->add("x25519");
    client_hello2->get_extensions().add(supported_groups2);

    auto client_key_share = new tls_extension_client_key_share(client_hello2);
    client_hello2->get_extensions().add(client_key_share);

    auto psk_modes2 = new tls_extension_psk_key_exchange_modes(client_hello2);
    psk_modes2->add(1);
    client_hello2->get_extensions().add(psk_modes2);

    auto psk2 = new tls_extension_client_psk(client_hello2);
    client_hello2->get_extensions().add(psk2);

    tls_record_handshake client_hello2_record(&client);
    client_hello2_record << client_hello2;
    binary_t client_hello2_wire;
    ret = client_hello2_record.write(from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with the selected key share and HRR binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "refresh the PSK identity count from ClientHello2 after HRR");

    // Rebuild the complete retry exchange in an independent client and ensure
    // a second HRR is rejected after ClientHello2 has restored the client cursor.
    tls_session second_hrr_client;
    configure_resumption(second_hrr_client);
    tls_records second_hrr_clienthello1_records;
    ret = second_hrr_clienthello1_records.read(&second_hrr_client, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "prepare an independent client for the second-HRR rejection test");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records second_hrr_first_retry_records;
    ret = second_hrr_first_retry_records.read(&second_hrr_client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "process the first HelloRetryRequest in the independent client");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records second_hrr_clienthello2_records;
    ret = second_hrr_clienthello2_records.read(&second_hrr_client, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "process ClientHello2 before injecting a second HelloRetryRequest");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_handshake_type_t::client_hello == second_hrr_client.get_session_info(from_client).get_status(), __FUNCTION__,
                      "position the client handshake cursor at ClientHello2 before the second HRR");
    tls_records second_hrr_records;
    ret = second_hrr_records.read(&second_hrr_client, from_server, hrr_wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a second HelloRetryRequest in the same connection");
    size_t second_hrr_unexpected_message_count = 0;
    second_hrr_client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++second_hrr_unexpected_message_count;
        }
    });
    _test_case.assert(1 == second_hrr_unexpected_message_count, __FUNCTION__, "report fatal unexpected_message for a second HelloRetryRequest");

    tls_records server_clienthello2_records;
    ret = server_clienthello2_records.read(&server, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "server validates ClientHello2 binder against its live HRR transcript");
    if (errorcode_t::success == ret) {
        _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "refresh the server's PSK identity count from ClientHello2");
        _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the HRR transcript flow after accepting the ClientHello2 PSK");
        _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "retain selected_identity zero for the final ServerHello");
        const binary_t& client_binder_hash = client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        const binary_t& server_binder_hash = server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        _test_case.assert(!client_binder_hash.empty() && client_binder_hash == server_binder_hash, __FUNCTION__,
                          "client and server derive the same binder transcript hash from the real HRR exchange");
    }

    // Complete the real HRR path through the production ServerHello composer.
    // This verifies that the server carries the selected PSK identity from
    // ClientHello2 into the final ServerHello rather than relying on a
    // hand-assembled extension vector.
    tls_handshake* selected_server_hello = nullptr;
    ret = tls_composer::construct_server_hello(&selected_server_hello, &server, nullptr);
    _test_case.test(ret, __FUNCTION__, "construct the final post-HRR ServerHello through the TLS composer");
    if ((errorcode_t::success != ret) || (nullptr == selected_server_hello)) {
        return;
    }

    auto selected_server_versions = selected_server_hello->get_extensions().get(tls_extension_type_t::supported_versions);
    auto selected_server_key_share = selected_server_hello->get_extensions().get(tls_extension_type_t::key_share);
    auto selected_server_psk = selected_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key);
    _test_case.assert(nullptr != selected_server_versions, __FUNCTION__, "include supported_versions in the final post-HRR ServerHello");
    _test_case.assert(nullptr != selected_server_key_share, __FUNCTION__, "include the requested key_share in the final post-HRR ServerHello");
    _test_case.assert(nullptr != selected_server_psk, __FUNCTION__, "include pre_shared_key after accepting the ClientHello2 PSK");
    if ((nullptr == selected_server_versions) || (nullptr == selected_server_key_share) || (nullptr == selected_server_psk)) {
        selected_server_hello->release();
        return;
    }

    auto selected_server_psk_extension = static_cast<tls_extension_server_psk*>(selected_server_psk);
    _test_case.assert(0 == selected_server_psk_extension->get_selected_identity(), __FUNCTION__, "serialize selected_identity zero retained from ClientHello2");
    binary_t selected_server_hello_wire;
    ret = selected_server_hello->write(from_server, selected_server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the composer-built post-HRR ServerHello");
    selected_server_hello->release();
    if (errorcode_t::success != ret) {
        return;
    }

    binary_t server_shared_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(!server_shared_secret.empty(), __FUNCTION__, "derive the server-side shared secret from the negotiated ClientHello2 key_share");

    tls_handshake_server_hello selected_server_hello_reader(&client);
    size_t selected_server_hello_pos = 0;
    ret = selected_server_hello_reader.read(from_server, selected_server_hello_wire.data(), selected_server_hello_wire.size(), selected_server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "client accepts the production-composed post-HRR ServerHello selecting identity zero");
    if (errorcode_t::success == ret) {
        _test_case.assert(selected_server_hello_wire.size() == selected_server_hello_pos, __FUNCTION__, "consume the complete post-HRR ServerHello");
        _test_case.assert(tls_13 == client.get_tls_protection().get_tls_version(), __FUNCTION__, "retain TLS 1.3 after accepting the post-HRR PSK selection");
        binary_t client_shared_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
        _test_case.assert(!client_shared_secret.empty(), __FUNCTION__, "derive the client-side shared secret from the ServerHello key_share");
        _test_case.assert(server_shared_secret == client_shared_secret, __FUNCTION__, "derive matching DHE shared secrets after HRR PSK resumption");
    }

    // Rebuild the same ClientHello1-HRR-ClientHello2 state in an independent
    // client session. The successful ServerHello above advances the original
    // client's handshake cursor to ServerHello, so reusing it would correctly
    // trigger unexpected_message before selected_identity can be validated.
    tls_session invalid_selected_client;
    configure_resumption(invalid_selected_client);

    tls_records invalid_clienthello1_records;
    ret = invalid_clienthello1_records.read(&invalid_selected_client, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "replay ClientHello1 for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records invalid_hrr_records;
    ret = invalid_hrr_records.read(&invalid_selected_client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "replay HelloRetryRequest for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records invalid_clienthello2_records;
    ret = invalid_clienthello2_records.read(&invalid_selected_client, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "replay ClientHello2 for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(tls_handshake_type_t::client_hello == invalid_selected_client.get_session_info(from_client).get_status(), __FUNCTION__,
                      "keep the peer handshake cursor at ClientHello2 before parsing ServerHello");
    _test_case.assert(1 == invalid_selected_client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                      "retain the single PSK identity offered in ClientHello2");

    binary_t invalid_selected_server_hello_wire = selected_server_hello_wire;
    invalid_selected_server_hello_wire.back() = 0x01;
    tls_handshake_server_hello invalid_selected_server_hello_reader(&invalid_selected_client);
    size_t invalid_selected_server_hello_pos = 0;
    ret = invalid_selected_server_hello_reader.read(from_server, invalid_selected_server_hello_wire.data(), invalid_selected_server_hello_wire.size(),
                                                    invalid_selected_server_hello_pos);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject selected_identity one when the real post-HRR ClientHello2 offered only one identity");
    size_t selected_identity_alert_count = 0;
    size_t unexpected_message_alert_count = 0;
    invalid_selected_client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if (tls_alertlevel_t::fatal == level) {
            if (tls_alertdesc_t::illegal_parameter == desc) {
                ++selected_identity_alert_count;
            } else if (tls_alertdesc_t::unexpected_message == desc) {
                ++unexpected_message_alert_count;
            }
        }
    });
    _test_case.assert(0 == unexpected_message_alert_count, __FUNCTION__, "do not reject the first post-HRR ServerHello as unexpected_message");
    _test_case.assert(1 == selected_identity_alert_count, __FUNCTION__, "report fatal illegal_parameter for an out-of-range post-HRR selected_identity");

    binary_t tampered = client_hello2_wire;
    tampered.back() ^= 0x01;
    tls_session rejecting_server;
    configure_resumption(rejecting_server);
    rejecting_server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
    tls_records rejecting_clienthello1_records;
    ret = rejecting_clienthello1_records.read(&rejecting_server, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a separate server with the same ClientHello1 transcript");
    if (errorcode_t::success != ret) {
        return;
    }

    // Reproduce the HRR on the rejecting server so its transcript is identical.
    auto rejecting_server_hello = new tls_handshake_server_hello(&rejecting_server);
    rejecting_server_hello->set_random(hrr_random);
    ret = rejecting_server_hello->set_cipher_suite(0x1301);
    if (errorcode_t::success != ret) {
        rejecting_server_hello->release();
        return;
    }
    auto rejecting_versions = new tls_extension_server_supported_versions(rejecting_server_hello);
    rejecting_versions->set(tls_13);
    rejecting_server_hello->get_extensions().add(rejecting_versions);
    auto rejecting_key_share = new tls_extension_server_key_share(rejecting_server_hello);
    ret = rejecting_key_share->add_keyshare();
    if (errorcode_t::success != ret) {
        rejecting_server_hello->release();
        return;
    }
    rejecting_server_hello->get_extensions().add(rejecting_key_share);
    tls_record_handshake rejecting_hrr_record(&rejecting_server);
    rejecting_hrr_record << rejecting_server_hello;
    binary_t rejecting_hrr_wire;
    ret = rejecting_hrr_record.write(from_server, rejecting_hrr_wire);
    _test_case.test(ret, __FUNCTION__, "recreate HRR before checking a modified ClientHello2 binder");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records rejecting_clienthello2_records;
    ret = rejecting_clienthello2_records.read(&rejecting_server, from_client, tampered);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ClientHello2 with a modified PSK binder");

    size_t decrypt_error_count = 0;
    rejecting_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decrypt_error == desc)) {
            ++decrypt_error_count;
        }
    });
    _test_case.assert(1 == decrypt_error_count, __FUNCTION__, "report decrypt_error for a modified ClientHello2 binder");
}

static void test_tls13_client_multiple_ticket_psk_offer() {
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
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
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
    ticket1.cipher_suite = 0x1301;
    ticket1.max_early_data_size = 4096;

    tls_resumption_ticket ticket2;
    ticket2.identity = identity2;
    ticket2.nonce = {0x00, 0x02};
    ticket2.psk = psk2;
    ticket2.lifetime = 3600;
    ticket2.age_add = 0x50607080;
    ticket2.timestamp = now_ms - 35;
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
    // 0x1302 uses SHA-384 and must not be mixed into this SHA-256 offer.
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
    _test_case.assert(2 == identity_count, __FUNCTION__, "offer both cached ticket identities");

    uint16 binders_length = (static_cast<uint16>(wire[pos]) << 8) | wire[pos + 1];
    pos += 2;
    size_t binders_end = pos + binders_length;
    size_t binder_count = 0;
    while (pos < binders_end) {
        uint8 binder_length = wire[pos++];
        bool nonzero = false;
        for (size_t i = 0; i < binder_length && pos + i < binders_end; ++i) {
            nonzero = nonzero || (0 != wire[pos + i]);
        }
        _test_case.assert(nonzero, __FUNCTION__, "compute a nonzero binder for each offered ticket");
        pos += binder_length;
        ++binder_count;
    }
    _test_case.assert(2 == binder_count, __FUNCTION__, "emit one binder for each offered identity");
    _test_case.assert(pos == binders_end, __FUNCTION__, "consume the complete binders vector");

    // The server knows only the second identity. It must verify binder index 1
    // with that ticket's PSK rather than reusing the first ticket's PSK.
    tls_session server;
    configure(server);
    server.get_tls_protection().set_cipher_suite(0);
    server.store_resumption_ticket(ticket2);
    tls_records records;
    ret = records.read(&server, from_client, wire);
    _test_case.test(ret, __FUNCTION__, "server parses ClientHello and verifies the second offered identity when the first is unknown");
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
            _test_case.assert(4096 == age_match_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                              "accept early data when ticket age matches and the ticket advertises an allowance");
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
            _test_case.assert(4096 == mismatch_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                              "recognize the ticket's early-data allowance before suite compatibility is evaluated");

            mismatch_context.clear_cipher_suites();
            mismatch_context.add_cipher_suite(0x1302);
            mismatch_context.add_cipher_suite(0x1301);

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

static void test_tls13_client_falls_back_when_server_declines_psk() {
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
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
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
    server_hello->release();
    if (errorcode_t::success != ret) {
        return;
    }

    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    tls_handshake_server_hello server_hello_reader(&client);
    size_t server_hello_pos = 0;
    ret = server_hello_reader.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_hello_pos);
    _test_case.test(ret, __FUNCTION__, "accept the ServerHello that declines PSK resumption");
    _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "switch the client to the full-handshake key schedule");
    _test_case.assert(client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "discard the cached PSK early secret before deriving handshake traffic keys");
    _test_case.assert(server_hello_wire.size() == server_hello_pos, __FUNCTION__, "consume the complete ServerHello");
}

static void test_tls13_psk_key_exchange_modes_vector() {
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

void testcase_gpt_session_ticket() {
    test_tls13_server_rejects_early_data_for_nonzero_selected_identity();
    test_tls13_server_requires_early_data_ticket_permission();
    test_tls13_new_session_ticket_lifetime();
    test_tls13_multiple_new_session_tickets_are_cached_independently();
    test_tls13_new_session_ticket_nonce_uniqueness();
    test_tls13_server_client_ticket_psk_roundtrip();
    test_tls13_ticket_nonce_resumption_psk();
    test_tls13_psk_binder_rfc8448_vector();
    test_tls13_psk_binder_hrr_transcript();
    test_tls13_psk_ticket_age_limit();
    test_tls13_psk_expired_clienthello_fallback();
    test_tls13_client_ticket_age_fallback();
    test_tls13_server_psk_selected_identity_encoding();
    test_tls13_server_psk_selected_identity_range();
    test_tls13_client_psk_writer_ticket_lifetime();
    test_tls13_client_psk_binder_roundtrip();
    test_tls13_clienthello2_psk_binder_hrr_roundtrip();
    test_tls13_client_multiple_ticket_psk_offer();
    test_tls13_client_falls_back_when_server_declines_psk();
    test_tls13_psk_key_exchange_modes_vector();
}
