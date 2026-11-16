/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk.cpp
 * @author GPT
 * @desc   TLS 1.3 resumption PSK derivation and binder tests.
 */

#include <algorithm>
#include <chrono>

#include "testcase_gpt_common.hpp"

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
    auto early_data_client_tickets = client_tickets;
    early_data_client_tickets.front().max_early_data_size = 4096;
    for (const auto& ticket : early_data_client_tickets) {
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
    resumed_client_hello_second->get_extensions().add(new tls_extension_early_data(resumed_client_hello_second));
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
    resumed_server_second.set_early_data_discard_limit(4096);
    resumed_server_second.store_resumption_ticket(server_tickets[1]);

    tls_records resumed_server_records_second;
    ret = resumed_server_records_second.read(&resumed_server_second, from_client, resumed_client_hello_wire_second);
    _test_case.test(ret, __FUNCTION__, "validate the second offered ticket binder using its independently restored server record");
    if (errorcode_t::success == ret) {
        auto& rejected_early_state = resumed_server_second.get_session_info(from_server).get_keyvalue();
        _test_case.assert(1 == rejected_early_state.get(session_early_data_offered), __FUNCTION__, "retain the early_data offer when identity zero is unknown");
        _test_case.assert(0 == rejected_early_state.get(session_early_data_limit), __FUNCTION__, "do not accept early data when the server selects identity one");
        _test_case.assert(4096 == rejected_early_state.get(session_early_data_discard_limit), __FUNCTION__,
                          "use the configured rejection skip limit when identity zero has no cached ticket");

        binary_t rejected_early_record{0x17, 0x03, 0x03, 0x00, 0x10};
        rejected_early_record.insert(rejected_early_record.end(), 16, 0xaa);
        tls_records rejected_early_records;
        return_t rejected_early_ret = rejected_early_records.read(&resumed_server_second, from_client, rejected_early_record);
        _test_case.test(rejected_early_ret, __FUNCTION__, "skip rejected 0-RTT records when identity zero is unknown");
        _test_case.assert(1 == rejected_early_records.size(), __FUNCTION__, "consume the rejected 0-RTT record without delivery");
        if (rejected_early_records.size()) {
            auto decoded = static_cast<tls_record_application_data*>(rejected_early_records.getat(0));
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "do not expose rejected 0-RTT plaintext to the application");
        }
        _test_case.assert(16 == rejected_early_state.get(session_early_data_discarded), __FUNCTION__,
                          "account the skipped ciphertext against the configured rejection bound");

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
    _test_case.begin("TLS 1.3 PSK binder SHA-256 and SHA-384 known-answer vectors");

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

    // Independent SHA-384 binder vector. Deliberately leave the cached empty
    // hash as SHA-256 to ensure binder derivation selects the PSK suite hash.
    protection.set_cipher_suite(0x1302);
    protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(48, 0x44));
    const binary_t sha384_binder_hash(48, 0x55);
    const binary_t expected_sha384_binder = base16_decode_rfc("c105b0279bcfb161bd470c73a97a44eeded5a2f34f3c547daa7edb543c09748c0582837e63885ade298b948a3f034307");
    binary_t sha384_binder;
    ret = protection.calc_psk_binder(&session, sha384_binder_hash, sha384_binder);
    _test_case.test(ret, __FUNCTION__, "calculate a SHA-384 resumption PSK binder");
    if (errorcode_t::success == ret) {
        _test_case.assert(48 == sha384_binder.size(), __FUNCTION__, "produce a 48-byte SHA-384 binder");
        _test_case.assert(expected_sha384_binder == sha384_binder, __FUNCTION__, "match the independent SHA-384 binder vector");
        ret = protection.calc_psk(&session, sha384_binder_hash, expected_sha384_binder);
        _test_case.test(ret, __FUNCTION__, "validate the SHA-384 binder with the shared calculation");
    }

    binary_t wrong_sha384_hash(32, 0x55);
    ret = protection.calc_psk_binder(&session, wrong_sha384_hash, sha384_binder);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a transcript hash whose length does not match SHA-384");
    protection.get_secrets().assign(tls_secret_t::resumption_early, binary_t(32, 0x44));
    ret = protection.calc_psk_binder(&session, sha384_binder_hash, sha384_binder);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a PSK early secret whose length does not match SHA-384");
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

    // Remove psk_key_exchange_modes from an otherwise valid, serialized PSK
    // ClientHello. The server, not just the local ClientHello writer, must
    // enforce RFC 8446 4.2.9 and abort with missing_extension.
    if ((psk_size > 0) && (psk_offset + psk_size == wire.size())) {
        binary_t missing_modes_wire = wire;
        size_t modes_offset = extension_block;
        size_t modes_size = 0;
        while (modes_offset + 4 <= psk_offset) {
            uint16 extension_type = (static_cast<uint16>(missing_modes_wire[modes_offset]) << 8) | missing_modes_wire[modes_offset + 1];
            uint16 extension_size = (static_cast<uint16>(missing_modes_wire[modes_offset + 2]) << 8) | missing_modes_wire[modes_offset + 3];
            if (static_cast<uint16>(tls_extension_type_t::psk_key_exchange_modes) == extension_type) {
                modes_size = 4 + extension_size;
                break;
            }
            modes_offset += 4 + extension_size;
        }
        _test_case.assert(modes_size > 0, __FUNCTION__, "locate psk_key_exchange_modes in the valid ClientHello");
        if (modes_size > 0) {
            missing_modes_wire.erase(missing_modes_wire.begin() + modes_offset, missing_modes_wire.begin() + modes_offset + modes_size);
            test_write_u16(missing_modes_wire, extension_block - 2, static_cast<uint16>(test_read_u16(wire, extension_block - 2) - modes_size));
            test_write_u24(missing_modes_wire, 6, test_read_u24(wire, 6) - static_cast<uint32>(modes_size));
            test_write_u16(missing_modes_wire, 3, static_cast<uint16>(test_read_u16(wire, 3) - modes_size));

            tls_session missing_modes_server;
            configure_resumption(missing_modes_server);
            tls_records missing_modes_records;
            ret = missing_modes_records.read(&missing_modes_server, from_client, missing_modes_wire);
            _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "server aborts a received PSK ClientHello without psk_key_exchange_modes");
            size_t missing_extension_count = 0;
            missing_modes_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::missing_extension == desc)) {
                    ++missing_extension_count;
                }
            });
            _test_case.assert(1 == missing_extension_count, __FUNCTION__, "report missing_extension for a received PSK offer without key-exchange modes");
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
        ticket_kv.set(session_ticket_max_early_data_size, 4096);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
        protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    };

    tls_session client;
    configure_resumption(client);
    client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

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

    client_hello1->get_extensions().add(new tls_extension_early_data(client_hello1));

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
    server.set_early_data_discard_limit(32);
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
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial), __FUNCTION__,
                      "record the actual ClientHello1 early_data offer on the server");
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "retain the current early_data offer while processing ClientHello1");

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
    _test_case.assert(false == client.get_session_info(from_client).apply_protection(), __FUNCTION__,
                      "disable client-to-server early-data record protection after accepting HRR");

    // The server learned the initial offer from the serialized ClientHello1;
    // retain that state while skipping records already in flight after HRR.
    binary_t in_flight_early_data_record{0x17, 0x03, 0x03, 0x00, 0x10};
    in_flight_early_data_record.insert(in_flight_early_data_record.end(), 16, 0xaa);
    tls_records early_data_before_clienthello2_records;
    ret = early_data_before_clienthello2_records.read(&server, from_client, in_flight_early_data_record);
    _test_case.test(ret, __FUNCTION__, "skip an in-flight ClientHello1 early-data record after HRR and before ClientHello2");
    _test_case.assert(16 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_discarded), __FUNCTION__,
                      "count pre-ClientHello2 rejected ciphertext against the configured HRR skip budget");

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

    // Even if the caller attempts to carry early_data into ClientHello2, the
    // writer must suppress it after HRR.
    client_hello2->get_extensions().add(new tls_extension_early_data(client_hello2));

    auto psk2 = new tls_extension_client_psk(client_hello2);
    client_hello2->get_extensions().add(psk2);

    // Probe the HRR-selected group separately so a key-generation failure
    // is distinguishable from the subsequent ClientHello2 binder serialization.
    uint16 retry_group = t_narrow_cast(client.get_session_info(from_server).get_keyvalue().get(session_key_share_group));
    _test_case.assert(static_cast<uint16>(tlsadvisor->valueof_group("x25519")) == retry_group, __FUNCTION__, "retain the HRR-selected x25519 group on the client");
    ret = client_key_share->add(static_cast<tls_group_t>(retry_group));
    _test_case.test(ret, __FUNCTION__, "generate the ClientHello2 key share for the HRR-selected group");
    if (errorcode_t::success != ret) {
        return;
    }
    client_key_share->clear();

    tls_record_handshake client_hello2_record(&client);
    client_hello2_record << client_hello2;
    binary_t client_hello2_wire;
    ret = client_hello2_record.write(from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with the selected key share and HRR binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "refresh the PSK identity count from ClientHello2 after HRR");

    auto prepare_retry_server = [&](tls_session& retry_server, binary_t& retry_wire) -> return_t {
        configure_resumption(retry_server);
        retry_server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
        tls_records initial_clienthello_records;
        return_t prepare_ret = initial_clienthello_records.read(&retry_server, from_client, client_hello1_wire);
        if (errorcode_t::success != prepare_ret) {
            return prepare_ret;
        }

        auto retry_hello = new tls_handshake_server_hello(&retry_server);
        retry_hello->set_random(hrr_random);
        prepare_ret = retry_hello->set_cipher_suite(0x1301);
        if (errorcode_t::success != prepare_ret) {
            retry_hello->release();
            return prepare_ret;
        }
        auto retry_versions = new tls_extension_server_supported_versions(retry_hello);
        retry_versions->set(tls_13);
        retry_hello->get_extensions().add(retry_versions);
        auto retry_key_share = new tls_extension_server_key_share(retry_hello);
        prepare_ret = retry_key_share->add_keyshare();
        if (errorcode_t::success != prepare_ret) {
            retry_hello->release();
            return prepare_ret;
        }
        retry_hello->get_extensions().add(retry_key_share);
        tls_record_handshake retry_record(&retry_server);
        retry_record << retry_hello;
        return retry_record.write(from_server, retry_wire);
    };

    // Keep the fatal skip-budget case isolated: overflow deliberately resets
    // the handshake status, so it must not run on the live session that will
    // continue to compose the final post-HRR ServerHello.
    tls_session over_limit_server;
    // Configure the discard budget before ClientHello1 is parsed. The TLS
    // session applies this setting to the per-connection early-data state
    // during ClientHello processing; setting it after HRR is too late.
    // The first 16-byte record reaches the exact boundary; the following
    // one-byte record must exceed it.
    over_limit_server.set_early_data_discard_limit(16);
    binary_t over_limit_hrr;
    ret = prepare_retry_server(over_limit_server, over_limit_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the post-ClientHello2 early-data skip-limit test");
    if (errorcode_t::success == ret) {
        _test_case.assert(1 == over_limit_server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial), __FUNCTION__,
                          "derive the isolated server's initial early_data state from ClientHello1");

        tls_records over_limit_before_clienthello2_records;
        ret = over_limit_before_clienthello2_records.read(&over_limit_server, from_client, in_flight_early_data_record);
        _test_case.test(ret, __FUNCTION__, "consume the first in-flight early-data record on the isolated server");
        if (errorcode_t::success == ret) {
            tls_records over_limit_clienthello2_records;
            ret = over_limit_clienthello2_records.read(&over_limit_server, from_client, client_hello2_wire);
            _test_case.test(ret, __FUNCTION__, "accept ClientHello2 before testing the isolated skip limit");
        }
        if (errorcode_t::success == ret) {
            binary_t over_limit_early_data_record{0x17, 0x03, 0x03, 0x00, 0x01, 0xaa};
            tls_records over_limit_after_clienthello2_records;
            return_t over_limit_ret = over_limit_after_clienthello2_records.read(&over_limit_server, from_client, over_limit_early_data_record);
            _test_case.assert(errorcode_t::overflow == over_limit_ret, __FUNCTION__, "enforce the same HRR skip budget for records arriving after ClientHello2");
            size_t hrr_skip_alert_count = 0;
            over_limit_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                    ++hrr_skip_alert_count;
                }
            });
            _test_case.assert(1 == hrr_skip_alert_count, __FUNCTION__, "raise one fatal unexpected_message when late HRR early data exceeds the skip budget");
        }
    }

    auto find_clienthello_extension = [](const binary_t& wire, uint16 extension_type, size_t& body_pos, size_t& body_size) -> bool {
        // tls_record_handshake::write() returns a complete TLS record:
        // 5-byte record header, 4-byte handshake header, then ClientHello.
        if (wire.size() < 5 + 4 + 2 + 32 + 1) {
            return false;
        }
        if ((0x16 != wire[0]) || (test_read_u16(wire, 3) != wire.size() - 5) || (0x01 != wire[5])) {
            return false;
        }
        size_t handshake_length = (static_cast<size_t>(wire[6]) << 16) | (static_cast<size_t>(wire[7]) << 8) | wire[8];
        if (handshake_length != wire.size() - 9) {
            return false;
        }
        size_t pos = 9 + 2 + 32;
        uint8 session_id_len = wire[pos++];
        if (session_id_len > wire.size() - pos) {
            return false;
        }
        pos += session_id_len;
        if (wire.size() - pos < 2) {
            return false;
        }
        uint16 cipher_suites_len = test_read_u16(wire, pos);
        pos += 2;
        if (cipher_suites_len > wire.size() - pos) {
            return false;
        }
        pos += cipher_suites_len;
        if (pos >= wire.size()) {
            return false;
        }
        uint8 compression_len = wire[pos++];
        if (compression_len > wire.size() - pos) {
            return false;
        }
        pos += compression_len;
        if (wire.size() - pos < 2) {
            return false;
        }
        uint16 extensions_len = test_read_u16(wire, pos);
        pos += 2;
        if ((extensions_len != wire.size() - pos)) {
            return false;
        }
        size_t end = pos + extensions_len;
        while (pos + 4 <= end) {
            uint16 type = test_read_u16(wire, pos);
            uint16 length = test_read_u16(wire, pos + 2);
            pos += 4;
            if (length > end - pos) {
                return false;
            }
            if (type == extension_type) {
                body_pos = pos;
                body_size = length;
                return true;
            }
            pos += length;
        }
        return false;
    };

    size_t client_hello2_early_data_pos = 0;
    size_t client_hello2_early_data_size = 0;
    bool client_hello2_has_early_data = find_clienthello_extension(client_hello2_wire, 0x002a, client_hello2_early_data_pos, client_hello2_early_data_size);
    _test_case.assert(false == client_hello2_has_early_data, __FUNCTION__, "omit early_data from ClientHello2 after HRR");
    _test_case.assert(0 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not mark early data as offered when its ClientHello2 extension is suppressed");

    // ClientHello2 may update ticket ages and binders, and remove PSKs that
    // are incompatible with the HRR suite. It must not substitute an identity.
    tls_session changed_identity_server;
    binary_t changed_identity_hrr;
    ret = prepare_retry_server(changed_identity_server, changed_identity_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the ClientHello2 identity consistency check");
    if (errorcode_t::success == ret) {
        binary_t changed_identity_clienthello2 = client_hello2_wire;
        size_t psk_body_pos = 0;
        size_t psk_body_size = 0;
        bool found_psk =
            find_clienthello_extension(changed_identity_clienthello2, static_cast<uint16>(tls_extension_type_t::pre_shared_key), psk_body_pos, psk_body_size);
        _test_case.assert(found_psk && (psk_body_size >= 8), __FUNCTION__, "locate the ClientHello2 PSK identities vector");
        if (found_psk && (psk_body_size >= 8)) {
            uint16 identity_len = test_read_u16(changed_identity_clienthello2, psk_body_pos + 2);
            _test_case.assert((identity_len > 0) && (psk_body_size >= static_cast<size_t>(identity_len) + 8), __FUNCTION__,
                              "validate the first ClientHello2 PSK identity boundary");
            if ((identity_len > 0) && (psk_body_size >= static_cast<size_t>(identity_len) + 8)) {
                changed_identity_clienthello2[psk_body_pos + 4] ^= 0x80;
                tls_records changed_identity_records;
                ret = changed_identity_records.read(&changed_identity_server, from_client, changed_identity_clienthello2);
                _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ClientHello2 that substitutes a PSK identity");
                size_t illegal_parameter_count = 0;
                changed_identity_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                    if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                        ++illegal_parameter_count;
                    }
                });
                _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report fatal illegal_parameter for a changed ClientHello2 PSK identity");
            }
        }
    }

    // psk_key_exchange_modes is not a permitted ClientHello2 change. Build a
    // correctly rebound ClientHello2 with a changed mode so the server reaches
    // the continuity check rather than failing binder verification first.
    tls_session changed_mode_server;
    binary_t changed_mode_hrr;
    ret = prepare_retry_server(changed_mode_server, changed_mode_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the ClientHello2 PSK mode consistency check");
    if (errorcode_t::success == ret) {
        tls_session changed_mode_client;
        configure_resumption(changed_mode_client);
        tls_records changed_mode_clienthello1_records;
        ret = changed_mode_clienthello1_records.read(&changed_mode_client, from_client, client_hello1_wire);
        _test_case.test(ret, __FUNCTION__, "restore the client state before constructing a changed-mode ClientHello2");
        if (errorcode_t::success == ret) {
            tls_records changed_mode_hrr_records;
            ret = changed_mode_hrr_records.read(&changed_mode_client, from_server, changed_mode_hrr);
            _test_case.test(ret, __FUNCTION__, "process the matching HRR before constructing a changed-mode ClientHello2");
        }
        if (errorcode_t::success == ret) {
            tls_handshake_client_hello modes_template(&changed_mode_client);
            tls_extension_psk_key_exchange_modes expected_modes(&modes_template);
            expected_modes.add(0);  // deliberately change psk_dhe_ke to psk_ke
            binary_t expected_modes_wire;
            ret = expected_modes.write(from_client, expected_modes_wire);
            _test_case.test(ret, __FUNCTION__, "encode the deliberately changed PSK mode offer");
            if (errorcode_t::success == ret) {
                // Bypass only the local client-side guard in this negative
                // server test; the actual ClientHello1 on the wire still
                // contains psk_dhe_ke.
                changed_mode_client.get_tls_protection().get_secrets().assign(tls_secret_t::client_hello_psk_modes, expected_modes_wire);

                auto changed_mode_clienthello2 = new tls_handshake_client_hello(&changed_mode_client);
                changed_mode_clienthello2->add_ciphersuite(0x1301);
                auto changed_mode_versions = new tls_extension_client_supported_versions(changed_mode_clienthello2);
                changed_mode_versions->add(tls_13);
                changed_mode_clienthello2->get_extensions().add(changed_mode_versions);
                auto changed_mode_groups = new tls_extension_supported_groups(changed_mode_clienthello2);
                changed_mode_groups->add("x25519");
                changed_mode_clienthello2->get_extensions().add(changed_mode_groups);
                auto changed_mode_key_share = new tls_extension_client_key_share(changed_mode_clienthello2);
                changed_mode_clienthello2->get_extensions().add(changed_mode_key_share);
                auto changed_mode_modes = new tls_extension_psk_key_exchange_modes(changed_mode_clienthello2);
                changed_mode_modes->add(0);
                changed_mode_clienthello2->get_extensions().add(changed_mode_modes);
                auto changed_mode_psk = new tls_extension_client_psk(changed_mode_clienthello2);
                changed_mode_clienthello2->get_extensions().add(changed_mode_psk);

                tls_record_handshake changed_mode_record(&changed_mode_client);
                changed_mode_record << changed_mode_clienthello2;
                binary_t changed_mode_clienthello2_wire;
                ret = changed_mode_record.write(from_client, changed_mode_clienthello2_wire);
                _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with a recomputed binder and changed PSK mode");
                if (errorcode_t::success == ret) {
                    tls_records changed_mode_records;
                    ret = changed_mode_records.read(&changed_mode_server, from_client, changed_mode_clienthello2_wire);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject ClientHello2 when psk_key_exchange_modes changes after HRR");
                    size_t illegal_parameter_count = 0;
                    changed_mode_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                            ++illegal_parameter_count;
                        }
                    });
                    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report fatal illegal_parameter for a changed ClientHello2 PSK mode offer");
                }
            }
        }
    }

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
        const auto& early_state = server.get_session_info(from_server).get_keyvalue();
        _test_case.assert(0 == early_state.get(session_early_data_offered), __FUNCTION__, "record that ClientHello2 did not re-offer early_data");
        _test_case.assert(1 == early_state.get(session_early_data_offered_initial), __FUNCTION__, "retain ClientHello1 early-data state for late in-flight records");
        _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__, "preserve the pre-ClientHello2 rejected-data skip count");
        _test_case.assert(32 == early_state.get(session_early_data_discard_limit), __FUNCTION__, "preserve the configured HRR rejected-data skip budget");
        tls_records early_data_after_clienthello2_records;
        return_t late_early_data_ret = early_data_after_clienthello2_records.read(&server, from_client, in_flight_early_data_record);
        _test_case.test(late_early_data_ret, __FUNCTION__, "skip a late ClientHello1 early-data record after ClientHello2");
        _test_case.assert(1 == early_data_after_clienthello2_records.size(), __FUNCTION__, "consume the late in-flight early-data record");
        _test_case.assert(32 == early_state.get(session_early_data_discarded), __FUNCTION__, "keep the HRR skip count cumulative across ClientHello2");
        _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "refresh the server's PSK identity count from ClientHello2");
        _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the HRR transcript flow after accepting the ClientHello2 PSK");
        _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "retain selected_identity zero for the final ServerHello");
        const binary_t& client_binder_hash = client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        const binary_t& server_binder_hash = server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        _test_case.assert(!client_binder_hash.empty() && client_binder_hash == server_binder_hash, __FUNCTION__,
                          "client and server derive the same binder transcript hash from the real HRR exchange");
    }

    // Exercise the final ServerHello while the resumption session marker is
    // still set. HRR nevertheless forbids 0-RTT, so the final PSK selection
    // must use the one_rtt flow while retaining the selected PSK early secret.
    server.get_keyvalue().set(session_handshake_finished, 1);
    client.get_keyvalue().set(session_handshake_finished, 1);

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
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                          "keep the post-HRR PSK handshake in one_rtt even when the resumption session marker is set");
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "retain one_rtt flow on the client while a PSK is selected");
    }
    if (errorcode_t::success == ret) {
        _test_case.assert(selected_server_hello_wire.size() == selected_server_hello_pos, __FUNCTION__, "consume the complete post-HRR ServerHello");
        _test_case.assert(tls_13 == client.get_tls_protection().get_tls_version(), __FUNCTION__, "retain TLS 1.3 after accepting the post-HRR PSK selection");
        binary_t client_shared_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
        _test_case.assert(!client_shared_secret.empty(), __FUNCTION__, "derive the client-side shared secret from the ServerHello key_share");
        _test_case.assert(server_shared_secret == client_shared_secret, __FUNCTION__, "derive matching DHE shared secrets after HRR PSK resumption");
        const binary_t& server_early_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::early_secret);
        const binary_t& server_resumption_early = server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early);
        const binary_t& client_early_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::early_secret);
        const binary_t& client_resumption_early = client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early);
        _test_case.assert(!server_resumption_early.empty() && server_early_secret == server_resumption_early, __FUNCTION__,
                          "use the selected PSK early secret for the server handshake even when the post-HRR flow is one_rtt");
        _test_case.assert(!client_resumption_early.empty() && client_early_secret == client_resumption_early, __FUNCTION__,
                          "use the selected PSK early secret for the client handshake even when the post-HRR flow is one_rtt");
    }

    // A server may decline PSK resumption in the final ServerHello after
    // HRR. The client must then use the zero-PSK early secret while preserving
    // the HRR transcript through ServerHello key-schedule processing.
    auto remove_server_hello_extension = [](binary_t& wire, uint16 extension_type) -> bool {
        if ((wire.size() < 44) || (wire[0] != static_cast<byte_t>(tls_handshake_type_t::server_hello))) {
            return false;
        }
        size_t pos = 4 + 2 + 32;
        uint8 session_id_length = wire[pos++];
        if (session_id_length > wire.size() - pos) {
            return false;
        }
        pos += session_id_length;
        if (wire.size() - pos < 5) {
            return false;
        }
        pos += 3;  // cipher_suite and legacy_compression_method
        uint16 extensions_length = (static_cast<uint16>(wire[pos]) << 8) | wire[pos + 1];
        size_t extensions_pos = pos + 2;
        if (extensions_length != wire.size() - extensions_pos) {
            return false;
        }
        size_t cursor = extensions_pos;
        while (cursor + 4 <= wire.size()) {
            uint16 type = (static_cast<uint16>(wire[cursor]) << 8) | wire[cursor + 1];
            uint16 length = (static_cast<uint16>(wire[cursor + 2]) << 8) | wire[cursor + 3];
            size_t extension_size = 4 + static_cast<size_t>(length);
            if (extension_size > wire.size() - cursor) {
                return false;
            }
            if (type == extension_type) {
                wire.erase(wire.begin() + cursor, wire.begin() + cursor + extension_size);
                uint16 updated_extensions_length = static_cast<uint16>(extensions_length - extension_size);
                wire[pos] = static_cast<byte_t>(updated_extensions_length >> 8);
                wire[pos + 1] = static_cast<byte_t>(updated_extensions_length);
                uint32 handshake_length = t_narrow_cast(wire.size() - 4);
                wire[1] = static_cast<byte_t>(handshake_length >> 16);
                wire[2] = static_cast<byte_t>(handshake_length >> 8);
                wire[3] = static_cast<byte_t>(handshake_length);
                return true;
            }
            cursor += extension_size;
        }
        return false;
    };

    tls_session declined_psk_client;
    configure_resumption(declined_psk_client);
    declined_psk_client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    declined_psk_client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

    // Rebuild ClientHello1 and ClientHello2 through the client writers rather
    // than parsing their wire bytes into a fresh session. Parsing an outbound
    // ClientHello restores the public key-share bytes, but cannot recreate the
    // private key generated by the original client for the final DHE step.
    auto declined_clienthello1 = new tls_handshake_client_hello(&declined_psk_client);
    declined_clienthello1->add_ciphersuite(0x1301);
    auto declined_versions1 = new tls_extension_client_supported_versions(declined_clienthello1);
    declined_versions1->add(tls_13);
    declined_clienthello1->get_extensions().add(declined_versions1);
    auto declined_groups1 = new tls_extension_supported_groups(declined_clienthello1);
    declined_groups1->add("x25519");
    declined_clienthello1->get_extensions().add(declined_groups1);
    auto declined_modes1 = new tls_extension_psk_key_exchange_modes(declined_clienthello1);
    declined_modes1->add(1);
    declined_clienthello1->get_extensions().add(declined_modes1);
    declined_clienthello1->get_extensions().add(new tls_extension_early_data(declined_clienthello1));
    declined_clienthello1->get_extensions().add(new tls_extension_client_psk(declined_clienthello1));
    tls_record_handshake declined_clienthello1_record(&declined_psk_client);
    declined_clienthello1_record << declined_clienthello1;
    binary_t declined_clienthello1_wire;
    ret = declined_clienthello1_record.write(from_client, declined_clienthello1_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a separate ClientHello1 for the post-HRR PSK-decline path");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records declined_hrr_records;
    ret = declined_hrr_records.read(&declined_psk_client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "process HRR before testing a declined final PSK selection");
    if (errorcode_t::success != ret) {
        return;
    }

    auto declined_clienthello2 = new tls_handshake_client_hello(&declined_psk_client);
    declined_clienthello2->add_ciphersuite(0x1301);
    auto declined_versions2 = new tls_extension_client_supported_versions(declined_clienthello2);
    declined_versions2->add(tls_13);
    declined_clienthello2->get_extensions().add(declined_versions2);
    auto declined_groups2 = new tls_extension_supported_groups(declined_clienthello2);
    declined_groups2->add("x25519");
    declined_clienthello2->get_extensions().add(declined_groups2);
    auto declined_key_share2 = new tls_extension_client_key_share(declined_clienthello2);
    declined_clienthello2->get_extensions().add(declined_key_share2);
    auto declined_modes2 = new tls_extension_psk_key_exchange_modes(declined_clienthello2);
    declined_modes2->add(1);
    declined_clienthello2->get_extensions().add(declined_modes2);
    declined_clienthello2->get_extensions().add(new tls_extension_client_psk(declined_clienthello2));
    uint16 declined_retry_group = t_narrow_cast(declined_psk_client.get_session_info(from_server).get_keyvalue().get(session_key_share_group));
    ret = declined_key_share2->add(static_cast<tls_group_t>(declined_retry_group));
    _test_case.test(ret, __FUNCTION__, "generate the independent ClientHello2 key share for the PSK-decline path");
    if (errorcode_t::success != ret) {
        return;
    }
    declined_key_share2->clear();
    tls_record_handshake declined_clienthello2_record(&declined_psk_client);
    declined_clienthello2_record << declined_clienthello2;
    binary_t declined_clienthello2_wire;
    ret = declined_clienthello2_record.write(from_client, declined_clienthello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with its own private key-share state");
    if (errorcode_t::success != ret) {
        return;
    }
    binary_t declined_server_hello_wire = selected_server_hello_wire;
    bool removed_selected_psk = remove_server_hello_extension(declined_server_hello_wire, static_cast<uint16>(tls_extension_type_t::pre_shared_key));
    _test_case.assert(removed_selected_psk, __FUNCTION__, "remove pre_shared_key to model a final ServerHello that declines resumption");
    if (removed_selected_psk) {
        tls_handshake_server_hello declined_server_hello_reader(&declined_psk_client);
        size_t declined_server_hello_pos = 0;
        ret = declined_server_hello_reader.read(from_server, declined_server_hello_wire.data(), declined_server_hello_wire.size(), declined_server_hello_pos);
        _test_case.test(ret, __FUNCTION__, "accept a final post-HRR ServerHello that declines PSK resumption");
        if (errorcode_t::success == ret) {
            _test_case.assert(tls_flow_t::one_rtt == declined_psk_client.get_tls_protection().get_flow(), __FUNCTION__,
                              "switch to one_rtt after a post-HRR ServerHello declines PSK");
            _test_case.assert(0xffff == declined_psk_client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "retain the no-selected-identity sentinel after PSK decline");
            _test_case.assert(declined_psk_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                              "discard the offered PSK early secret when the final ServerHello declines resumption");
            _test_case.assert(false == declined_psk_client.get_tls_protection().get_secrets().get(tls_secret_t::early_secret).empty(), __FUNCTION__,
                              "derive the zero-PSK early secret for the full handshake after HRR");
        }
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

static void test_tls13_hrr_rejects_psk_with_incompatible_hash() {
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
}

static void test_tls13_server_rejects_unoffered_psk_mode() {
    _test_case.begin("TLS 1.3 server does not serialize an unoffered PSK selection");

    auto assert_rejected = [&](uint8 offered_modes, bool include_key_share, uint16 selected_identity, bool include_server_modes_extension, bool hello_retry_request,
                               const char* description) {
        tls_session server;
        server.set_type(session_type_t::tls);
        auto& protection = server.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        server.update_session_status(session_status_client_hello);
        server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        auto& kv = server.get_keyvalue();
        kv.set(session_client_psk_identity_count, 1);
        kv.set(session_client_psk_modes_present, 1);
        kv.set(session_client_psk_modes, offered_modes);

        auto server_hello = new tls_handshake_server_hello(&server);
        server_hello->set_cipher_suite(0x1301);
        if (hello_retry_request) {
            const binary_t hrr_random = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                         0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
            server_hello->set_random(hrr_random);
        }
        auto versions = new tls_extension_server_supported_versions(server_hello);
        versions->set(tls_13);
        server_hello->get_extensions().add(versions);

        auto psk = new tls_extension_server_psk(server_hello);
        psk->set_selected_identity(selected_identity);
        server_hello->get_extensions().add(psk);

        if (include_key_share) {
            server_hello->get_extensions().add(new tls_extension_server_key_share(server_hello));
        }
        if (include_server_modes_extension) {
            auto modes = new tls_extension_psk_key_exchange_modes(server_hello);
            modes->add(0);
            server_hello->get_extensions().add(modes);
        }

        tls_record_handshake record(&server);
        record << server_hello;
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, description);
        _test_case.assert(wire.empty(), __FUNCTION__, "do not emit a ServerHello with an invalid PSK selection");
    };

    assert_rejected(0x01, true, 0, false, false, "reject psk_dhe_ke when the ClientHello offered only psk_ke");
    assert_rejected(0x02, false, 0, false, false, "reject psk_ke when the ClientHello offered only psk_dhe_ke");
    assert_rejected(0x04, true, 0, false, false, "reject PSK selection when the ClientHello offered only an unknown mode");
    assert_rejected(0x01, false, 1, false, false, "reject a server selected_identity outside the ClientHello identity list");
    assert_rejected(0x01, false, 0, true, false, "reject the ClientHello-only psk_key_exchange_modes extension in ServerHello");
    assert_rejected(0x01, false, 0, false, true, "reject a PSK selection in HelloRetryRequest");
}

void testcase_gpt_psk() {
    test_tls13_server_rejects_unoffered_psk_mode();
    test_tls13_server_client_ticket_psk_roundtrip();
    test_tls13_ticket_nonce_resumption_psk();
    test_tls13_psk_binder_rfc8448_vector();
    test_tls13_psk_binder_hrr_transcript();
    test_tls13_client_psk_binder_roundtrip();
    test_tls13_clienthello2_psk_binder_hrr_roundtrip();
    test_tls13_hrr_rejects_psk_with_incompatible_hash();
}
