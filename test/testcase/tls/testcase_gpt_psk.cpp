/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk.cpp
 * @author GPT
 * @desc   TLS 1.3 PSK ticket derivation, selection, key schedule, and extension tests.
 */

#include <algorithm>
#include <chrono>
#include <utility>

#include "testcase_gpt_common.hpp"

struct tls13_server_client_ticket_psk_context {
    tls_session server;
    tls_session client;
    std::vector<tls_resumption_ticket> server_tickets;
    std::vector<tls_resumption_ticket> client_tickets;
    binary_t empty_hash;
};

static bool test_tls13_ticket_psk_issue_and_first_identity_resumption(const char* function_name, tls13_server_client_ticket_psk_context& context) {
    // Scenario under test: TLS 1.3 server-issued ticket PSKs are identical on the client and server.
    // Action: issue two tickets, compare their derived PSKs, and resume a fresh connection with the first identity.
    // Expected: preserve active early secrets and restore the selected ticket's PSK on the new server connection.
    auto& server = context.server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls1_3);
    server_protection.set_cipher_suite(0x1301);
    server_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t server_active_early_secret(32, 0xa5);
    server_protection.get_secrets().assign(tls_secret_t::resumption_early, server_active_early_secret);

    auto& client = context.client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls1_3);
    client_protection.set_cipher_suite(0x1301);
    client_protection.get_secrets().assign(tls_secret_t::res_master, binary_t(32, 0x11));
    const binary_t client_active_early_secret(32, 0x5a);
    client_protection.get_secrets().assign(tls_secret_t::resumption_early, client_active_early_secret);

    for (size_t i = 0; i < 2; ++i) {
        tls_handshake_new_session_ticket issued(&server);
        binary_t wire;
        return_t ret = issued.write(from_server, wire);
        _test_case.test(ret, function_name, "server issues another NewSessionTicket");
        if (errorcode_t::success != ret) {
            continue;
        }

        tls_handshake_new_session_ticket received(&client);
        size_t pos = 0;
        ret = received.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "client receives the server-issued NewSessionTicket");
        if (errorcode_t::success != ret) {
            continue;
        }
        _test_case.assert(wire.size() == pos, function_name, "consume the complete server-issued NewSessionTicket");
    }

    context.server_tickets = server.get_resumption_tickets();
    auto& server_tickets = context.server_tickets;
    context.client_tickets = client.get_resumption_tickets();
    auto& client_tickets = context.client_tickets;
    _test_case.assert(2 == server_tickets.size(), function_name, "server retains both independently issued tickets");
    _test_case.assert(2 == client_tickets.size(), function_name, "client caches both received tickets independently");
    _test_case.assert(server_active_early_secret == server_protection.get_secrets().get(tls_secret_t::resumption_early), function_name,
                      "issuing tickets does not overwrite the server's active early secret");
    _test_case.assert(client_active_early_secret == client_protection.get_secrets().get(tls_secret_t::resumption_early), function_name,
                      "receiving tickets does not overwrite the client's active early secret");

    for (const auto& server_ticket : server_tickets) {
        tls_resumption_ticket client_ticket;
        bool found = client.find_resumption_ticket(server_ticket.identity, client_ticket);
        _test_case.assert(found, function_name, "client retains the identity issued by the server");
        if (found) {
            _test_case.assert(server_ticket.nonce == client_ticket.nonce, function_name, "server and client associate the same nonce with a ticket");
            _test_case.assert(server_ticket.psk == client_ticket.psk, function_name, "server and client derive exactly the same RFC 8446 resumption PSK");
            _test_case.assert(server_ticket.psk.size() == 32, function_name, "TLS_AES_128_GCM_SHA256 ticket PSK has a 32-byte hash length");
        }
    }

    // Model a new connection on both endpoints. The client restores its
    // cached tickets, while the server restores its independently retained
    // ticket records into a fresh tls_session before validating the binder.
    tls_session resumed_client;
    resumed_client.set_type(session_type_t::tls);
    auto& resumed_client_protection = resumed_client.get_tls_protection();
    resumed_client_protection.set_tls_version(tls1_3);
    resumed_client_protection.set_cipher_suite(0x1301);
    resumed_client.get_keyvalue().set(session_tls_version, tls1_3);
    _test_case.assert(0 == resumed_client.get_session_status(), function_name, "begin first-identity client resumption with a fresh session status");
    for (const auto& ticket : client_tickets) {
        resumed_client.store_resumption_ticket(ticket);
    }

    openssl_digest digest;
    binary_t empty;
    auto& empty_hash = context.empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, function_name, "prepare the empty transcript hash for a fresh-connection PSK binder");
    if (errorcode_t::success != ret) {
        return false;
    }
    resumed_client_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    auto resumed_client_hello = new tls_handshake_client_hello(&resumed_client);
    resumed_client_hello->add_ciphersuite(0x1301);
    auto resumed_supported_versions = new tls_extension_client_supported_versions(resumed_client_hello);
    resumed_supported_versions->add(tls1_3);
    resumed_client_hello->get_extensions().add(resumed_supported_versions);
    auto resumed_psk_modes = new tls_extension_psk_key_exchange_modes(resumed_client_hello);
    resumed_psk_modes->add(1);  // psk_dhe_ke
    resumed_client_hello->get_extensions().add(resumed_psk_modes);
    resumed_client_hello->get_extensions().add(new tls_extension_client_psk(resumed_client_hello));

    tls_record_handshake resumed_client_hello_record(&resumed_client);
    resumed_client_hello_record << resumed_client_hello;
    binary_t resumed_client_hello_wire;
    ret = resumed_client_hello_record.write(from_client, resumed_client_hello_wire);
    _test_case.test(ret, function_name, "serialize a PSK ClientHello from a fresh client connection using restored ticket records");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_session resumed_server;
    resumed_server.set_type(session_type_t::tls);
    auto& resumed_server_protection = resumed_server.get_tls_protection();
    resumed_server_protection.set_tls_version(tls1_3);
    resumed_server_protection.set_cipher_suite(0x1301);
    resumed_server_protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
    resumed_server.get_keyvalue().set(session_tls_version, tls1_3);
    _test_case.assert(0 == resumed_server.get_session_status(), function_name, "begin first-identity server resumption with a fresh session status");
    for (const auto& ticket : server_tickets) {
        resumed_server.store_resumption_ticket(ticket);
    }

    tls_records resumed_server_records;
    ret = resumed_server_records.read(&resumed_server, from_client, resumed_client_hello_wire);
    _test_case.test(ret, function_name, "validate a fresh-connection ClientHello binder using restored server ticket records");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::zero_rtt == resumed_server_protection.get_flow(), function_name,
                          "resume on a new server connection without relying on the issuing tls_session");
        _test_case.assert(0 == resumed_server.get_keyvalue().get(session_server_psk_selected_identity), function_name, "select the first restored ticket identity");
        _test_case.assert(0x1301 == resumed_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), function_name,
                          "retain the original cipher suite metadata from the restored ticket");
        _test_case.assert(resumed_server.get_resumption_tickets().size() == server_tickets.size(), function_name,
                          "keep the restored per-ticket server records available on the new connection");
        const auto& selected_ticket = server_tickets.front();
        binary_t expected_early_secret;
        ret = resumed_server_protection.calc_resumption_early_secret(selected_ticket.psk, expected_early_secret);
        _test_case.test(ret, function_name, "derive the expected early secret from the selected ticket PSK");
        if (errorcode_t::success == ret) {
            _test_case.assert(expected_early_secret == resumed_server_protection.get_secrets().get(tls_secret_t::resumption_early), function_name,
                              "derive the active early secret from the selected ticket rather than stale session state");
        }
    }

    return true;
}

static bool test_tls13_ticket_psk_second_identity_early_data_rejection(const char* function_name, tls13_server_client_ticket_psk_context& context) {
    return_t ret = errorcode_t::success;
    // Scenario under test: TLS 1.3 resumption selects the second cached PSK identity.
    // Action: offer both tickets with early_data while the server restores only identity one.
    // Expected: select identity one, reject 0-RTT, and account for discarded ciphertext.
    // Exercise the second cached ticket as selected_identity=1. The server
    // restores only that ticket, so the first offered identity is unknown.
    if ((context.server_tickets.size() < 2) || (context.client_tickets.size() < 2)) {
        _test_case.assert(false, function_name, "prepare two independently retained tickets for second-identity resumption");
        return false;
    }

    tls_session resumed_client_second;
    resumed_client_second.set_type(session_type_t::tls);
    auto& resumed_client_second_protection = resumed_client_second.get_tls_protection();
    resumed_client_second_protection.set_tls_version(tls1_3);
    resumed_client_second_protection.set_cipher_suite(0x1301);
    resumed_client_second.get_keyvalue().set(session_tls_version, tls1_3);
    _test_case.assert(0 == resumed_client_second.get_session_status(), function_name, "begin second-identity client resumption with a fresh session status");
    auto early_data_tickets = context.client_tickets;
    early_data_tickets.front().max_early_data_size = 4096;
    for (const auto& ticket : early_data_tickets) {
        resumed_client_second.store_resumption_ticket(ticket);
    }
    resumed_client_second_protection.get_secrets().assign(tls_secret_t::empty_hash, context.empty_hash);

    auto resumed_client_hello_second = new tls_handshake_client_hello(&resumed_client_second);
    resumed_client_hello_second->add_ciphersuite(0x1301);
    auto resumed_supported_versions_second = new tls_extension_client_supported_versions(resumed_client_hello_second);
    resumed_supported_versions_second->add(tls1_3);
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
    _test_case.test(ret, function_name, "serialize a ClientHello offering both restored tickets in their cached order");
    if (errorcode_t::success != ret) {
        return false;
    }

    tls_session resumed_server_second;
    resumed_server_second.set_type(session_type_t::tls);
    auto& resumed_server_second_protection = resumed_server_second.get_tls_protection();
    resumed_server_second_protection.set_tls_version(tls1_3);
    resumed_server_second_protection.set_cipher_suite(0x1301);
    resumed_server_second_protection.get_secrets().assign(tls_secret_t::empty_hash, context.empty_hash);
    resumed_server_second.get_keyvalue().set(session_tls_version, tls1_3);
    _test_case.assert(0 == resumed_server_second.get_session_status(), function_name, "begin second-identity server resumption with a fresh session status");
    resumed_server_second.set_early_data_discard_limit(4096);
    resumed_server_second.store_resumption_ticket(context.server_tickets[1]);

    tls_records resumed_server_records_second;
    ret = resumed_server_records_second.read(&resumed_server_second, from_client, resumed_client_hello_wire_second);
    _test_case.test(ret, function_name, "validate the second offered ticket binder using its independently restored server record");
    if (errorcode_t::success == ret) {
        auto& rejected_early_state = resumed_server_second.get_session_info(from_server).get_keyvalue();
        _test_case.assert(1 == rejected_early_state.get(session_early_data_offered), function_name, "retain the early_data offer when identity zero is unknown");
        _test_case.assert(0 == rejected_early_state.get(session_early_data_limit), function_name, "do not accept early data when the server selects identity one");
        _test_case.assert(4096 == rejected_early_state.get(session_early_data_discard_limit), function_name,
                          "use the configured rejection skip limit when identity zero has no cached ticket");

        binary_t rejected_early_record{0x17, 0x03, 0x03, 0x00, 0x10};
        rejected_early_record.insert(rejected_early_record.end(), 16, 0xaa);
        tls_records rejected_early_records;
        return_t rejected_early_ret = rejected_early_records.read(&resumed_server_second, from_client, rejected_early_record);
        _test_case.test(rejected_early_ret, function_name, "skip rejected 0-RTT records when identity zero is unknown");
        _test_case.assert(1 == rejected_early_records.size(), function_name, "consume the rejected 0-RTT record without delivery");
        if (rejected_early_records.size()) {
            auto decoded = static_cast<tls_record_application_data*>(rejected_early_records.getat(0));
            _test_case.assert(decoded->get_binary().empty(), function_name, "do not expose rejected 0-RTT plaintext to the application");
        }
        _test_case.assert(16 == rejected_early_state.get(session_early_data_discarded), function_name,
                          "account the skipped ciphertext against the configured rejection bound");

        _test_case.assert(tls_flow_t::zero_rtt == resumed_server_second_protection.get_flow(), function_name,
                          "resume with the second cached ticket on a fresh server connection");
        _test_case.assert(1 == resumed_server_second.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                          "select the second offered ticket identity");
        _test_case.assert(0x1301 == resumed_server_second.get_keyvalue().get(session_server_psk_ticket_cipher_suite), function_name,
                          "retain the second ticket's original cipher suite metadata");
        binary_t expected_second_early_secret;
        ret = resumed_server_second_protection.calc_resumption_early_secret(context.server_tickets[1].psk, expected_second_early_secret);
        _test_case.test(ret, function_name, "derive the expected early secret from the second ticket PSK");
        if (errorcode_t::success == ret) {
            _test_case.assert(expected_second_early_secret == resumed_server_second_protection.get_secrets().get(tls_secret_t::resumption_early), function_name,
                              "derive the active early secret from the second selected ticket");
        }
    }

    return true;
}

static bool test_tls13_ticket_psk_store_backed_early_data_decline(const char* function_name, tls13_server_client_ticket_psk_context& context) {
    // Scenario under test: a valid store-backed early-data ticket is declined by the final full-handshake ServerHello.
    // Action: validate identity zero and early_data, then send a ServerHello without pre_shared_key and deliver an in-flight 0-RTT record.
    // Expected: clear the provisional PSK, discard delayed early data, and keep the client on the full-handshake path.
    return_t ret = errorcode_t::success;
    // Identity zero is backed by a real restored ticket-store entry here.
    // The server can therefore calculate the ticket's early-data allowance,
    // but a later full-handshake ServerHello must still reject 0-RTT when it
    // omits pre_shared_key.
    {
        tls_resumption_ticket client_ticket = context.client_tickets.front();
        tls_resumption_ticket server_ticket = context.server_tickets.front();
        client_ticket.max_early_data_size = 4096;
        server_ticket.max_early_data_size = 4096;

        auto prepare_resumption_session = [&](tls_session& session) {
            session.set_type(session_type_t::tls);
            auto& protection = session.get_tls_protection();
            protection.set_tls_version(tls1_3);
            protection.set_cipher_suite(0x1301);
            session.get_keyvalue().set(session_tls_version, tls1_3);
            _test_case.assert(0 == session.get_session_status(), function_name, "begin store-backed ticket resumption with a fresh session status");
        };

        tls_session early_client;
        prepare_resumption_session(early_client);
        early_client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        early_client.store_resumption_ticket(client_ticket);
        early_client.get_tls_protection().get_secrets().assign(tls_secret_t::empty_hash, context.empty_hash);

        auto early_client_hello = new tls_handshake_client_hello(&early_client);
        early_client_hello->add_ciphersuite(0x1301);
        auto early_versions = new tls_extension_client_supported_versions(early_client_hello);
        early_versions->add(tls1_3);
        early_client_hello->get_extensions().add(early_versions);
        auto early_groups = new tls_extension_supported_groups(early_client_hello);
        early_groups->add("x25519");
        early_client_hello->get_extensions().add(early_groups);
        auto early_key_share = new tls_extension_client_key_share(early_client_hello);
        early_client_hello->get_extensions().add(early_key_share);
        auto early_tlsadvisor = tls_advisor::get_instance();
        ret = early_key_share->add(static_cast<tls_group_t>(early_tlsadvisor->valueof_group("x25519")));
        _test_case.test(ret, function_name, "create a DHE share for the store-backed early-data offer");
        if (errorcode_t::success == ret) {
            auto early_modes = new tls_extension_psk_key_exchange_modes(early_client_hello);
            early_modes->add(1);  // psk_dhe_ke
            early_client_hello->get_extensions().add(early_modes);
            early_client_hello->get_extensions().add(new tls_extension_early_data(early_client_hello));
            early_client_hello->get_extensions().add(new tls_extension_client_psk(early_client_hello));

            tls_record_handshake early_client_hello_record(&early_client);
            early_client_hello_record << early_client_hello;
            binary_t early_client_hello_wire;
            ret = early_client_hello_record.write(from_client, early_client_hello_wire);
            _test_case.test(ret, function_name, "serialize ClientHello with a store-backed PSK and early_data offer");
            if (errorcode_t::success == ret) {
                // Capture a genuine 0-RTT record before the server's final
                // ServerHello, then deliver it only after the server declines
                // the otherwise eligible PSK.
                binary_t in_flight_early_data_wire;
                tls_record_application_data in_flight_early_data(&early_client, "pending-early-data");
                ret = in_flight_early_data.write(from_client, in_flight_early_data_wire);
                _test_case.test(ret, function_name, "write a genuine 0-RTT application-data record before ServerHello");
                if (errorcode_t::success != ret) {
                    return false;
                }

                tls_session early_server;
                prepare_resumption_session(early_server);
                early_server.get_tls_protection().get_secrets().assign(tls_secret_t::empty_hash, context.empty_hash);
                early_server.store_resumption_ticket(server_ticket);
                early_server.set_early_data_discard_limit(4096);

                tls_records early_client_hello_records;
                ret = early_client_hello_records.read(&early_server, from_client, early_client_hello_wire);
                _test_case.test(ret, function_name, "validate identity-zero binder against the restored server ticket");
                if (errorcode_t::success == ret) {
                    auto& early_server_protection = early_server.get_tls_protection();
                    auto& early_state = early_server.get_session_info(from_server).get_keyvalue();
                    _test_case.assert(1 == early_state.get(session_early_data_offered), function_name, "record the store-backed early_data offer");
                    _test_case.assert(4096 == early_state.get(session_early_data_limit), function_name,
                                      "recognize the matching identity-zero ticket's early-data allowance");
                    _test_case.assert(0 == early_state.get(session_early_data_accepted), function_name, "keep early data provisional until EncryptedExtensions");

                    auto early_server_hello = new tls_handshake_server_hello(&early_server);
                    ret = early_server_hello->set_cipher_suite(0x1301);
                    _test_case.test(ret, function_name, "select TLS_AES_128_GCM_SHA256 for the full handshake");
                    if (errorcode_t::success == ret) {
                        auto early_server_versions = new tls_extension_server_supported_versions(early_server_hello);
                        early_server_versions->set(tls1_3);
                        early_server_hello->get_extensions().add(early_server_versions);
                        auto early_server_key_share = new tls_extension_server_key_share(early_server_hello);
                        ret = early_server_key_share->add_keyshare();
                        _test_case.test(ret, function_name, "create the server DHE share for the non-PSK handshake");
                        if (errorcode_t::success == ret) {
                            early_server_hello->get_extensions().add(early_server_key_share);
                            binary_t early_server_hello_wire;
                            tls_record_handshake early_server_hello_record(&early_server);
                            early_server_hello_record << early_server_hello;
                            ret = early_server_hello_record.write(from_server, early_server_hello_wire);
                            _test_case.test(ret, function_name, "write a full-handshake ServerHello despite the valid PSK candidate");
                            if (errorcode_t::success == ret) {
                                _test_case.assert(0xffff == early_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                  "clear the provisional identity when the valid ticket PSK is declined");
                                _test_case.assert(tls_flow_t::one_rtt == early_server_protection.get_flow(), function_name,
                                                  "leave zero_rtt after declining the store-backed PSK");
                                _test_case.assert(0 == early_state.get(session_early_data_accepted), function_name,
                                                  "never accept early data when the final ServerHello omits pre_shared_key");
                                _test_case.assert(early_server_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                                  "discard the store-backed PSK before the full-handshake key schedule");

                                // Once ServerHello has selected the full
                                // handshake, a delayed 0-RTT record must be
                                // trial-decrypted with handshake keys and
                                // discarded on authentication failure.
                                tls_records rejected_after_server_hello_records;
                                return_t rejected_after_server_hello_ret =
                                    rejected_after_server_hello_records.read(&early_server, from_client, in_flight_early_data_wire);
                                _test_case.test(rejected_after_server_hello_ret, function_name, "discard an in-flight 0-RTT record received after PSK decline");
                                _test_case.assert(1 == rejected_after_server_hello_records.size(), function_name, "consume the delayed rejected 0-RTT record");
                                if (rejected_after_server_hello_records.size()) {
                                    auto decoded = static_cast<tls_record_application_data*>(rejected_after_server_hello_records.getat(0));
                                    _test_case.assert(decoded->get_binary().empty(), function_name, "never expose rejected 0-RTT plaintext after ServerHello");
                                }
                                _test_case.assert(in_flight_early_data_wire.size() - 5 == early_state.get(session_early_data_discarded), function_name,
                                                  "account the rejected ciphertext against the independent discard budget");
                                _test_case.assert(0 == early_state.get(session_early_data_accepted), function_name,
                                                  "keep early data rejected after discarding the in-flight record");

                                tls_records early_server_hello_records;
                                ret = early_server_hello_records.read(&early_client, from_server, early_server_hello_wire);
                                _test_case.test(ret, function_name, "client processes the ServerHello that declines its store-backed ticket");
                                if (errorcode_t::success == ret) {
                                    _test_case.assert(tls_flow_t::one_rtt == early_client.get_tls_protection().get_flow(), function_name,
                                                      "client leaves zero_rtt when the server declines the valid ticket");
                                    _test_case.assert(early_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                                      "client discards the declined store-backed PSK");
                                }
                            }
                        }
                    }
                    // The record owns the ServerHello after operator<<.
                }
            }
        }
    }

    return true;
}

static void test_tls13_ticket_psk_zero_lifetime_discard_preserves_metadata(const char* function_name, tls13_server_client_ticket_psk_context& context) {
    // Scenario under test: zero-lifetime NewSessionTicket is discarded independently of other cached tickets.
    // Action: receive a zero-lifetime ticket with a different identity after usable tickets are cached.
    // Expected: discard only the zero-lifetime ticket and preserve the latest usable ticket metadata.
    auto& server = context.server;
    auto& client = context.client;
    auto& client_protection = client.get_tls_protection();
    return_t ret = errorcode_t::success;
    // A zero-lifetime ticket with a different identity is discarded, but
    // must not clear the compatibility metadata for the latest usable ticket.
    tls_handshake_new_session_ticket zero_lifetime_issued(&server);
    binary_t zero_lifetime_wire;
    ret = zero_lifetime_issued.write(from_server, zero_lifetime_wire);
    _test_case.test(ret, function_name, "issue a ticket that will be changed to zero lifetime for the discard-path test");
    if (errorcode_t::success == ret && zero_lifetime_wire.size() >= 8) {
        zero_lifetime_wire[4] = 0;
        zero_lifetime_wire[5] = 0;
        zero_lifetime_wire[6] = 0;
        zero_lifetime_wire[7] = 0;

        const auto latest_ticket_before_discard = context.client_tickets.back();
        auto& client_ticket_kv = client.get_session_info(from_server).get_keyvalue();
        tls_handshake_new_session_ticket zero_lifetime_received(&client);
        size_t zero_lifetime_pos = 0;
        ret = zero_lifetime_received.read(from_server, zero_lifetime_wire.data(), zero_lifetime_wire.size(), zero_lifetime_pos);
        _test_case.test(ret, function_name, "discard a zero-lifetime ticket without disturbing other cached tickets");
        if (errorcode_t::success == ret) {
            _test_case.assert(2 == client.get_resumption_tickets().size(), function_name, "do not retain the zero-lifetime ticket or remove unrelated cached tickets");
            _test_case.assert(latest_ticket_before_discard.identity == client_protection.get_secrets().get(tls_secret_t::new_session_ticket), function_name,
                              "preserve the latest usable ticket identity when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.lifetime == client_ticket_kv.get(session_ticket_lifetime), function_name,
                              "preserve the latest usable ticket lifetime when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.age_add == client_ticket_kv.get(session_ticket_age_add), function_name,
                              "preserve the latest usable ticket age_add when discarding an unrelated ticket");
            _test_case.assert(latest_ticket_before_discard.timestamp == client_ticket_kv.get(session_ticket_timestamp), function_name,
                              "preserve the latest usable ticket timestamp when discarding an unrelated ticket");
        }
    } else if (errorcode_t::success == ret) {
        _test_case.assert(false, function_name, "serialize a complete ticket before testing zero-lifetime discard");
    }
}

static void test_tls13_server_client_ticket_psk_roundtrip() {
    // Scenario under test: TLS 1.3 server-issued tickets derive identical per-ticket PSKs on the client.
    // Action: issue tickets, resume with different identities, and exercise early-data acceptance and decline.
    // Expected: preserve ticket isolation, select the matching PSK, and enforce early-data limits.
    _test_case.begin("TLS 1.3 server-issued tickets derive identical per-ticket PSKs on the client");

    tls13_server_client_ticket_psk_context context;
    if (false == test_tls13_ticket_psk_issue_and_first_identity_resumption(__FUNCTION__, context)) {
        return;
    }
    if (false == test_tls13_ticket_psk_second_identity_early_data_rejection(__FUNCTION__, context)) {
        return;
    }
    if (false == test_tls13_ticket_psk_store_backed_early_data_decline(__FUNCTION__, context)) {
        return;
    }
    test_tls13_ticket_psk_zero_lifetime_discard_preserves_metadata(__FUNCTION__, context);
}

static void test_tls13_ticket_nonce_resumption_psk() {
    // Scenario under test: TLS 1.3 ticket nonce resumption PSK derivation.
    // Action: derive ticket PSK using first ticket nonce.
    // Expected: match the RFC 8446 HKDF-Expand-Label ticket PSK known-answer value.
    _test_case.begin("TLS 1.3 ticket nonce resumption PSK derivation");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
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
        sha384_client_protection.set_tls_version(tls1_3);
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

static void test_tls13_client_suppresses_unusable_initial_psk_offer() {
    // Scenario under test: TLS 1.3 client suppresses an unusable initial PSK offer.
    // Action: omit PSK when no cached identity is usable in the initial ClientHello.
    // Expected: record zero PSK identities when the initial PSK extension is suppressed.
    _test_case.begin("TLS 1.3 client suppresses an unusable initial PSK offer");

    const uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    struct test_case {
        uint16 ticket_suite;
        uint64 ticket_age_ms;
        const char* description;
    };
    const std::array<test_case, 2> cases = {
        {{0x1301, 8ULL * 24 * 60 * 60 * 1000, "expired cached ticket"}, {0x1302, 25, "ticket whose hash is not offered by ClientHello"}}};

    for (const auto& item : cases) {
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

        tls_resumption_ticket ticket;
        ticket.identity = binary_t{0x51, 0x52, 0x53};
        ticket.psk = binary_t((0x1302 == item.ticket_suite) ? 48 : 32, 0x5a);
        ticket.cipher_suite = item.ticket_suite;
        ticket.lifetime = 3600;
        ticket.timestamp = now_ms - item.ticket_age_ms;
        ticket.age_add = 0x10203040;
        client.store_resumption_ticket(ticket);

        auto hello = new tls_handshake_client_hello(&client);
        hello->add_ciphersuite(0x1301);
        auto versions = new tls_extension_client_supported_versions(hello);
        versions->add(tls1_3);
        hello->get_extensions().add(versions);
        auto modes = new tls_extension_psk_key_exchange_modes(hello);
        modes->add(1);  // psk_dhe_ke
        hello->get_extensions().add(modes);
        hello->get_extensions().add(new tls_extension_early_data(hello));
        auto psk = new tls_extension_client_psk(hello);
        hello->get_extensions().add(psk);

        tls_record_handshake record(&client);
        record << hello;
        binary_t wire;
        return_t ret = record.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, item.description);
        if (errorcode_t::success != ret) {
            continue;
        }

        _test_case.assert(psk->is_suppressed(), __FUNCTION__, "omit PSK when no cached identity is usable in the initial ClientHello");
        _test_case.assert(0 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                          "record zero PSK identities when the initial PSK extension is suppressed");
        _test_case.assert(client.get_offered_resumption_tickets().empty(), __FUNCTION__, "do not retain a ticket offer snapshot when no PSK identity was serialized");
        _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__,
                          "continue with the full-handshake flow after suppressing the unusable initial PSK offer");
    }
}

static void test_tls13_server_rejects_unoffered_psk_modes_on_write(const char* function_name) {
    // Scenario under test: TLS 1.3 server-side PSK selection must match the ClientHello offer.
    // Action: attempt ServerHello and HelloRetryRequest serialization with unsupported modes, identity, or extension combinations.
    // Expected: reject every unoffered or invalid PSK selection without emitting ServerHello.
    auto assert_rejected = [&](uint8 offered_modes, bool include_key_share, uint16 selected_identity, bool include_server_modes_extension, bool hello_retry_request,
                               const char* description) {
        tls_session server;
        server.set_type(session_type_t::tls);
        auto& protection = server.get_tls_protection();
        protection.set_tls_version(tls1_3);
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
        versions->set(tls1_3);
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
        _test_case.assert(errorcode_t::bad_request == ret, function_name, description);
        _test_case.assert(wire.empty(), function_name, "do not emit a ServerHello with an invalid PSK selection");
    };

    assert_rejected(0x01, true, 0, false, false, "reject psk_dhe_ke when the ClientHello offered only psk_ke");
    assert_rejected(0x02, false, 0, false, false, "reject psk_ke when the ClientHello offered only psk_dhe_ke");
    assert_rejected(0x04, true, 0, false, false, "reject PSK selection when the ClientHello offered only an unknown mode");
    assert_rejected(0x01, false, 1, false, false, "reject a server selected_identity outside the ClientHello identity list");
    assert_rejected(0x01, false, 0, true, false, "reject the ClientHello-only psk_key_exchange_modes extension in ServerHello");
    assert_rejected(0x01, false, 0, false, true, "reject a PSK selection in HelloRetryRequest");
}

static void test_tls13_server_rejects_mismatched_selected_psk_identity(const char* function_name) {
    // Scenario under test: TLS 1.3 ServerHello selected_identity must match the validated binder identity.
    // Action: configure an in-range but different selected_identity than the identity whose binder was validated.
    // Expected: reject the mismatch and emit no ServerHello.
    // The server may only select the identity whose binder it actually
    // validated. An in-range but different identity would make the peer and
    // server derive the handshake keys from different PSKs.
    {
        tls_session mismatched_server;
        mismatched_server.set_type(session_type_t::tls);
        auto& protection = mismatched_server.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        mismatched_server.update_session_status(session_status_client_hello);
        mismatched_server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        auto& kv = mismatched_server.get_keyvalue();
        kv.set(session_client_psk_identity_count, 2);
        kv.set(session_client_psk_modes_present, 1);
        kv.set(session_client_psk_modes, 0x01);           // psk_ke
        kv.set(session_server_psk_selected_identity, 1);  // binder validated identity one

        auto server_hello = new tls_handshake_server_hello(&mismatched_server);
        server_hello->set_cipher_suite(0x1301);
        auto versions = new tls_extension_server_supported_versions(server_hello);
        versions->set(tls1_3);
        server_hello->get_extensions().add(versions);
        auto psk = new tls_extension_server_psk(server_hello);
        psk->set_selected_identity(0);  // in range, but not the validated identity
        server_hello->get_extensions().add(psk);

        tls_record_handshake record(&mismatched_server);
        record << server_hello;
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::bad_request == ret, function_name, "reject an in-range ServerHello identity different from the validated PSK binder");
        _test_case.assert(wire.empty(), function_name, "do not emit a ServerHello that selects a different PSK than the validated binder");
    }
}

static void test_tls13_rejects_server_sent_psk_modes_extension(const char* function_name) {
    // Scenario under test: psk_key_exchange_modes is ClientHello-only.
    // Action: parse psk_key_exchange_modes from a server-originated ServerHello.
    // Expected: reject the extension with fatal illegal_parameter.
    // The extension is ClientHello-only. Verify the receive-side guard as
    // well as the server writer checks above: a peer must not send it in
    // ServerHello, even when no PSK selection is present.
    {
        tls_session client;
        client.set_type(session_type_t::tls);
        tls_handshake_server_hello server_hello(&client);
        tls_extension_psk_key_exchange_modes invalid_modes(&server_hello);
        const binary_t invalid_server_modes_wire{0x00, 0x2d, 0x00, 0x02, 0x01, 0x00};
        size_t invalid_server_modes_pos = 0;
        return_t ret = invalid_modes.read(from_server, invalid_server_modes_wire.data(), invalid_server_modes_wire.size(), invalid_server_modes_pos);
        _test_case.assert(errorcode_t::bad_format == ret, function_name, "reject psk_key_exchange_modes received in ServerHello");
        size_t illegal_parameter_count = 0;
        illegal_parameter_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, function_name, "report fatal illegal_parameter for a server-sent psk_key_exchange_modes extension");
    }
}

static void test_tls13_client_rejects_invalid_server_psk_selection(const char* function_name) {
    // Scenario under test: TLS 1.3 client validates the server's PSK selection independently.
    // Action: parse ServerHello with unsupported mode, out-of-range identity, or mismatched PSK hash.
    // Expected: reject the peer selection and leave selected identity and key-exchange mode uncommitted.
    // The client must independently validate a received ServerHello PSK
    // selection. Server-side serialization checks cannot protect a client
    // connected to a non-conforming or malicious peer.
    auto assert_client_rejects = [&](uint16 selected_identity, uint8 offered_modes, const char* description, bool mismatched_hash) {
        tls_session client;
        client.set_type(session_type_t::tls);
        auto& protection = client.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        protection.get_protection_context().add_cipher_suite(0x1301).add_supported_version(tls1_3);
        client.update_session_status(session_status_client_hello);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        const tls_cipher_suite_t* suite = tls_advisor::get_instance()->hintof_cipher_suite(0x1301);
        const tls_cipher_suite_t* hash_suite = tls_advisor::get_instance()->hintof_cipher_suite(mismatched_hash ? 0x1302 : 0x1301);
        _test_case.assert(nullptr != suite && nullptr != hash_suite, function_name, "resolve the ServerHello and offered PSK hash suites");
        if (nullptr == suite || nullptr == hash_suite) {
            return;
        }
        auto& kv = client.get_keyvalue();
        kv.set(session_client_psk_identity_count, 1);
        kv.set(session_client_psk_modes_present, 1);
        kv.set(session_client_psk_modes, offered_modes);
        kv.set(session_client_psk_hash, static_cast<uint16>(hash_suite->mac));

        // ServerHello with supported_versions and pre_shared_key only.
        // The selected identity is supplied by the peer; no key_share means
        // the server is claiming psk_ke.
        binary_t wire = {0x16,
                         0x03,
                         0x03,
                         0x00,
                         0x38,  // TLS Handshake record, 56-byte payload
                         0x02,
                         0x00,
                         0x00,
                         0x34,  // ServerHello, 52-byte body
                         0x03,
                         0x03,  // legacy_version
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x42,
                         0x00,  // legacy_session_id_echo
                         0x13,
                         0x01,  // TLS_AES_128_GCM_SHA256
                         0x00,  // legacy_compression_method
                         0x00,
                         0x0c,  // extensions length
                         0x00,
                         0x2b,
                         0x00,
                         0x02,
                         0x03,
                         0x04,  // supported_versions = TLS 1.3
                         0x00,
                         0x29,
                         0x00,
                         0x02,
                         static_cast<byte_t>(selected_identity >> 8),
                         static_cast<byte_t>(selected_identity)};

        tls_records records;
        return_t ret = records.read(&client, from_server, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, function_name, description);
        size_t illegal_parameter_count = 0;
        illegal_parameter_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, function_name, "report fatal illegal_parameter for the invalid peer PSK selection");
        _test_case.assert(0xffff == client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                          "do not commit selected_identity when the ServerHello PSK selection is invalid");
        _test_case.assert(0xffff == client.get_keyvalue().get(session_server_psk_key_exchange_mode), function_name,
                          "do not commit the PSK key-exchange mode when the ServerHello PSK selection is invalid");
    };

    assert_client_rejects(0, 0x02, "reject psk_ke when the client offered only psk_dhe_ke", false);
    assert_client_rejects(1, 0x01, "reject a ServerHello selected_identity outside the client's offered identity vector", false);
    assert_client_rejects(0, 0x01, "reject a selected PSK whose hash differs from the ServerHello cipher suite", true);
}

static void test_tls13_server_rejects_unoffered_psk_mode() {
    // Scenario under test: TLS 1.3 server and client reject unoffered PSK selections.
    // Action: exercise server serialization, extension direction, and client ServerHello validation.
    // Expected: reject unsupported or inconsistent PSK selections before key establishment.
    _test_case.begin("TLS 1.3 server does not serialize an unoffered PSK selection");

    test_tls13_server_rejects_unoffered_psk_modes_on_write(__FUNCTION__);
    test_tls13_server_rejects_mismatched_selected_psk_identity(__FUNCTION__);
    test_tls13_rejects_server_sent_psk_modes_extension(__FUNCTION__);
    test_tls13_client_rejects_invalid_server_psk_selection(__FUNCTION__);
}

static void test_tls13_server_hello_rejects_unoffered_cipher_suite() {
    // Action: parse ServerHello selecting a cipher suite absent from the client's offer.
    // Scenario under test: TLS 1.3 ServerHello must select a ClientHello-offered cipher suite.
    // Expected: reject a ServerHello selecting an unoffered TLS 1.3 cipher suite.
    _test_case.begin("TLS 1.3 ServerHello must select a ClientHello-offered cipher suite");

    {
        tls_session client;
        client.set_type(session_type_t::tls);
        auto& protection = client.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        protection.get_protection_context().add_cipher_suite(0x1301).add_supported_version(tls1_3);
        client.update_session_status(session_status_client_hello);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        // ServerHello selects TLS_CHACHA20_POLY1305_SHA256 (0x1303), which
        // shares SHA-256 with the offered 0x1301 suite but was not offered.
        // The suite/hash match must not hide the missing offer.
        binary_t wire = {
            0x16, 0x03, 0x03, 0x00, 0x32,  // TLS Handshake record, 50-byte payload
            0x02, 0x00, 0x00, 0x2e,        // ServerHello, 46-byte body
            0x03, 0x03,                    // legacy_version
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x00,                               // legacy_session_id_echo
            0x13, 0x03,                         // unoffered cipher suite
            0x00,                               // legacy_compression_method
            0x00, 0x06,                         // extensions length
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04  // supported_versions = TLS 1.3
        };

        tls_records records;
        return_t ret = records.read(&client, from_server, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject a ServerHello selecting an unoffered TLS 1.3 cipher suite");
        size_t illegal_parameter_count = 0;
        illegal_parameter_count = test_count_fatal_alert(client, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for an unoffered cipher suite");
    }

    {
        tls_session server;
        server.set_type(session_type_t::tls);
        auto& protection = server.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1303);
        protection.get_protection_context().add_cipher_suite(0x1301);
        server.update_session_status(session_status_client_hello);
        server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

        auto server_hello = new tls_handshake_server_hello(&server);
        server_hello->set_cipher_suite(0x1303);
        auto versions = new tls_extension_server_supported_versions(server_hello);
        versions->set(tls1_3);
        server_hello->get_extensions().add(versions);

        tls_record_handshake record(&server);
        record << server_hello;
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse to serialize a ServerHello selecting an unoffered cipher suite");
        _test_case.assert(wire.empty(), __FUNCTION__, "do not emit a ServerHello with an unoffered cipher suite");
    }

    {
        tls_session server;
        server.set_type(session_type_t::tls);
        auto& protection = server.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1302);  // SHA-384 suite
        protection.get_protection_context().add_cipher_suite(0x1302);
        server.update_session_status(session_status_client_hello);
        server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        server.get_keyvalue().set(session_client_psk_identity_count, 1);
        server.get_keyvalue().set(session_client_psk_modes_present, 1);
        server.get_keyvalue().set(session_client_psk_modes, 1);  // psk_ke
        server.get_keyvalue().set(session_server_psk_selected_identity, 0);
        server.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);  // SHA-256 ticket

        auto server_hello = new tls_handshake_server_hello(&server);
        server_hello->set_cipher_suite(0x1302);
        auto versions = new tls_extension_server_supported_versions(server_hello);
        versions->set(tls1_3);
        server_hello->get_extensions().add(versions);
        auto selected_psk = new tls_extension_server_psk(server_hello);
        selected_psk->set_selected_identity(0);
        server_hello->get_extensions().add(selected_psk);

        tls_record_handshake record(&server);
        record << server_hello;
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse a PSK selection when the ServerHello suite uses a different hash");
        _test_case.assert(wire.empty(), __FUNCTION__, "do not emit a ServerHello with a PSK hash mismatch");
    }
}

static void test_tls13_psk_ke_key_schedule_roundtrip() {
    // Scenario under test: TLS 1.3 psk_ke selection derives the PSK-only handshake schedule.
    // Action: restore the client-side TLS 1.3 resumption ticket.
    // Expected: retain the identity whose binder was validated.
    _test_case.begin("TLS 1.3 psk_ke selection derives the PSK-only handshake schedule");

    tls_resumption_ticket ticket;
    ticket.identity = {0xa1, 0xb2, 0xc3};
    ticket.psk = binary_t(32, 0x5a);
    ticket.cipher_suite = 0x1303;  // Same SHA-256 hash as the initial suite.
    ticket.version = static_cast<uint16>(tls1_3);
    ticket.lifetime = 3600;
    ticket.age_add = 0x10203040;
    ticket.max_early_data_size = 4096;
    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    ticket.timestamp = now_ms - 25;

    auto configure_resumption = [&](tls_session& session) -> return_t {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        openssl_digest digest;
        binary_t empty;
        binary_t empty_hash;
        return_t ret = digest.digest("sha256", empty, empty_hash);
        if (errorcode_t::success == ret) {
            protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);
            session.store_resumption_ticket(ticket);
            _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "begin PSK resumption with a fresh session status");
        }
        return ret;
    };

    tls_session client;
    return_t ret = configure_resumption(client);
    _test_case.test(ret, __FUNCTION__, "restore the client-side TLS 1.3 resumption ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session server;
    ret = configure_resumption(server);
    _test_case.test(ret, __FUNCTION__, "restore the server-side TLS 1.3 resumption ticket");
    if (errorcode_t::success != ret) {
        return;
    }

    client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 1024);
    auto client_hello = new tls_handshake_client_hello(&client);
    client_hello->add_ciphersuite(0x1301);
    client_hello->add_ciphersuite(0x1303);  // Same SHA-256 PSK hash, different AEAD suite.
    auto versions = new tls_extension_client_supported_versions(client_hello);
    versions->add(tls1_3);
    client_hello->get_extensions().add(versions);
    auto modes = new tls_extension_psk_key_exchange_modes(client_hello);
    modes->add(0);  // psk_ke: no key_share is sent in ServerHello.
    client_hello->get_extensions().add(modes);
    client_hello->get_extensions().add(new tls_extension_early_data(client_hello));
    client_hello->get_extensions().add(new tls_extension_client_psk(client_hello));

    tls_record_handshake client_hello_record(&client);
    client_hello_record << client_hello;
    binary_t client_hello_wire;
    ret = client_hello_record.write(from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a PSK ClientHello that offers only psk_ke and no key_share");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records server_client_hello_records;
    ret = server_client_hello_records.read(&server, from_client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "validate the psk_ke-only ClientHello binder on the server");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "retain the identity whose binder was validated");
    _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_modes), __FUNCTION__, "record the client's psk_ke-only mode offer");
    _test_case.assert(0 != server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "record the early_data offer independently of the PSK binder");
    _test_case.assert(0 != server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                      "retain the ticket's early-data allowance before the server decides whether to accept it");

    auto server_hello = new tls_handshake_server_hello(&server);
    ret = server_hello->set_cipher_suite(0x1303);
    _test_case.test(ret, __FUNCTION__, "select the ticket's offered SHA-256 suite after a different provisional suite");
    if (errorcode_t::success != ret) {
        return;
    }
    auto server_versions = new tls_extension_server_supported_versions(server_hello);
    server_versions->set(tls1_3);
    server_hello->get_extensions().add(server_versions);
    auto selected_psk = new tls_extension_server_psk(server_hello);
    selected_psk->set_selected_identity(0);
    server_hello->get_extensions().add(selected_psk);
    _test_case.assert(nullptr == server_hello->get_extensions().get(tls_extension_type_t::key_share), __FUNCTION__, "omit key_share when selecting psk_ke");

    tls_record_handshake server_hello_record(&server);
    server_hello_record << server_hello;
    binary_t server_hello_wire;
    ret = server_hello_record.write(from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the psk_ke ServerHello and derive the server handshake keys");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                      "record psk_ke on the server before calculating the key schedule");
    _test_case.assert(binary_t(32, 0) == server.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret), __FUNCTION__,
                      "use Hash.length zero bytes instead of an (EC)DHE shared secret");
    _test_case.assert(tls_flow_t::zero_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                      "keep the server in the early-data decision phase after selecting the eligible PSK");

    tls_records client_server_hello_records;
    ret = client_server_hello_records.read(&client, from_server, server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "accept the psk_ke ServerHello and derive the client handshake keys");
    if (errorcode_t::success == ret) {
        auto& client_protection = client.get_tls_protection();
        auto& server_protection = server.get_tls_protection();
        _test_case.assert(0x1303 == client_protection.get_cipher_suite(), __FUNCTION__,
                          "accept the offered ServerHello suite rather than requiring the ticket's original suite");
        _test_case.assert(0x1303 == server_protection.get_cipher_suite(), __FUNCTION__, "use the negotiated ServerHello suite for the server key schedule");
        _test_case.assert(0 == client.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__, "record psk_ke on the client");
        _test_case.assert(server_protection.get_secrets().get(tls_secret_t::early_secret) == client_protection.get_secrets().get(tls_secret_t::early_secret),
                          __FUNCTION__, "derive the same PSK Early Secret on both endpoints");
        _test_case.assert(server_protection.get_secrets().get(tls_secret_t::shared_secret) == client_protection.get_secrets().get(tls_secret_t::shared_secret),
                          __FUNCTION__, "derive the same zero DHE input on both endpoints");
        _test_case.assert(server_protection.get_secrets().get(tls_secret_t::handshake) == client_protection.get_secrets().get(tls_secret_t::handshake), __FUNCTION__,
                          "derive the same handshake secret on both endpoints");
        _test_case.assert(server_protection.get_secrets().get(tls_secret_t::c_hs_traffic) == client_protection.get_secrets().get(tls_secret_t::c_hs_traffic),
                          __FUNCTION__, "derive matching client handshake traffic secrets");
        _test_case.assert(server_protection.get_secrets().get(tls_secret_t::s_hs_traffic) == client_protection.get_secrets().get(tls_secret_t::s_hs_traffic),
                          __FUNCTION__, "derive matching server handshake traffic secrets");

        // The server may select the PSK while declining the separate 0-RTT
        // offer. Omitting early_data from EncryptedExtensions must switch the
        // record flow to 1-RTT without discarding the selected PSK schedule.
        const binary_t client_early_secret = client_protection.get_secrets().get(tls_secret_t::early_secret);
        const binary_t server_early_secret = server_protection.get_secrets().get(tls_secret_t::early_secret);
        const binary_t client_handshake_secret = client_protection.get_secrets().get(tls_secret_t::handshake);
        const binary_t server_handshake_secret = server_protection.get_secrets().get(tls_secret_t::handshake);
        _test_case.assert(0 != client.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                          "record the client's early_data offer independently of PSK selection");

        auto encrypted_extensions = new tls_handshake_encrypted_extensions(&server);
        // TLS 1.3 carries EncryptedExtensions in a protected
        // TLSCiphertext record (outer application_data, inner handshake).
        tls_record_application_data encrypted_extensions_record(&server);
        encrypted_extensions_record.get_handshakes() << encrypted_extensions;
        binary_t encrypted_extensions_wire;
        ret = encrypted_extensions_record.write(from_server, encrypted_extensions_wire);
        _test_case.test(ret, __FUNCTION__, "serialize EncryptedExtensions without early_data to decline 0-RTT");
        if (errorcode_t::success == ret) {
            _test_case.assert(tls_flow_t::one_rtt == server_protection.get_flow(), __FUNCTION__, "switch the server to 1-RTT after declining early data");
            _test_case.assert(0 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                              "leave server early_data acceptance unset when the extension is omitted");

            tls_records client_encrypted_extensions_records;
            ret = client_encrypted_extensions_records.read(&client, from_server, encrypted_extensions_wire);
            _test_case.test(ret, __FUNCTION__, "process the server's EncryptedExtensions rejection of 0-RTT");
            if (errorcode_t::success == ret) {
                _test_case.assert(tls_flow_t::one_rtt == client_protection.get_flow(), __FUNCTION__, "switch the client to 1-RTT after declining early data");
                _test_case.assert(0 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                                  "do not mark early_data accepted when EncryptedExtensions omits it");
                _test_case.assert(0 == client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                  "retain the selected PSK identity after rejecting only early data");
                _test_case.assert(client_early_secret == client_protection.get_secrets().get(tls_secret_t::early_secret), __FUNCTION__,
                                  "retain the client's PSK Early Secret after rejecting early data");
                _test_case.assert(server_early_secret == server_protection.get_secrets().get(tls_secret_t::early_secret), __FUNCTION__,
                                  "retain the server's PSK Early Secret after rejecting early data");
                _test_case.assert(client_handshake_secret == client_protection.get_secrets().get(tls_secret_t::handshake), __FUNCTION__,
                                  "retain the client's PSK handshake secret after rejecting early data");
                _test_case.assert(server_handshake_secret == server_protection.get_secrets().get(tls_secret_t::handshake), __FUNCTION__,
                                  "retain the server's PSK handshake secret after rejecting early data");
                _test_case.assert(client_protection.get_secrets().get(tls_secret_t::handshake) == server_protection.get_secrets().get(tls_secret_t::handshake),
                                  __FUNCTION__, "keep the PSK-derived handshake schedule synchronized after early_data rejection");
            }
        }
    }
}

static void test_tls13_clienthello_extension_vector_message_boundary() {
    // Action: mutate the ClientHello extension-vector length beyond the enclosing handshake body.
    // Scenario under test: TLS 1.3 ClientHello extension vector stays inside its handshake message.
    // Expected: reject an extension vector that crosses the ClientHello message boundary.
    _test_case.begin("TLS 1.3 ClientHello extension vector stays inside its handshake message");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls1_3);

    tls_handshake_client_hello handshake(&session);
    binary_t wire = {
        0x01, 0x00, 0x00, 0x2b,  // ClientHello handshake header: 43-byte body
        0x03, 0x03               // legacy_version
    };
    wire.insert(wire.end(), 32, 0x00);  // random
    wire.insert(wire.end(), {
                                0x00,                    // legacy_session_id length
                                0x00, 0x02, 0x13, 0x01,  // cipher_suites
                                0x01, 0x00,              // legacy_compression_methods
                                0x00, 0x04               // extension vector claims four bytes outside ClientHello
                            });
    // These bytes follow the declared ClientHello message. They resemble an
    // empty unknown extension and must not be consumed as part of its vector.
    wire.insert(wire.end(), {0xff, 0xff, 0x00, 0x00});

    size_t pos = 0;
    return_t ret = handshake.read(from_client, wire.data(), wire.size(), pos);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject an extension vector that crosses the ClientHello message boundary");
    _test_case.assert(0 == handshake.get_extensions().size(), __FUNCTION__, "do not parse trailing bytes as a ClientHello extension");

    size_t decode_error_count = 0;
    decode_error_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::decode_error);
    _test_case.assert(1 == decode_error_count, __FUNCTION__, "report exactly one fatal decode_error for the malformed ClientHello extension length");

    const std::array<binary_t, 2> truncated_extension_vectors = {
        binary_t{0xff},
        binary_t{0xff, 0xff, 0x00, 0x01},
    };
    for (const auto& extensions : truncated_extension_vectors) {
        tls_session truncated_session;
        truncated_session.set_type(session_type_t::tls);
        truncated_session.get_tls_protection().set_tls_version(tls1_3);
        tls_handshake_client_hello truncated_handshake(&truncated_session);

        binary_t truncated_wire = {0x01, 0x00, 0x00, 0x00,  // ClientHello header; body length filled below
                                   0x03, 0x03};
        truncated_wire.insert(truncated_wire.end(), 32, 0x00);
        truncated_wire.insert(truncated_wire.end(), {0x00,                    // legacy_session_id length
                                                     0x00, 0x02, 0x13, 0x01,  // cipher_suites
                                                     0x01, 0x00,              // legacy_compression_methods
                                                     static_cast<byte_t>((extensions.size() >> 8) & 0xff), static_cast<byte_t>(extensions.size() & 0xff)});
        truncated_wire.insert(truncated_wire.end(), extensions.begin(), extensions.end());
        const uint32 body_length = t_narrow_cast(truncated_wire.size() - 4);
        truncated_wire[1] = static_cast<byte_t>((body_length >> 16) & 0xff);
        truncated_wire[2] = static_cast<byte_t>((body_length >> 8) & 0xff);
        truncated_wire[3] = static_cast<byte_t>(body_length & 0xff);

        size_t truncated_pos = 0;
        return_t truncated_ret = truncated_handshake.read(from_client, truncated_wire.data(), truncated_wire.size(), truncated_pos);
        _test_case.assert(errorcode_t::bad_format == truncated_ret, __FUNCTION__, "reject a truncated extension header or body in a complete ClientHello");

        size_t truncated_decode_error_count = 0;
        truncated_decode_error_count = test_count_fatal_alert(truncated_session, from_client, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == truncated_decode_error_count, __FUNCTION__, "report exactly one fatal decode_error for a truncated ClientHello extension");
    }
}

static void test_tls13_psk_modes_unknown_and_duplicate_values() {
    // Scenario under test: TLS 1.3 PSK key-exchange-modes ignores unknown values and tolerates duplicates.
    // Action: parse a non-empty PSK mode vector containing unknown or duplicate values.
    // Expected: consume the complete PSK mode extension.
    _test_case.begin("TLS 1.3 PSK key-exchange-modes ignores unknown values and tolerates duplicates");

    const std::array<std::pair<binary_t, uint8>, 3> cases = {{
        {binary_t{0x00, 0x2d, 0x00, 0x04, 0x03, 0x01, 0xfe, 0x01}, 0x02},
        {binary_t{0x00, 0x2d, 0x00, 0x03, 0x02, 0x01, 0x01}, 0x02},
        {binary_t{0x00, 0x2d, 0x00, 0x02, 0x01, 0xfe}, 0x00},
    }};

    for (const auto& test_case : cases) {
        tls_session session;
        session.set_type(session_type_t::tls);
        tls_handshake_client_hello handshake(&session);
        tls_extension_psk_key_exchange_modes extension(&handshake);
        size_t pos = 0;
        return_t ret = extension.read(from_client, test_case.first.data(), test_case.first.size(), pos);
        _test_case.test(ret, __FUNCTION__, "parse a non-empty PSK mode vector containing unknown or duplicate values");
        if (errorcode_t::success == ret) {
            _test_case.assert(test_case.first.size() == pos, __FUNCTION__, "consume the complete PSK mode extension");
            _test_case.assert(test_case.second == extension.get_modes(), __FUNCTION__, "retain only the distinct, recognized PSK modes");
        }
    }
}

static void test_tls13_psk_modes_malformed_length_alert() {
    // Action: parse empty and length-mismatched psk_key_exchange_modes vectors.
    // Scenario under test: TLS 1.3 PSK key-exchange-modes malformed vector decode_error.
    // Expected: reject an empty or length-mismatched PSK mode vector.
    _test_case.begin("TLS 1.3 PSK key-exchange-modes malformed vector decode_error");

    const std::array<binary_t, 2> malformed_extensions = {
        binary_t{0x00, 0x2d, 0x00, 0x00},
        binary_t{0x00, 0x2d, 0x00, 0x02, 0x02, 0x01},
    };

    for (const auto& wire : malformed_extensions) {
        tls_session session;
        session.set_type(session_type_t::tls);
        tls_handshake_client_hello handshake(&session);
        tls_extension_psk_key_exchange_modes extension(&handshake);
        size_t pos = 0;
        return_t ret = extension.read(from_client, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject an empty or length-mismatched PSK mode vector");

        size_t decode_error_count = 0;
        decode_error_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == decode_error_count, __FUNCTION__, "report exactly one fatal decode_error for malformed PSK modes");
    }
}

static void test_tls13_psk_extension_message_context() {
    // Action: parse pre_shared_key in an EncryptedExtensions message context.
    // Scenario under test: TLS 1.3 pre_shared_key extension message context.
    // Expected: reject pre_shared_key in EncryptedExtensions.
    _test_case.begin("TLS 1.3 pre_shared_key extension message context");

    tls_session session;
    session.set_type(session_type_t::tls);
    tls_handshake_encrypted_extensions handshake(&session);
    tls_extension_server_psk extension(&handshake);
    const binary_t wire = {0x00, 0x29, 0x00, 0x02, 0x00, 0x00};
    size_t pos = 0;
    return_t ret = extension.read(from_server, wire.data(), wire.size(), pos);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject pre_shared_key in EncryptedExtensions");

    size_t illegal_parameter_count = 0;
    illegal_parameter_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::illegal_parameter);
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for pre_shared_key outside ServerHello");
}

static void test_tls13_server_psk_extension_malformed_length_alert() {
    // Action: parse ServerHello pre_shared_key extensions with one- and three-byte selected_identity bodies.
    // Scenario under test: TLS 1.3 ServerHello PSK selected_identity malformed length alert.
    // Expected: reject a selected_identity body whose length is not exactly two bytes.
    _test_case.begin("TLS 1.3 ServerHello PSK selected_identity malformed length alert");

    const std::array<binary_t, 2> malformed_extensions = {
        binary_t{0x00, 0x29, 0x00, 0x01, 0x00},
        binary_t{0x00, 0x29, 0x00, 0x03, 0x00, 0x00, 0x00},
    };

    for (const auto& wire : malformed_extensions) {
        tls_session session;
        session.set_type(session_type_t::tls);
        tls_handshake_server_hello handshake(&session);
        tls_extension_server_psk extension(&handshake);
        size_t pos = 0;
        return_t ret = extension.read(from_server, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a selected_identity body whose length is not exactly two bytes");

        size_t decode_error_count = 0;
        decode_error_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::decode_error);
        _test_case.assert(1 == decode_error_count, __FUNCTION__, "report exactly one fatal decode_error for a malformed ServerHello PSK extension");
    }
}

static void test_tls13_encrypted_extensions_write_failure_rolls_back_psk_state() {
    // Action: serialize early_data before forcing a later EncryptedExtensions extension writer to fail.
    // Scenario under test: EncryptedExtensions serialization fails after early_data was serialized.
    // Expected: roll back extension-writer side effects without discarding the already-selected PSK schedule.
    _test_case.begin("TLS 1.3 EncryptedExtensions serialization failure rolls back extension state");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);

    auto& secrets = protection.get_secrets();
    const binary_t resumption_early(32, 0x11);
    secrets.assign(tls_secret_t::resumption_early, resumption_early);
    const binary_t binder_hash(32, 0x22);
    const binary_t binder_key(32, 0x33);
    const binary_t binder_finished_key(32, 0x44);
    const binary_t binder_finished(32, 0x55);
    secrets.assign(tls_secret_t::resumption_binder_hash, binder_hash);
    secrets.assign(tls_secret_t::resumption_binder_key, binder_key);
    secrets.assign(tls_secret_t::resumption_finished_key, binder_finished_key);
    secrets.assign(tls_secret_t::resumption_finished, binder_finished);
    secrets.assign(tls_secret_t::c_e_traffic, binary_t(32, 0x66));
    secrets.assign(tls_secret_t::e_exp_master, binary_t(32, 0x77));
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x88));
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x99));
    secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0xaa));

    auto& kv = session.get_keyvalue();
    kv.set(session_server_psk_selected_identity, 0);
    kv.set(session_server_psk_key_exchange_mode, 1);
    kv.set(session_server_psk_ticket_cipher_suite, 0x1301);

    tls_resumption_ticket ticket;
    ticket.identity = {0xa1, 0xb2};
    ticket.psk = resumption_early;
    ticket.version = static_cast<uint16>(tls1_3);
    ticket.cipher_suite = 0x1301;
    ticket.max_early_data_size = 4096;
    session.set_offered_resumption_tickets({ticket});
    session.set_early_data_ticket(ticket);

    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_limit, 1024);
    early_state.set(session_early_data_accepted, 0);
    session.get_session_info(from_client).begin_protection();
    session.update_session_status(session_status_client_hello);
    session.update_session_status(session_status_server_hello);
    const uint32 original_session_status = session.get_session_status();

    // Prove the fixture is eligible: the direct early_data writer provisionally
    // marks acceptance, which the enclosing extension-vector writer must undo
    // if a later extension fails.
    tls_handshake_encrypted_extensions early_data_probe(&session);
    tls_extension_early_data early_data_probe_extension(&early_data_probe);
    binary_t early_data_probe_wire;
    return_t ret = early_data_probe_extension.write(from_server, early_data_probe_wire);
    _test_case.test(ret, __FUNCTION__, "serialize an eligible early_data indication");
    _test_case.assert(1 == early_state.get(session_early_data_accepted), __FUNCTION__, "observe the provisional early_data acceptance side effect");
    early_state.set(session_early_data_accepted, 0);

    tls_handshake_encrypted_extensions encrypted_extensions(&session);
    encrypted_extensions.get_extensions().add(new tls_extension_early_data(&encrypted_extensions));
    auto invalid_modes = new tls_extension_psk_key_exchange_modes(&encrypted_extensions);
    invalid_modes->add(1);
    encrypted_extensions.get_extensions().add(invalid_modes);

    binary_t wire;
    ret = encrypted_extensions.write(from_server, wire);
    // This failure is intentional: the following assertion verifies the expected error code.
    _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "return the extension serialization error");
    _test_case.assert(wire.empty(), __FUNCTION__, "do not emit a partial EncryptedExtensions message");

    _test_case.assert(tls_flow_t::zero_rtt == protection.get_flow(), __FUNCTION__, "preserve the active 0-RTT decision flow for a corrected retry");
    _test_case.assert(0 == kv.get(session_server_psk_selected_identity), __FUNCTION__, "preserve the selected PSK identity");
    _test_case.assert(1 == kv.get(session_server_psk_key_exchange_mode), __FUNCTION__, "preserve the selected PSK exchange mode");
    _test_case.assert(0x1301 == kv.get(session_server_psk_ticket_cipher_suite), __FUNCTION__, "preserve the selected ticket cipher suite");
    _test_case.assert(resumption_early == secrets.get(tls_secret_t::resumption_early), __FUNCTION__,
                      "preserve the PSK Early Secret after a retryable local write failure");
    _test_case.assert(binder_hash == secrets.get(tls_secret_t::resumption_binder_hash), __FUNCTION__, "preserve the binder transcript hash");
    _test_case.assert(binder_key == secrets.get(tls_secret_t::resumption_binder_key), __FUNCTION__, "preserve the binder key");
    _test_case.assert(binder_finished_key == secrets.get(tls_secret_t::resumption_finished_key), __FUNCTION__, "preserve the binder Finished key");
    _test_case.assert(binder_finished == secrets.get(tls_secret_t::resumption_finished), __FUNCTION__, "preserve the binder Finished value");
    _test_case.assert(false == secrets.get(tls_secret_t::c_hs_traffic).empty(), __FUNCTION__, "preserve the installed client handshake traffic secret");

    _test_case.assert(1 == session.get_offered_resumption_tickets().size(), __FUNCTION__, "preserve the offered-ticket snapshot");
    _test_case.assert(ticket.identity == session.get_early_data_ticket().identity, __FUNCTION__, "preserve the provisional early-data ticket");
    _test_case.assert(1 == early_state.get(session_early_data_offered), __FUNCTION__, "preserve the early-data offer state");
    _test_case.assert(1 == early_state.get(session_early_data_offered_initial), __FUNCTION__, "preserve the initial early-data offer state");
    _test_case.assert(1024 == early_state.get(session_early_data_limit), __FUNCTION__, "preserve the early-data allowance");
    _test_case.assert(0 == early_state.get(session_early_data_accepted), __FUNCTION__, "restore the pre-write early_data acceptance value");
    _test_case.assert(original_session_status == session.get_session_status(), __FUNCTION__, "preserve aggregate handshake status after the local write failure");
}

void testcase_gpt_psk() {
    test_tls13_encrypted_extensions_write_failure_rolls_back_psk_state();
    test_tls13_clienthello_extension_vector_message_boundary();
    test_tls13_psk_modes_unknown_and_duplicate_values();
    test_tls13_psk_modes_malformed_length_alert();
    test_tls13_psk_extension_message_context();
    test_tls13_server_psk_extension_malformed_length_alert();
    test_tls13_server_rejects_unoffered_psk_mode();
    test_tls13_server_hello_rejects_unoffered_cipher_suite();
    test_tls13_psk_ke_key_schedule_roundtrip();
    test_tls13_server_client_ticket_psk_roundtrip();
    test_tls13_ticket_nonce_resumption_psk();
    test_tls13_client_suppresses_unusable_initial_psk_offer();
}
