/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_renegotiation.cpp
 * @author GPT
 * @desc   TLS 1.2 RFC 5746 renegotiation policy, initiation, and directional cipher-suite tests.
 */

#include <algorithm>
#include <functional>
#include <thread>

#include "testcase_gpt_common.hpp"

static void configure_tls12_completed_secure_session(tls_session& session, bool enable_renegotiation) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    if (enable_renegotiation) {
        session.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
    }
    session.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.update_session_status(session_status_client_finished);
    session.update_session_status(session_status_server_finished);
    protection.get_secrets().assign(tls_secret_t::client_verifydata, binary_t(12, 0x31));
    protection.get_secrets().assign(tls_secret_t::server_verifydata, binary_t(12, 0x42));
    session.get_session_info(from_client).set_active_cipher_suite(0xc030);
    session.get_session_info(from_server).set_active_cipher_suite(0xc02c);
}

static return_t write_tls12_renegotiation_client_hello(tls_session& session, binary_t& wire) {
    tls_handshake_client_hello hello(&session);
    hello.add_ciphersuite(0xc02f);
    auto versions = new tls_extension_client_supported_versions(&hello);
    versions->add(tls1_2);
    hello.get_extensions().add(versions);
    return hello.write(from_client, wire);
}

static void test_tls12_renegotiation_option_and_client_initiation() {
    // Scenario: a completed, securely renegotiated TLS 1.2 connection receives a
    // locally initiated renegotiation request, first with the default policy and
    // then with the explicit opt-in.
    // Action: serialize the renegotiation ClientHello and inspect its RFC 5746
    // renegotiation_info binding and the receiving server's policy response.
    // Expected: the default policy declines without disturbing the established
    // connection; explicit opt-in permits the bound renegotiation ClientHello.
    _test_case.begin("TLS 1.2 renegotiation option defaults disabled and explicitly enables RFC 5746");

    {
        tls_session client;
        configure_tls12_completed_secure_session(client, false);
        _test_case.assert(0 == client.get_keyvalue().get(session_conf_enable_tls12_renegotiation), __FUNCTION__, "TLS 1.2 renegotiation option defaults to disabled");

        binary_t wire;
        return_t ret = write_tls12_renegotiation_client_hello(client, wire);
        _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__, "decline locally initiated renegotiation under the default policy");
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the established flow when local renegotiation is disabled");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (client.get_session_status() & completed_status), __FUNCTION__,
                          "preserve completed-handshake status when local renegotiation is disabled");
        _test_case.assert(0 == test_count_fatal_alerts(client, from_client), __FUNCTION__, "do not queue a fatal alert for locally disabled renegotiation");
    }

    {
        tls_session client;
        configure_tls12_completed_secure_session(client, true);
        binary_t wire;
        return_t ret = write_tls12_renegotiation_client_hello(client, wire);
        _test_case.test(ret, __FUNCTION__, "write ClientHello when the TLS 1.2 renegotiation option is enabled");
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "enter renegotiation flow for an explicitly enabled client");
        size_t body_pos = 0;
        size_t body_size = 0;
        bool found = test_find_client_hello_extension(wire, 0xff01, body_pos, body_size);
        _test_case.assert(found, __FUNCTION__, "include the RFC 5746 renegotiation_info extension");
        if (found) {
            _test_case.assert(13 == body_size, __FUNCTION__, "encode the client verify_data vector with its one-byte length");
            if (13 == body_size) {
                _test_case.assert((wire[body_pos] == 12), __FUNCTION__, "encode the 12-byte previous client Finished verify_data length");
                const binary_t& client_verifydata = client.get_tls_protection().get_secrets().get(tls_secret_t::client_verifydata);
                _test_case.assert(std::equal(wire.begin() + body_pos + 1, wire.begin() + body_pos + body_size, client_verifydata.begin()), __FUNCTION__,
                                  "bind ClientHello to the previous client Finished verify_data");
            }
        }

        {
            tls_session refusing_server;
            configure_tls12_completed_secure_session(refusing_server, false);
            _test_case.assert(0 == refusing_server.get_keyvalue().get(session_conf_enable_tls12_renegotiation), __FUNCTION__,
                              "leave the peer renegotiation policy at its default-disabled value");
            tls_handshake_client_hello declined_hello(&refusing_server);
            size_t declined_pos = 0;
            return_t declined_ret = declined_hello.read(from_client, wire.data(), wire.size(), declined_pos);
            _test_case.test(declined_ret, __FUNCTION__, "consume a valid peer renegotiation ClientHello when local policy is disabled");
            _test_case.assert(wire.size() == declined_pos, __FUNCTION__, "consume the complete declined ClientHello");
            _test_case.assert(tls_flow_t::one_rtt == refusing_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "preserve the established server flow after declining peer renegotiation");
            // Peek first so the warning assertion observes the queued alert.
            // The subsequent fatal-alert helper intentionally uses get_alert()
            // without flags and therefore drains the complete alert queue.
            size_t warning_count = 0;
            refusing_server.get_alert(
                from_client,
                [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                    if ((tls_alertlevel_t::warning == level) && (tls_alertdesc_t::no_renegotiation == desc)) {
                        ++warning_count;
                    }
                },
                session_alert_peek);
            _test_case.assert(1 == warning_count, __FUNCTION__, "queue one warning no_renegotiation alert");
            _test_case.assert(0 == test_count_fatal_alerts(refusing_server, from_client), __FUNCTION__, "do not queue a fatal alert for the declined renegotiation");
        }

        tls_session server;
        configure_tls12_completed_secure_session(server, true);
        tls_handshake_client_hello peer_hello(&server);
        size_t pos = 0;
        ret = peer_hello.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "accept the client-initiated renegotiation ClientHello");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete renegotiation ClientHello");
        _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "enter renegotiation flow at the receiving server");
        _test_case.assert(0xc030 == server.get_session_info(from_client).get_active_cipher_suite(), __FUNCTION__,
                          "retain the old client-direction cipher suite until client CCS");
        _test_case.assert(0xc02c == server.get_session_info(from_server).get_active_cipher_suite(), __FUNCTION__,
                          "retain the old server-direction cipher suite until server CCS");
    }
}

static void test_tls12_server_initiated_renegotiation() {
    // Scenario: client and server have completed a secure TLS 1.2 handshake and
    // both permit renegotiation; the server initiates the next handshake.
    // Action: send HelloRequest, receive it at the client, and exchange the
    // renegotiation ClientHello.
    // Expected: both peers enter the renegotiation flow and preserve the prior
    // connection state until the new handshake advances it.
    _test_case.begin("TLS 1.2 server-initiated renegotiation completes the HelloRequest and ClientHello exchange");

    tls_session server;
    tls_session client;
    configure_tls12_completed_secure_session(server, true);
    configure_tls12_completed_secure_session(client, true);

    tls_handshake_builder builder;
    auto request = builder.set(tls_handshake_type_t::hello_request).set(&server).build();
    _test_case.assert(nullptr != request, __FUNCTION__, "construct server HelloRequest");
    if (nullptr == request) {
        return;
    }

    binary_t request_wire;
    return_t ret = request->write(from_server, request_wire);
    _test_case.test(ret, __FUNCTION__, "write HelloRequest after secure TLS 1.2 handshake");
    request->release();
    if (errorcode_t::success != ret) {
        return;
    }

    auto peer_request = builder.set(tls_handshake_type_t::hello_request).set(&client).build();
    _test_case.assert(nullptr != peer_request, __FUNCTION__, "construct client HelloRequest parser");
    if (nullptr == peer_request) {
        return;
    }
    size_t request_pos = 0;
    ret = peer_request->read(from_server, request_wire.data(), request_wire.size(), request_pos);
    _test_case.test(ret, __FUNCTION__, "receive server HelloRequest");
    _test_case.assert(request_wire.size() == request_pos, __FUNCTION__, "consume complete HelloRequest");
    peer_request->release();
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "server enters renegotiation flow");
    _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "client enters renegotiation flow");

    binary_t client_hello_wire;
    ret = write_tls12_renegotiation_client_hello(client, client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "client answers HelloRequest with a bound renegotiation ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_handshake_client_hello peer_hello(&server);
    size_t client_hello_pos = 0;
    ret = peer_hello.read(from_client, client_hello_wire.data(), client_hello_wire.size(), client_hello_pos);
    _test_case.test(ret, __FUNCTION__, "server accepts the ClientHello response to HelloRequest");
    _test_case.assert(client_hello_wire.size() == client_hello_pos, __FUNCTION__, "consume complete server-initiated renegotiation ClientHello");
}

static void test_tls12_server_composer_renegotiation() {
    // Scenario: an established TLS 1.2 server reaches its outbound sequence
    // reserve and must perform an option-enabled RFC 5746 renegotiation.
    // Action: exercise the server composer with callback-simulated full and
    // abbreviated completion, plus the peer no_renegotiation refusal path.
    // Expected: HelloRequest is sent once; both Finished bits are required;
    // peer refusal is not mistaken for a successful handshake.
    _test_case.begin("TLS 1.2 server composer initiates renegotiation and waits for both Finished messages");

    for (int abbreviated_case = 0; abbreviated_case < 2; ++abbreviated_case) {
        const bool abbreviated = (0 != abbreviated_case);
        tls_session server;
        configure_tls12_completed_secure_session(server, true);
        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);

        size_t send_count = 0;
        auto send_hello_request = [&](tls_session* current, binary_t& wire) -> return_t {
            ++send_count;
            _test_case.assert((wire.size() >= 6) && (tls_content_type_t::handshake == static_cast<tls_content_type_t>(wire[0])) &&
                                  (static_cast<byte_t>(tls_handshake_type_t::hello_request) == wire[5]),
                              __FUNCTION__, "send a TLS handshake record containing HelloRequest");
            _test_case.assert(tls_flow_t::renegotiation == current->get_tls_protection().get_flow(), __FUNCTION__,
                              "enter renegotiation flow before waiting for the peer");
            _test_case.assert(0 == current->get_session_status(), __FUNCTION__, "clear the previous Finished status before the new handshake");

            current->update_session_status(session_status_client_hello);
            current->update_session_status(session_status_server_hello);
            if (abbreviated) {
                // RFC 5077 abbreviated order: server Finished precedes client Finished.
                current->update_session_status(session_status_server_finished);
                current->update_session_status(session_status_client_finished);
            } else {
                // Full handshake order: client Finished precedes server Finished.
                current->update_session_status(session_status_client_finished);
                current->update_session_status(session_status_server_finished);
            }
            current->get_tls_protection().set_flow(tls_flow_t::one_rtt);
            return errorcode_t::success;
        };

        return_t ret = composer.handshake(from_server, 100, send_hello_request);
        _test_case.test(ret, __FUNCTION__,
                        abbreviated ? "complete callback-simulated abbreviated server renegotiation" : "complete callback-simulated full server renegotiation");
        _test_case.assert(1 == send_count, __FUNCTION__, "send exactly one HelloRequest for the server-initiated exchange");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (server.get_session_status() & completed_status), __FUNCTION__, "wait for both client and server Finished messages");
        _test_case.assert(0 != (server.get_session_status() & session_status_server_hello), __FUNCTION__,
                          "distinguish successful renegotiation from a no_renegotiation refusal");
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                          "return only after the renegotiated connection is back in one_rtt flow");
    }

    {
        tls_session server;
        configure_tls12_completed_secure_session(server, true);
        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);

        size_t send_count = 0;
        auto peer_refuses = [&](tls_session* current, binary_t&) -> return_t {
            ++send_count;
            tls_record_alert refusal(current, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
            binary_t alert_wire;
            return refusal.write(from_client, alert_wire);
        };

        return_t ret = composer.handshake(from_server, 100, peer_refuses);
        _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__, "report peer no_renegotiation instead of treating restored Finished bits as success");
        _test_case.assert(1 == send_count, __FUNCTION__, "send one HelloRequest before processing peer refusal");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (server.get_session_status() & completed_status), __FUNCTION__,
                          "restore the established Finished status after peer refusal");
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__, "restore the established flow after peer refusal");
        _test_case.assert(0 == (server.get_session_status() & session_status_server_hello), __FUNCTION__, "do not publish ServerHello for a refused renegotiation");
    }

    {
        tls_session server;
        configure_tls12_completed_secure_session(server, true);
        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);
        size_t send_count = 0;
        auto failed_send = [&](tls_session*, binary_t&) -> return_t {
            ++send_count;
            return errorcode_t::internal_error;
        };

        return_t ret = composer.handshake(from_server, 100, failed_send);
        _test_case.assert(errorcode_t::internal_error == ret, __FUNCTION__, "propagate a HelloRequest transport callback failure without waiting for the peer");
        _test_case.assert(1 == send_count, __FUNCTION__, "do not retry a failed HelloRequest transport callback");
    }

    {
        tls_session server;
        configure_tls12_completed_secure_session(server, true);
        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);
        size_t send_count = 0;
        auto unanswered_peer = [&](tls_session*, binary_t&) -> return_t {
            ++send_count;
            return errorcode_t::success;
        };

        return_t ret = composer.handshake(from_server, 20, unanswered_peer);
        _test_case.assert(errorcode_t::timeout == ret, __FUNCTION__, "time out when the peer neither answers HelloRequest nor declines renegotiation");
        _test_case.assert(1 == send_count, __FUNCTION__, "send only one HelloRequest before the peer-response timeout");
    }

    {
        tls_session server;
        configure_tls12_completed_secure_session(server, false);
        tls_composer composer(&server);
        composer.set_minver(tls1_2);
        composer.set_maxver(tls1_2);
        size_t send_count = 0;
        auto should_not_send = [&](tls_session*, binary_t&) -> return_t {
            ++send_count;
            return errorcode_t::success;
        };

        return_t ret = composer.handshake(from_server, 10, should_not_send);
        _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__, "honor the default-disabled server renegotiation option");
        _test_case.assert(0 == send_count, __FUNCTION__, "do not send HelloRequest when the option is disabled");
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the established connection when local policy declines initiation");
    }

    {
        tls_session tls13(session_type_t::tls);
        tls13.get_tls_protection().set_tls_version(tls1_3);
        tls_composer composer(&tls13);
        size_t send_count = 0;
        auto should_not_send = [&](tls_session*, binary_t&) -> return_t {
            ++send_count;
            return errorcode_t::success;
        };
        return_t ret = composer.handshake(from_server, 10, should_not_send);
        _test_case.assert(errorcode_t::not_supported == ret, __FUNCTION__, "leave TLS 1.3 server handshake behavior unchanged");
        _test_case.assert(0 == send_count, __FUNCTION__, "do not send HelloRequest for TLS 1.3");
    }

    {
        tls_session dtls(session_type_t::dtls);
        tls_composer composer(&dtls);
        size_t send_count = 0;
        auto should_not_send = [&](tls_session*, binary_t&) -> return_t {
            ++send_count;
            return errorcode_t::success;
        };
        return_t ret = composer.handshake(from_server, 10, should_not_send);
        _test_case.assert(errorcode_t::not_supported == ret, __FUNCTION__, "leave DTLS server handshake behavior unchanged");
        _test_case.assert(0 == send_count, __FUNCTION__, "do not send HelloRequest for DTLS");
    }
}

static void test_tls12_server_send_joins_peer_initiated_renegotiation() {
    // Scenario: the peer has already initiated TLS 1.2 renegotiation and its
    // ClientHello has been processed while the server application wants to send.
    // Action: start the server socket send, hold the peer exchange before Finished,
    // then publish ServerHello and both Finished messages.
    // Expected: the application sender waits for the in-progress exchange, does
    // not write an application record while renegotiation is pending, and only
    // attempts the application record after the connection returns to one_rtt.
    _test_case.begin("TLS 1.2 server application send joins peer-initiated renegotiation");

    auto session = new tls_session(session_type_t::tls);
    configure_tls12_completed_secure_session(*session, true);
    auto& protection = session->get_tls_protection();
    protection.set_cipher_suite(0xc02f);
    session->get_session_info(from_server).begin_protection();
    session->get_session_info(from_server).set_active_cipher_suite(0xc02f);
    protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
    protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x22));
    const uint64 initial_recordno = session->get_recordno(from_server);
    const uint32 completed_status = session_status_client_finished | session_status_server_finished;
    session->clear_session_status(completed_status);
    session->get_tls_protection().set_flow(tls_flow_t::renegotiation);
    session->update_session_status(session_status_client_hello);

    socket_context_t context;
    context.handle.session = session;
    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    std::atomic<bool> sender_a_started(false);
    std::atomic<bool> sender_b_started(false);
    std::atomic<bool> sender_a_finished(false);
    std::atomic<bool> sender_b_finished(false);
    return_t send_ret_a = errorcode_t::success;
    return_t send_ret_b = errorcode_t::success;
    size_t sent_a = 99;
    size_t sent_b = 99;
    std::thread sender_a([&]() {
        sender_a_started.store(true, std::memory_order_release);
        send_ret_a = server_socket.send(&context, "a", 1, &sent_a);
        sender_a_finished.store(true, std::memory_order_release);
    });

    while (true) {
        if (sender_a_started.load(std::memory_order_acquire)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::thread sender_b([&]() {
        sender_b_started.store(true, std::memory_order_release);
        send_ret_b = server_socket.send(&context, "b", 1, &sent_b);
        sender_b_finished.store(true, std::memory_order_release);
    });
    while (true) {
        if (sender_b_started.load(std::memory_order_acquire)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    _test_case.assert(false == sender_a_finished.load(std::memory_order_acquire), __FUNCTION__, "keep sender A blocked while peer renegotiation is incomplete");
    _test_case.assert(false == sender_b_finished.load(std::memory_order_acquire), __FUNCTION__, "keep sender B blocked while peer renegotiation is incomplete");
    _test_case.assert(initial_recordno == session->get_recordno(from_server), __FUNCTION__,
                      "do not advance the server write sequence while either sender awaits peer Finished");

    session->update_session_status(session_status_server_hello);
    session->update_session_status(session_status_client_finished);
    session->get_tls_protection().set_flow(tls_flow_t::one_rtt);
    session->update_session_status(session_status_server_finished);
    sender_a.join();
    sender_b.join();

    _test_case.assert(true == sender_a_finished.load(std::memory_order_acquire), __FUNCTION__, "complete sender A after both Finished messages and transport failure");
    _test_case.assert(true == sender_b_finished.load(std::memory_order_acquire), __FUNCTION__, "complete sender B after the transport is retired");
    _test_case.assert((errorcode_t::success != send_ret_a) && (errorcode_t::success != send_ret_b), __FUNCTION__,
                      "propagate transport failure and reject the queued send after terminal retirement");
    _test_case.assert((0 == sent_a) && (0 == sent_b), __FUNCTION__, "report no application bytes sent when the test socket is unavailable");
    _test_case.assert(initial_recordno + 1 == session->get_recordno(from_server), __FUNCTION__,
                      "serialize only one application record after both Finished messages before terminal retirement");
    _test_case.assert(session->is_terminal(), __FUNCTION__, "retire the TLS 1.2 session after the post-renegotiation application transport fails");
}

static void test_tls12_server_outbound_reserve_requires_secure_renegotiation() {
    // Scenario: a TLS 1.2 server's outbound application-data counter reaches
    // the first reserved value, first with renegotiation default-off and then
    // with local opt-in but no negotiated RFC 5746 secure-renegotiation support.
    // Action: call the production server socket send wrapper with each protected
    // session and an invalid transport handle, so no application record is sent.
    // Expected: both cases refuse the reserved record, retire the session, and
    // do not queue a fatal alert or report application bytes sent.
    _test_case.begin("TLS 1.2 server outbound reserve requires policy opt-in and secure renegotiation");

    auto session = new tls_session(session_type_t::tls);
    configure_tls12_completed_secure_session(*session, false);
    session->get_session_info(from_server).begin_protection();

    constexpr uint64 sequence_max = ~static_cast<uint64>(0);
    constexpr uint64 sequence_reserve = 65535;
    constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
    session->set_recordno(from_server, sequence_reserve_start);

    socket_context_t context;
    context.handle.session = session;
    trial_tls_server_socket server_socket;
    size_t sent = 99;
    return_t ret = server_socket.send(&context, "x", 1, &sent);

    _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "return the TLS 1.2 application-data reserve refusal");
    _test_case.assert(0 == sent, __FUNCTION__, "report no application bytes sent");
    _test_case.assert(session->is_terminal(), __FUNCTION__, "terminalize the server session when default policy forbids renegotiation");
    _test_case.assert(0 == test_count_fatal_alerts(*session, from_server), __FUNCTION__, "do not queue a fatal alert for intentional reserve refusal");
    _test_case.assert(sequence_reserve_start == session->get_recordno(from_server), __FUNCTION__, "do not advance the reserved server record number");
    {
        auto session = new tls_session(session_type_t::tls);
        configure_tls12_completed_secure_session(*session, true);
        // The local option is enabled, but this established connection did not
        // negotiate RFC 5746 secure renegotiation.
        session->get_keyvalue().set(session_tls12_secure_renegotiation, 0);
        session->get_session_info(from_server).begin_protection();

        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        session->set_recordno(from_server, sequence_reserve_start);

        socket_context_t context;
        context.handle.session = session;
        trial_tls_server_socket server_socket;
        size_t sent = 99;
        return_t ret = server_socket.send(&context, "x", 1, &sent);

        _test_case.assert(1 == session->get_keyvalue().get(session_conf_enable_tls12_renegotiation), __FUNCTION__, "keep the local TLS 1.2 renegotiation option enabled");
        _test_case.assert(0 == session->get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                          "model a connection without negotiated RFC 5746 secure renegotiation");
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "refuse the reserved application record when secure renegotiation was not negotiated");
        _test_case.assert(0 == sent, __FUNCTION__, "report no application bytes sent");
        _test_case.assert(session->is_terminal(), __FUNCTION__, "retire the connection when secure renegotiation is unavailable");
        _test_case.assert(0 == test_count_fatal_alerts(*session, from_server), __FUNCTION__, "do not queue a fatal alert for intentional reserve refusal");
        _test_case.assert(sequence_reserve_start == session->get_recordno(from_server), __FUNCTION__, "do not advance the reserved server record number");
    }
}

static return_t configure_tls12_directional_renegotiation_ccs_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);  // New renegotiated suite: AES-128-GCM.
    protection.set_flow(tls_flow_t::renegotiation);
    session.get_keyvalue().set(session_tls_version, tls1_2);

    // The existing connection deliberately uses distinct AES-256-GCM suites by direction:
    // client writes ECDHE-RSA, server writes ECDHE-ECDSA.
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).begin_protection();
    session.get_session_info(from_client).set_active_cipher_suite(0xc030);
    session.get_session_info(from_server).set_active_cipher_suite(0xc02c);
    session.update_session_status(session_status_server_key_exchange);
    session.update_session_status(session_status_client_key_exchange);

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::client_key, binary_t(32, 0x11));
    secrets.assign(tls_secret_t::client_iv, binary_t(4, 0x21));
    secrets.assign(tls_secret_t::server_key, binary_t(32, 0x12));
    secrets.assign(tls_secret_t::server_iv, binary_t(4, 0x22));

    const binary_t master_secret(48, 0x31);
    const binary_t client_random(32, 0x41);
    const binary_t server_random(32, 0x42);
    secrets.assign(tls_secret_t::master, master_secret);
    secrets.assign(tls_secret_t::client_hello_random, client_random);
    secrets.assign(tls_secret_t::server_hello_random, server_random);
    return protection.calc_keyblock(hash_algorithm_t::sha2_256, master_secret, client_random, server_random, 0xc02f);
}

static void test_tls12_directional_cipher_suite_switch_at_ccs() {
    // Scenario: TLS 1.2 renegotiation negotiates a new cipher suite while the
    // client-to-server and server-to-client directions still use their old keys.
    // Action: write and read each peer's ChangeCipherSpec independently.
    // Expected: each direction switches to its pending cipher suite and resets
    // its record sequence only when that direction's CCS is processed.
    _test_case.begin("TLS 1.2 renegotiation selects and activates cipher suites independently by direction");

    binary_t client_ccs_wire;
    binary_t server_ccs_wire;
    {
        tls_session writer;
        return_t ret = configure_tls12_directional_renegotiation_ccs_session(writer);
        _test_case.test(ret, __FUNCTION__, "derive the pending AES-128-GCM renegotiation key block");
        if (errorcode_t::success != ret) {
            return;
        }

        auto& protection = writer.get_tls_protection();
        _test_case.assert(0xc030 == protection.get_cipher_suite(&writer, from_client), __FUNCTION__, "select the active client-direction cipher suite independently");
        _test_case.assert(0xc02c == protection.get_cipher_suite(&writer, from_server), __FUNCTION__, "select the active server-direction cipher suite independently");

        writer.set_recordno(from_client, 101);
        writer.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&writer);
        ret = ccs.write(from_client, client_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write client CCS using the old client-direction protection state");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0xc02f == protection.get_cipher_suite(&writer, from_client), __FUNCTION__,
                          "switch the client direction from its old suite to the newly negotiated suite at client CCS");
        _test_case.assert(0xc02c == protection.get_cipher_suite(&writer, from_server), __FUNCTION__, "preserve the distinct old server-direction suite until server CCS");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset only the client record sequence at client CCS");
        _test_case.assert(103 == writer.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence until server CCS");

        writer.update_session_status(session_status_client_finished);
        ret = ccs.write(from_server, server_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write server CCS using the still-active server-direction protection state");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0xc02f == protection.get_cipher_suite(&writer, from_server), __FUNCTION__,
                          "activate the newly negotiated server-direction suite at server CCS");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset the server record sequence only at server CCS");
    }

    {
        tls_session reader;
        return_t ret = configure_tls12_directional_renegotiation_ccs_session(reader);
        _test_case.test(ret, __FUNCTION__, "derive matching pending read keys for directional CCS validation");
        if (errorcode_t::success != ret) {
            return;
        }
        reader.set_recordno(from_client, 101);
        reader.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        ret = ccs.read(from_client, client_ccs_wire.data(), client_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "decrypt client CCS with the old client-direction cipher suite");
        _test_case.assert(client_ccs_wire.size() == pos, __FUNCTION__, "consume complete client CCS record");
        _test_case.assert(0xc02f == reader.get_tls_protection().get_cipher_suite(&reader, from_client), __FUNCTION__,
                          "switch client read suite after successfully reading client CCS");
        _test_case.assert(0xc02c == reader.get_tls_protection().get_cipher_suite(&reader, from_server), __FUNCTION__,
                          "keep the distinct server read suite unchanged after client CCS");

        reader.update_session_status(session_status_client_finished);
        pos = 0;
        ret = ccs.read(from_server, server_ccs_wire.data(), server_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "decrypt server CCS with the old server-direction cipher suite");
        _test_case.assert(server_ccs_wire.size() == pos, __FUNCTION__, "consume complete server CCS record");
        _test_case.assert(0xc02f == reader.get_tls_protection().get_cipher_suite(&reader, from_server), __FUNCTION__,
                          "switch server read suite only after successfully reading server CCS");
    }
}

static void test_tls13_renegotiation_option_is_ignored() {
    // Scenario: a TLS 1.3 client has the legacy TLS 1.2 renegotiation option
    // enabled in its configuration.
    // Action: serialize a TLS 1.3 ClientHello and inspect the resulting flow
    // and extension set.
    // Expected: the TLS 1.2 option does not add renegotiation_info or change
    // the ordinary TLS 1.3 handshake flow; this test does not attempt a
    // post-handshake renegotiation exchange.
    _test_case.begin("TLS 1.2 renegotiation option does not enable renegotiation in TLS 1.3");

    tls_session client;
    client.get_tls_protection().set_tls_version(tls1_3);
    client.get_keyvalue().set(session_tls_version, tls1_3);
    client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);

    tls_handshake_client_hello hello(&client);
    hello.add_ciphersuite(0x1301);
    auto versions = new tls_extension_client_supported_versions(&hello);
    versions->add(tls1_3);
    hello.get_extensions().add(versions);

    binary_t wire;
    return_t ret = hello.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "write an ordinary TLS 1.3 ClientHello with the TLS 1.2 renegotiation option set");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "keep the ordinary TLS 1.3 handshake flow");
        _test_case.assert(nullptr == hello.get_extensions().get(tls_extension_type_t::renegotiation_info), __FUNCTION__,
                          "do not add the TLS 1.2 renegotiation_info extension to TLS 1.3");
    }
}

static return_t test_configure_tls12_renegotiation_ccs_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);
    protection.set_flow(tls_flow_t::renegotiation);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).begin_protection();
    session.get_session_info(from_client).set_active_cipher_suite(0xc02f);
    session.get_session_info(from_server).set_active_cipher_suite(0xc02f);
    session.update_session_status(session_status_server_key_exchange);
    session.update_session_status(session_status_client_key_exchange);

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::client_key, binary_t(16, 0x11));
    secrets.assign(tls_secret_t::client_iv, binary_t(4, 0x21));
    secrets.assign(tls_secret_t::server_key, binary_t(16, 0x12));
    secrets.assign(tls_secret_t::server_iv, binary_t(4, 0x22));

    // Exercise the production TLS 1.2 key-block derivation. The resulting
    // renegotiation keys must remain staged until each direction's CCS.
    const binary_t master_secret(48, 0x31);
    const binary_t client_random(32, 0x41);
    const binary_t server_random(32, 0x42);
    secrets.assign(tls_secret_t::master, master_secret);
    secrets.assign(tls_secret_t::client_hello_random, client_random);
    secrets.assign(tls_secret_t::server_hello_random, server_random);
    return protection.calc_keyblock(hash_algorithm_t::sha2_256, master_secret, client_random, server_random, 0xc02f);
}

static void test_tls12_renegotiation_ccs_transition() {
    // Scenario: a secure TLS 1.2 renegotiation has derived new keys, but both
    // traffic directions are still protected by their previously active keys.
    // Action: process client and server CCS records separately on writer and
    // reader sessions, including a failed activation case.
    // Expected: each direction installs its pending key and resets its record
    // sequence only at its own CCS; a failed activation preserves the old key.
    // RFC 5746 + RFC 5246 §7.1: the old directional keys remain active until
    // that direction's CCS installs its pending renegotiation key block.
    _test_case.begin("TLS 1.2 renegotiation CCS activates pending directional keys");

    const binary_t ccs_wire{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

    binary_t client_ccs_wire;
    binary_t server_ccs_wire;
    {
        tls_session writer;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(writer);
        _test_case.test(setup_ret, __FUNCTION__, "derive the pending renegotiation key block without replacing active keys");
        const binary_t pending_client_key = writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key_renegotiation);
        const binary_t pending_server_key = writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key_renegotiation);
        _test_case.assert(16 == pending_client_key.size() && 16 == pending_server_key.size(), __FUNCTION__, "derive both AES-128 directional renegotiation keys");
        _test_case.assert(binary_t(16, 0x11) == writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "keep the active client key unchanged while deriving pending keys");
        _test_case.assert(binary_t(16, 0x12) == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "keep the active server key unchanged while deriving pending keys");
        writer.set_recordno(from_client, 101);
        writer.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&writer);

        return_t ret = ccs.write(from_client, client_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write the client renegotiation CCS");
        _test_case.assert((client_ccs_wire.size() > ccs_wire.size()) && (0x14 == client_ccs_wire[0]), __FUNCTION__,
                          "encrypt the client CCS under the old client write state");
        _test_case.assert(pending_client_key == writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "activate the derived client write key at client CCS");
        _test_case.assert(binary_t(16, 0x12) == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "preserve the old server write key until server CCS");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset only the client record sequence at renegotiation CCS");
        _test_case.assert(103 == writer.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence until its CCS");
        _test_case.assert(1 == writer.get_session_info(from_client).get_keyvalue().get(session_tls12_renegotiation_ccs), __FUNCTION__,
                          "remember that the client direction has switched");

        writer.update_session_status(session_status_client_finished);
        ret = ccs.write(from_server, server_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write the server renegotiation CCS after Client Finished");
        _test_case.assert((server_ccs_wire.size() > ccs_wire.size()) && (0x14 == server_ccs_wire[0]), __FUNCTION__,
                          "encrypt the server CCS under the old server write state");
        _test_case.assert(pending_server_key == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "activate the derived server write key at server CCS");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset the server record sequence at its CCS");
        binary_t duplicate_wire;
        _test_case.assert(errorcode_t::unexpected == ccs.write(from_client, duplicate_wire), __FUNCTION__, "reject a duplicate client CCS in one renegotiation");
    }

    {
        tls_session reader;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(reader);
        _test_case.test(setup_ret, __FUNCTION__, "derive the matching pending read key block");
        const binary_t pending_client_key = reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key_renegotiation);
        const binary_t pending_server_key = reader.get_tls_protection().get_secrets().get(tls_secret_t::server_key_renegotiation);
        reader.set_recordno(from_client, 101);
        reader.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_client, client_ccs_wire.data(), client_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the client renegotiation CCS under the old client read state");
        _test_case.assert(client_ccs_wire.size() == pos, __FUNCTION__, "consume the encrypted client CCS");
        _test_case.assert(pending_client_key == reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "activate the derived client read key at client CCS");
        _test_case.assert(103 == reader.get_recordno(from_server), __FUNCTION__, "preserve the server read sequence until its CCS");

        reader.update_session_status(session_status_client_finished);
        pos = 0;
        ret = ccs.read(from_server, server_ccs_wire.data(), server_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the server renegotiation CCS under the old server read state");
        _test_case.assert(server_ccs_wire.size() == pos, __FUNCTION__, "consume the encrypted server CCS");
        _test_case.assert(pending_server_key == reader.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "activate the derived server read key at server CCS");
        _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "reset the server read sequence at its CCS");
    }
    {
        tls_session reader;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(reader);
        _test_case.test(setup_ret, __FUNCTION__, "prepare a renegotiation CCS receiver with active and pending keys");
        reader.get_tls_protection().set_cipher_suite(0);
        reader.get_session_info(from_client).reset_protection();
        const binary_t plaintext_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_client, plaintext_ccs.data(), plaintext_ccs.size(), pos);
        _test_case.assert(errorcode_t::internal_error == ret, __FUNCTION__, "report an internal error when CCS has no negotiated cipher suite");
        _test_case.assert(1 == test_count_fatal_alert(reader, from_client, tls_alertdesc_t::internal_error), __FUNCTION__,
                          "queue fatal internal_error for missing CCS cipher-suite state");
        _test_case.assert(binary_t(16, 0x11) == reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "leave the active client key unchanged when CCS activation cannot proceed");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "do not reset the client record sequence when CCS activation fails");
    }
}

static void test_tls12_initial_secure_renegotiation_scsv() {
    // Scenario: an initial TLS 1.2 handshake negotiates secure renegotiation
    // with a peer that may or may not signal RFC 5746 support.
    // Action: inspect the ClientHello SCSV, the ServerHello renegotiation_info
    // response, and behavior for unsolicited or missing responses.
    // Expected: SCSV is used only as a signal (not a negotiable suite), the
    // initial empty renegotiation_info response is validated, and TLS 1.3
    // ClientHello generation does not use the TLS 1.2 SCSV.
    _test_case.begin("TLS 1.2 ClientHello signals secure renegotiation with SCSV");

    tls_session client;
    client.get_tls_protection().set_tls_version(tls1_2);
    client.get_keyvalue().set(session_tls_version, tls1_2);
    tls_handshake_client_hello hello(&client);
    hello.add_ciphersuite(0xc02f);
    auto versions = new tls_extension_client_supported_versions(&hello);
    versions->add(tls1_2);
    hello.get_extensions().add(versions);

    binary_t wire;
    return_t ret = hello.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize an initial TLS 1.2 ClientHello");
    if (errorcode_t::success == ret) {
        const size_t session_id_length_offset = 4 + 2 + 32;
        size_t cipher_suite_length_offset = session_id_length_offset + 1;
        if (wire.size() > session_id_length_offset) {
            cipher_suite_length_offset += wire[session_id_length_offset];
        }
        bool has_scsv =
            (wire.size() >= cipher_suite_length_offset + 6) && (wire[cipher_suite_length_offset + 4] == 0x00) && (wire[cipher_suite_length_offset + 5] == 0xff);
        uint16 cipher_suite_length =
            (wire.size() >= cipher_suite_length_offset + 2) ? static_cast<uint16>((wire[cipher_suite_length_offset] << 8) | wire[cipher_suite_length_offset + 1]) : 0;
        _test_case.assert(4 == cipher_suite_length, __FUNCTION__, "append one two-byte SCSV after the offered TLS 1.2 cipher suite");
        _test_case.assert(has_scsv, __FUNCTION__, "encode TLS_EMPTY_RENEGOTIATION_INFO_SCSV as 0x00ff");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                          "remember that the client signaled secure renegotiation");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        tls_handshake_client_hello peer_hello(&server);
        size_t pos = 0;
        ret = peer_hello.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "parse the peer ClientHello carrying the SCSV");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete ClientHello");
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__, "recognize the peer's secure-renegotiation signal");

        bool scsv_in_negotiation_list = false;
        server.get_tls_protection().get_protection_context().for_each_cipher_suites([&](uint16 offered, bool* stop) -> void {
            if (0x00ff == offered) {
                scsv_in_negotiation_list = true;
                *stop = true;
            }
        });
        _test_case.assert(false == scsv_in_negotiation_list, __FUNCTION__, "exclude the signaling value from cipher-suite negotiation");

        {
            tls_session server_hello_session;
            server_hello_session.get_tls_protection().set_tls_version(tls1_2);
            server_hello_session.get_keyvalue().set(session_tls_version, tls1_2);
            server_hello_session.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
            server_hello_session.update_session_status(session_status_client_hello);
            tls_handshake_server_hello server_hello(&server_hello_session);
            server_hello.set_version(tls1_2);
            ret = server_hello.set_cipher_suite(0xc02f);
            _test_case.test(ret, __FUNCTION__, "select a TLS 1.2 suite for the secure-renegotiation response");
            binary_t server_hello_wire;
            if (errorcode_t::success == ret) {
                ret = server_hello.write(from_server, server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello after the peer signaled secure renegotiation");
                if (errorcode_t::success == ret) {
                    const binary_t renegotiation_info_wire{0xff, 0x01, 0x00, 0x01, 0x00};
                    bool has_renegotiation_info = (std::search(server_hello_wire.begin(), server_hello_wire.end(), renegotiation_info_wire.begin(),
                                                               renegotiation_info_wire.end()) != server_hello_wire.end());
                    _test_case.assert(has_renegotiation_info, __FUNCTION__, "echo an empty renegotiation_info extension in the initial ServerHello");
                    _test_case.assert(1 == server_hello_session.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "record that secure renegotiation was established");

                    tls_session client_peer;
                    client_peer.get_tls_protection().set_tls_version(tls1_2);
                    client_peer.get_keyvalue().set(session_tls_version, tls1_2);
                    client_peer.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
                    client_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    client_peer.update_session_status(session_status_client_hello);
                    tls_handshake_server_hello parsed_server_hello(&client_peer);
                    size_t client_pos = 0;
                    return_t client_ret = parsed_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), client_pos);
                    _test_case.test(client_ret, __FUNCTION__, "accept the empty renegotiation_info response after signaling support");
                    _test_case.assert(1 == client_peer.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "record secure renegotiation on the client after ServerHello validation");

                    tls_session unsolicited_peer;
                    unsolicited_peer.get_tls_protection().set_tls_version(tls1_2);
                    unsolicited_peer.get_keyvalue().set(session_tls_version, tls1_2);
                    unsolicited_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    unsolicited_peer.update_session_status(session_status_client_hello);
                    tls_handshake_server_hello unsolicited_server_hello(&unsolicited_peer);
                    size_t unsolicited_pos = 0;
                    client_ret = unsolicited_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), unsolicited_pos);
                    _test_case.assert(errorcode_t::handshake_failure == client_ret, __FUNCTION__, "reject renegotiation_info when the client did not signal support");
                    _test_case.assert(1 == test_count_fatal_alert(unsolicited_peer, from_server, tls_alertdesc_t::unsupported_extension), __FUNCTION__,
                                      "queue fatal unsupported_extension for an unsolicited response");
                }
            }
        }

        binary_t legacy_server_hello_wire;
        {
            tls_session legacy_server;
            legacy_server.get_tls_protection().set_tls_version(tls1_2);
            legacy_server.get_keyvalue().set(session_tls_version, tls1_2);
            legacy_server.update_session_status(session_status_client_hello);
            tls_handshake_server_hello legacy_server_hello(&legacy_server);
            legacy_server_hello.set_version(tls1_2);
            ret = legacy_server_hello.set_cipher_suite(0xc02f);
            _test_case.test(ret, __FUNCTION__, "select a TLS 1.2 suite without a secure-renegotiation offer");
            if (errorcode_t::success == ret) {
                ret = legacy_server_hello.write(from_server, legacy_server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello without a secure-renegotiation offer");
                if (errorcode_t::success == ret) {
                    const binary_t renegotiation_info_wire{0xff, 0x01, 0x00, 0x01, 0x00};
                    bool has_renegotiation_info = (std::search(legacy_server_hello_wire.begin(), legacy_server_hello_wire.end(), renegotiation_info_wire.begin(),
                                                               renegotiation_info_wire.end()) != legacy_server_hello_wire.end());
                    _test_case.assert(false == has_renegotiation_info, __FUNCTION__, "do not send an unsolicited renegotiation_info extension");
                    _test_case.assert(0 == legacy_server.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "leave secure renegotiation unestablished without a peer signal");
                }
            }
        }

        tls_session missing_response_peer;
        missing_response_peer.get_tls_protection().set_tls_version(tls1_2);
        missing_response_peer.get_keyvalue().set(session_tls_version, tls1_2);
        missing_response_peer.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
        missing_response_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
        missing_response_peer.update_session_status(session_status_client_hello);
        tls_handshake_server_hello missing_response(&missing_response_peer);
        size_t missing_response_pos = 0;
        return_t missing_response_ret = missing_response.read(from_server, legacy_server_hello_wire.data(), legacy_server_hello_wire.size(), missing_response_pos);
        _test_case.assert(errorcode_t::handshake_failure == missing_response_ret, __FUNCTION__,
                          "reject an initial ServerHello that omits renegotiation_info after the client signaled support");
        _test_case.assert(0 == missing_response_peer.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                          "do not establish secure renegotiation when the server omits the required response");
        _test_case.assert(1 == test_count_fatal_alert(missing_response_peer, from_server, tls_alertdesc_t::handshake_failure), __FUNCTION__,
                          "queue one fatal handshake_failure for the missing initial response");
    }

    {
        tls_session tls13_client;
        tls13_client.get_tls_protection().set_tls_version(tls1_3);
        tls13_client.get_keyvalue().set(session_tls_version, tls1_3);
        tls_handshake_client_hello tls13_hello(&tls13_client);
        tls13_hello.add_ciphersuite(0x1301);
        auto tls13_versions = new tls_extension_client_supported_versions(&tls13_hello);
        tls13_versions->add(tls1_3);
        tls13_hello.get_extensions().add(tls13_versions);
        binary_t tls13_wire;
        ret = tls13_hello.write(from_client, tls13_wire);
        _test_case.test(ret, __FUNCTION__, "serialize a TLS 1.3-only ClientHello");
        if (errorcode_t::success == ret) {
            const size_t cipher_suite_length_offset = 4 + 2 + 32 + 1;
            uint16 cipher_suite_length = (tls13_wire.size() >= cipher_suite_length_offset + 2)
                                             ? static_cast<uint16>((tls13_wire[cipher_suite_length_offset] << 8) | tls13_wire[cipher_suite_length_offset + 1])
                                             : 0;
            _test_case.assert(2 == cipher_suite_length, __FUNCTION__, "do not append the TLS 1.2 renegotiation SCSV to a TLS 1.3-only offer");
            _test_case.assert(0 == tls13_client.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                              "do not mark TLS 1.3 as secure-renegotiation capable");
        }
    }
}

static void test_tls12_hello_request_secure_renegotiation() {
    // Scenario: a server requests renegotiation from a client with an
    // established TLS 1.2 connection, both with and without secure-renegotiation
    // permission and the RFC 5746 binding.
    // Action: serialize and parse HelloRequest, then inspect flow restoration
    // and the warning sent when the client declines the request.
    // Expected: an enabled, securely negotiated connection enters renegotiation;
    // a client without the required permission stays in the established flow
    // and sends no_renegotiation.
    // RFC 5746: HelloRequest is not part of the handshake transcript.
    _test_case.begin("TLS 1.2 HelloRequest starts secure renegotiation");

    const binary_t hello_request_wire{0x00, 0x00, 0x00, 0x00};

    {
        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        server.update_session_status(session_status_client_finished);
        server.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&server).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the server HelloRequest");
        if (nullptr != request) {
            binary_t wire;
            return_t ret = request->write(from_server, wire);
            _test_case.test(ret, __FUNCTION__, "write HelloRequest after a secure TLS 1.2 handshake");
            _test_case.assert(hello_request_wire == wire, __FUNCTION__, "encode HelloRequest with an empty body");
            _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "start the server-side renegotiation flow");
            request->release();
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&client).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the client HelloRequest parser");
        if (nullptr != request) {
            size_t pos = 0;
            return_t ret = request->read(from_server, hello_request_wire.data(), hello_request_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "accept the server HelloRequest after a secure TLS 1.2 handshake");
            _test_case.assert(hello_request_wire.size() == pos, __FUNCTION__, "consume the complete HelloRequest");
            _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "start the client-side renegotiation flow");
            request->release();
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&client).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the disabled-policy HelloRequest parser");
        if (nullptr != request) {
            size_t pos = 0;
            return_t ret = request->read(from_server, hello_request_wire.data(), hello_request_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "decline HelloRequest when secure renegotiation is not enabled");
            _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "keep the established flow when renegotiation is declined");
            size_t warning_count = 0;
            client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::warning == level) && (tls_alertdesc_t::no_renegotiation == desc)) {
                    ++warning_count;
                }
            });
            _test_case.assert(1 == warning_count, __FUNCTION__, "queue one warning no_renegotiation alert");
            request->release();

            tls_session server;
            server.get_tls_protection().set_tls_version(tls1_2);
            server.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            tls_record_alert warning(&client, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
            binary_t warning_wire;
            ret = warning.write(from_client, warning_wire);
            _test_case.test(ret, __FUNCTION__, "serialize the client's no_renegotiation warning");
            tls_record_alert peer_warning(&server);
            pos = 0;
            ret = peer_warning.read(from_client, warning_wire.data(), warning_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "receive the client's no_renegotiation warning");
            _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                              "restore the server's established flow after the client declines");
            const uint32 completed_status = session_status_client_finished | session_status_server_finished;
            _test_case.assert(completed_status == (server.get_session_status() & completed_status), __FUNCTION__,
                              "restore the completed-handshake status after the client declines");
            _test_case.assert(tls_handshake_type_t::finished == server.get_session_info(from_client).get_status(), __FUNCTION__,
                              "restore the client handshake cursor after the client declines");
        }
    }
}

static void test_tls12_renegotiation_policy_and_binding() {
    // TLS 1.2 renegotiation is policy-gated and requires the RFC 5746 binding.
    // Action: serialize and parse a post-handshake ClientHello with both gates enabled.
    // Expected: enter the renegotiation flow and carry the previous client Finished verify_data.
    _test_case.begin("TLS 1.2 renegotiation policy gate and binding validation");

    {
        const binary_t client_verifydata(12, 0x31);
        const binary_t server_verifydata(12, 0x42);
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
        const binary_t prior_alpn{0x02, 'h', '2'};
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1234);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 2345);
        client.get_keyvalue().set(session_tls1_2_ticket_resumed, 1);

        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0xc02f);
        auto versions = new tls_extension_client_supported_versions(&hello);
        versions->add(tls1_2);
        hello.get_extensions().add(versions);
        binary_t wire;
        return_t ret = hello.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "write a secure renegotiation ClientHello when policy and RFC 5746 are enabled");
        _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__,
                          "enter the renegotiation flow before serializing the new ClientHello");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "retain active ALPN until the peer accepts renegotiation");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the client record-size limit until the peer accepts renegotiation");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the server record-size limit until the peer accepts renegotiation");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls1_2_ticket_resumed), __FUNCTION__,
                          "retain active resumption state until the peer accepts renegotiation");
        auto renegotiation_info = hello.get_extensions().get(tls_extension_type_t::renegotiation_info);
        _test_case.assert(nullptr != renegotiation_info, __FUNCTION__, "automatically include renegotiation_info in the renegotiation ClientHello");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        server.update_session_status(session_status_client_finished);
        server.update_session_status(session_status_server_finished);
        server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
        server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
        tls_handshake_client_hello peer_hello(&server);
        size_t pos = 0;
        ret = peer_hello.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "accept the matching RFC 5746 binding on the peer");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete renegotiation ClientHello");
        _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "enter the renegotiation flow on the receiving endpoint");
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                          "recognize the renegotiation_info extension as the secure-renegotiation signal");

        {
            // A policy-disabled endpoint declines a valid peer renegotiation
            // with warning no_renegotiation and leaves the active connection intact.
            tls_session refusing_server;
            refusing_server.get_tls_protection().set_tls_version(tls1_2);
            refusing_server.get_tls_protection().set_cipher_suite(0xc02f);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
            refusing_server.get_keyvalue().set(session_tls_version, tls1_2);
            refusing_server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
            refusing_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
            refusing_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
            refusing_server.update_session_status(session_status_client_finished);
            refusing_server.update_session_status(session_status_server_finished);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
            const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
            const binary_t prior_alpn{0x02, 'h', '2'};
            refusing_server.set_client_server_name(prior_server_name);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
            refusing_server.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 1234);
            refusing_server.set_recordno(from_client, 77);
            refusing_server.set_recordno(from_server, 79);

            tls_handshake_client_hello declined_hello(&refusing_server);
            size_t declined_pos = 0;
            return_t declined_ret = declined_hello.read(from_client, wire.data(), wire.size(), declined_pos);
            _test_case.test(declined_ret, __FUNCTION__, "decline a valid peer renegotiation when local policy is disabled");
            _test_case.assert(wire.size() == declined_pos, __FUNCTION__, "consume the declined ClientHello");
            _test_case.assert(tls_flow_t::one_rtt == refusing_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "retain the established TLS flow after declining renegotiation");
            const uint32 completed_status = session_status_client_finished | session_status_server_finished;
            _test_case.assert(completed_status == (refusing_server.get_session_status() & completed_status), __FUNCTION__,
                              "preserve completed-handshake status after declining renegotiation");
            _test_case.assert(tls_handshake_type_t::finished == refusing_server.get_session_info(from_client).get_status(), __FUNCTION__,
                              "preserve the client handshake cursor after declining renegotiation");
            _test_case.assert(tls_handshake_type_t::finished == refusing_server.get_session_info(from_server).get_status(), __FUNCTION__,
                              "preserve the server handshake cursor after declining renegotiation");
            _test_case.assert(77 == refusing_server.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence");
            _test_case.assert(79 == refusing_server.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence");
            _test_case.assert(binary_t(16, 0x11) == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                              "preserve the active client traffic key");
            _test_case.assert(binary_t(16, 0x12) == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                              "preserve the active server traffic key");
            _test_case.assert(prior_server_name == refusing_server.get_client_server_name(), __FUNCTION__, "preserve the active connection's server name");
            _test_case.assert(prior_alpn == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                              "preserve the active connection's negotiated ALPN");
            _test_case.assert(1234 == refusing_server.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "preserve the active connection's record_size_limit state");
            size_t warning_count = 0;
            refusing_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::warning == level) && (tls_alertdesc_t::no_renegotiation == desc)) {
                    ++warning_count;
                }
            });
            _test_case.assert(1 == warning_count, __FUNCTION__, "queue one warning no_renegotiation alert");
            _test_case.assert(0 == test_count_fatal_alerts(refusing_server, from_client), __FUNCTION__, "do not terminate the active connection with a fatal alert");
        }

        // A peer must not be able to alter the previous client Finished value
        // while retaining an otherwise well-formed renegotiation_info extension.
        {
            binary_t bad_binding_wire = wire;
            binary_t client_binding_prefix{0xff, 0x01, 0x00, 0x0d, 0x0c};
            binary_append(client_binding_prefix, client_verifydata);
            auto binding = std::search(bad_binding_wire.begin(), bad_binding_wire.end(), client_binding_prefix.begin(), client_binding_prefix.end());
            _test_case.assert(binding != bad_binding_wire.end(), __FUNCTION__, "locate the ClientHello renegotiation_info binding");
            if (binding != bad_binding_wire.end()) {
                *(binding + client_binding_prefix.size() - 1) ^= 0x01;

                tls_session bad_server;
                bad_server.get_tls_protection().set_tls_version(tls1_2);
                bad_server.get_keyvalue().set(session_tls_version, tls1_2);
                bad_server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
                bad_server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
                bad_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                bad_server.update_session_status(session_status_client_finished);
                bad_server.update_session_status(session_status_server_finished);
                bad_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
                bad_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);

                tls_handshake_client_hello bad_peer(&bad_server);
                size_t bad_pos = 0;
                return_t bad_ret = bad_peer.read(from_client, bad_binding_wire.data(), bad_binding_wire.size(), bad_pos);
                _test_case.assert(errorcode_t::illegal_parameter == bad_ret, __FUNCTION__, "reject a ClientHello with a mismatched previous client Finished binding");
                _test_case.assert(1 == test_count_fatal_alert(bad_server, from_client, tls_alertdesc_t::illegal_parameter), __FUNCTION__,
                                  "queue fatal illegal_parameter for a mismatched ClientHello binding");
            }
        }

        tls_handshake_server_hello server_hello(&server);
        server_hello.set_version(tls1_2);
        ret = server_hello.set_cipher_suite(0xc02f);
        _test_case.test(ret, __FUNCTION__, "select the TLS 1.2 suite for the renegotiation ServerHello");
        binary_t server_hello_wire;
        if (errorcode_t::success == ret) {
            ret = server_hello.write(from_server, server_hello_wire);
            _test_case.test(ret, __FUNCTION__, "write ServerHello with the previous client and server Finished values");
        }
        if (errorcode_t::success == ret) {
            _test_case.assert(nullptr != server_hello.get_extensions().get(tls_extension_type_t::renegotiation_info), __FUNCTION__,
                              "include the ServerHello renegotiation_info extension");

            client.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
            client.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
            client.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
            client.update_session_status(session_status_client_hello);
            tls_handshake_server_hello peer_server_hello(&client);
            size_t server_pos = 0;
            ret = peer_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_pos);
            _test_case.test(ret, __FUNCTION__, "validate the server's previous Finished verify_data binding");
            _test_case.assert(server_hello_wire.size() == server_pos, __FUNCTION__, "consume the complete renegotiation ServerHello");
            _test_case.assert(binary_t() == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                              "clear the previous ALPN after the peer accepts renegotiation without a new ALPN selection");
            _test_case.assert(0 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "clear the previous client record-size limit after ServerHello acceptance");
            _test_case.assert(0 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "clear the previous server record-size limit after ServerHello acceptance");
            _test_case.assert(0 == client.get_keyvalue().get(session_tls1_2_ticket_resumed), __FUNCTION__,
                              "reset the previous resumption mode for the accepted renegotiation");

            // Both Finished values are part of the ServerHello renegotiation_info
            // binding. A client must reject a peer that changes either value.
            {
                binary_t server_binding_prefix{0xff, 0x01, 0x00, 0x19, 0x18};
                binary_append(server_binding_prefix, client_verifydata);
                binary_append(server_binding_prefix, server_verifydata);
                const size_t binding_offsets[] = {5, 5 + client_verifydata.size()};
                const char* mismatch_messages[] = {
                    "reject ServerHello with mismatched previous client Finished binding",
                    "reject ServerHello with mismatched previous server Finished binding",
                };
                const char* alert_messages[] = {
                    "queue fatal illegal_parameter for mismatched previous client Finished binding",
                    "queue fatal illegal_parameter for mismatched previous server Finished binding",
                };
                for (size_t i = 0; i < sizeof(binding_offsets) / sizeof(binding_offsets[0]); ++i) {
                    binary_t bad_server_hello_wire = server_hello_wire;
                    auto binding = std::search(bad_server_hello_wire.begin(), bad_server_hello_wire.end(), server_binding_prefix.begin(), server_binding_prefix.end());
                    _test_case.assert(binding != bad_server_hello_wire.end(), __FUNCTION__, "locate the ServerHello renegotiation_info binding");
                    if (binding == bad_server_hello_wire.end()) {
                        continue;
                    }
                    *(binding + binding_offsets[i]) ^= 0x01;

                    tls_session bad_client;
                    bad_client.get_tls_protection().set_tls_version(tls1_2);
                    bad_client.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    bad_client.get_tls_protection().set_flow(tls_flow_t::renegotiation);
                    bad_client.get_keyvalue().set(session_tls_version, tls1_2);
                    bad_client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
                    bad_client.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
                    bad_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                    bad_client.update_session_status(session_status_client_finished);
                    bad_client.update_session_status(session_status_server_finished);
                    bad_client.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
                    bad_client.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
                    bad_client.update_session_status(session_status_client_hello);

                    tls_handshake_server_hello bad_peer_server_hello(&bad_client);
                    size_t bad_server_pos = 0;
                    return_t bad_server_ret = bad_peer_server_hello.read(from_server, bad_server_hello_wire.data(), bad_server_hello_wire.size(), bad_server_pos);
                    _test_case.assert(errorcode_t::illegal_parameter == bad_server_ret, __FUNCTION__, mismatch_messages[i]);
                    _test_case.assert(1 == test_count_fatal_alert(bad_client, from_server, tls_alertdesc_t::illegal_parameter), __FUNCTION__, alert_messages[i]);
                }
            }
        }
    }

    {
        tls_session renegotiating_client;
        renegotiating_client.get_tls_protection().set_tls_version(tls1_2);
        renegotiating_client.get_keyvalue().set(session_tls_version, tls1_2);
        renegotiating_client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        renegotiating_client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        renegotiating_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        renegotiating_client.update_session_status(session_status_client_finished);
        renegotiating_client.update_session_status(session_status_server_finished);
        tls_handshake_client_hello invalid_writer(&renegotiating_client);
        invalid_writer.add_ciphersuite(0xc02f);
        invalid_writer.add_ciphersuite(0x00ff);
        binary_t invalid_wire;
        return_t invalid_ret = invalid_writer.write(from_client, invalid_wire);
        _test_case.assert(errorcode_t::bad_request == invalid_ret, __FUNCTION__, "refuse to serialize SCSV in a secure renegotiation ClientHello");
        _test_case.assert(invalid_wire.empty(), __FUNCTION__, "emit no ClientHello containing renegotiation SCSV");
        _test_case.assert(tls_flow_t::one_rtt == renegotiating_client.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the established flow when rejecting an invalid local offer");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (renegotiating_client.get_session_status() & completed_status), __FUNCTION__,
                          "preserve the completed-handshake status when rejecting an invalid local offer");

        tls_session initial_client;
        initial_client.get_tls_protection().set_tls_version(tls1_2);
        initial_client.get_keyvalue().set(session_tls_version, tls1_2);
        tls_handshake_client_hello scsv_client_hello(&initial_client);
        scsv_client_hello.add_ciphersuite(0xc02f);
        scsv_client_hello.add_ciphersuite(0x00ff);
        auto versions = new tls_extension_client_supported_versions(&scsv_client_hello);
        versions->add(tls1_2);
        scsv_client_hello.get_extensions().add(versions);
        binary_t scsv_wire;
        invalid_ret = scsv_client_hello.write(from_client, scsv_wire);
        _test_case.test(invalid_ret, __FUNCTION__, "construct a ClientHello carrying the initial SCSV signal");
        if (errorcode_t::success == invalid_ret) {
            tls_session renegotiating_server;
            renegotiating_server.get_tls_protection().set_tls_version(tls1_2);
            renegotiating_server.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            tls_handshake_client_hello invalid_peer(&renegotiating_server);
            size_t invalid_pos = 0;
            invalid_ret = invalid_peer.read(from_client, scsv_wire.data(), scsv_wire.size(), invalid_pos);
            _test_case.assert(errorcode_t::handshake_failure == invalid_ret, __FUNCTION__, "reject SCSV received in an established secure renegotiation");
            _test_case.assert(1 == test_count_fatal_alert(renegotiating_server, from_client, tls_alertdesc_t::handshake_failure), __FUNCTION__,
                              "queue fatal handshake_failure for renegotiation SCSV");
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.set_recordno(from_client, 81);
        client.set_recordno(from_server, 83);
        const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
        const binary_t prior_alpn{0x02, 'h', '2'};
        client.set_client_server_name(prior_server_name);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 1234);

        tls_handshake_client_hello hello(&client);
        binary_t wire;
        return_t ret = hello.write(from_client, wire);
        _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__, "reject a locally initiated TLS 1.2 renegotiation");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no ClientHello for a prohibited renegotiation");
        _test_case.assert(0 == test_count_fatal_alerts(client, from_client), __FUNCTION__, "do not queue an alert for a locally rejected renegotiation attempt");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (client.get_session_status() & completed_status), __FUNCTION__,
                          "preserve completed-handshake status after local rejection");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "preserve the client handshake cursor after local rejection");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_server).get_status(), __FUNCTION__,
                          "preserve the server handshake cursor after local rejection");
        _test_case.assert(81 == client.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence after local rejection");
        _test_case.assert(83 == client.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence after local rejection");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "preserve the active connection's server name");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "preserve the active connection's negotiated ALPN");
        _test_case.assert(1234 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the active connection's record_size_limit state");
        size_t local_alert_count = 0;
        client.get_alert(from_client, [&](tls_alertlevel_t, tls_alertdesc_t) -> void { ++local_alert_count; });
        _test_case.assert(0 == local_alert_count, __FUNCTION__, "do not queue any alert for a local policy rejection");
    }

    {
        // If a locally initiated renegotiation is declined by the peer, the
        // client must restore the still-active TLS 1.2 connection.
        const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
        const binary_t prior_alpn{0x02, 'h', '2'};
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_tls_protection().set_cipher_suite(0xc02f);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
        client.get_tls_protection().get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.get_keyvalue().set(session_tls1_2_ticket_resumed, 1);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.set_recordno(from_client, 91);
        client.set_recordno(from_server, 93);
        client.set_client_server_name(prior_server_name);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1234);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 2345);

        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0xc02f);
        auto versions = new tls_extension_client_supported_versions(&hello);
        versions->add(tls1_2);
        hello.get_extensions().add(versions);
        binary_t client_hello_wire;
        return_t ret = hello.write(from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "send a locally initiated secure renegotiation ClientHello");
        _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "enter renegotiation while awaiting the peer's response");
        _test_case.assert(tls_handshake_type_t::client_hello == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "record the outstanding ClientHello while awaiting the peer's response");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "retain the active server name while awaiting renegotiation acceptance");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "retain the active ALPN while awaiting renegotiation acceptance");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the client record-size limit while awaiting renegotiation acceptance");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the server record-size limit while awaiting renegotiation acceptance");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls1_2_ticket_resumed), __FUNCTION__,
                          "retain the active resumption state while awaiting renegotiation acceptance");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        tls_record_alert server_warning(&server, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
        binary_t alert_wire;
        ret = server_warning.write(from_server, alert_wire);
        _test_case.test(ret, __FUNCTION__, "serialize the peer's no_renegotiation warning");

        tls_record_alert client_warning(&client);
        size_t alert_pos = 0;
        ret = client_warning.read(from_server, alert_wire.data(), alert_wire.size(), alert_pos);
        _test_case.test(ret, __FUNCTION__, "receive the peer's no_renegotiation warning");
        _test_case.assert(alert_wire.size() == alert_pos, __FUNCTION__, "consume the no_renegotiation alert");
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "restore the established flow after the peer declines");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (client.get_session_status() & completed_status), __FUNCTION__,
                          "restore completed-handshake status after the peer declines");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "restore the client handshake cursor after the peer declines");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_server).get_status(), __FUNCTION__,
                          "restore the server handshake cursor after the peer declines");
        _test_case.assert(91 == client.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence after peer refusal");
        _test_case.assert(93 == client.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence after peer refusal");
        _test_case.assert(binary_t(16, 0x11) == client.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "preserve the active client traffic key after peer refusal");
        _test_case.assert(binary_t(16, 0x12) == client.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "preserve the active server traffic key after peer refusal");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "preserve the active server name after peer refusal");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__, "preserve the active ALPN after peer refusal");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the client record-size limit after peer refusal");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the server record-size limit after peer refusal");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls1_2_ticket_resumed), __FUNCTION__, "preserve the active resumption state after peer refusal");
    }
}

static void test_tls12_composer_reports_renegotiation_refusal() {
    // Scenario: a securely established TLS 1.2 client starts renegotiation,
    // but the peer declines before sending ServerHello.
    // Action: run the client composer with a peer response that restores the
    // established flow without advancing the handshake.
    // Expected: return negotiation_failure, send only ClientHello, preserve
    // both Finished states, and queue no fatal alert.
    _test_case.begin("TLS 1.2 client composer returns when peer declines renegotiation");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);
    protection.set_flow(tls_flow_t::one_rtt);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
    session.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.update_session_status(session_status_client_finished);
    session.update_session_status(session_status_server_finished);
    protection.get_secrets().assign(tls_secret_t::client_verifydata, binary_t(12, 0x31));
    protection.get_secrets().assign(tls_secret_t::server_verifydata, binary_t(12, 0x42));

    tls_composer composer(&session);
    composer.set_minver(tls1_2);
    composer.set_maxver(tls1_2);

    size_t send_count = 0;
    return_t ret = composer.handshake(from_client, 1, [&](tls_session* current, binary_t& wire) -> return_t {
        ++send_count;
        _test_case.assert(false == wire.empty(), __FUNCTION__, "serialize the renegotiation ClientHello before waiting for the peer");

        // Model the state transition performed by tls_record_alert after
        // receiving warning no_renegotiation before ServerHello. The alert
        // parser's state-preservation behavior is covered separately.
        current->reset_session_status();
        current->update_session_status(static_cast<session_status_t>(session_status_client_finished | session_status_server_finished));
        current->get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        current->get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        current->get_tls_protection().set_flow(tls_flow_t::one_rtt);
        return errorcode_t::success;
    });

    _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__,
                      "return negotiation_failure when the peer restores the established flow without ServerHello");
    _test_case.assert(1 == send_count, __FUNCTION__, "send only the renegotiation ClientHello and no client key-exchange flight");
    _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "preserve the established TLS 1.2 flow after peer refusal");
    const uint32 completed_status = session_status_client_finished | session_status_server_finished;
    _test_case.assert(completed_status == (session.get_session_status() & completed_status), __FUNCTION__,
                      "preserve both completed-handshake status bits after peer refusal");
    _test_case.assert(tls_handshake_type_t::finished == session.get_session_info(from_client).get_status(), __FUNCTION__,
                      "preserve the client handshake cursor after peer refusal");
    _test_case.assert(tls_handshake_type_t::finished == session.get_session_info(from_server).get_status(), __FUNCTION__,
                      "preserve the server handshake cursor after peer refusal");
    _test_case.assert(0 == test_count_fatal_alerts(session, from_client), __FUNCTION__, "do not queue a fatal alert for a clean no_renegotiation refusal");
}

class test_trial_tls_client_socket : public trial_tls_client_socket {
   public:
    test_trial_tls_client_socket() : trial_tls_client_socket(tls1_2), _send_count(0), _disconnect_count(0), _close_count(0) {}

    void set_send_handler(std::function<return_t(tls_session*, binary_t&)> handler) { _send_handler = handler; }
    size_t send_count() const { return _send_count; }
    size_t disconnect_count() const { return _disconnect_count; }
    size_t close_count() const { return _close_count; }

   protected:
    virtual return_t do_send(binary_t& wire) override {
        ++_send_count;
        if (_send_handler) {
            return _send_handler(get_session(), wire);
        }
        return errorcode_t::success;
    }

    virtual return_t do_transport_disconnect() override {
        ++_disconnect_count;
        return secure_client_socket::do_transport_disconnect();
    }

    virtual return_t do_close() override {
        ++_close_count;
        return errorcode_t::success;
    }

   private:
    std::function<return_t(tls_session*, binary_t&)> _send_handler;
    size_t _send_count;
    size_t _disconnect_count;
    size_t _close_count;
};

static return_t test_configure_tls12_client_reserve_session(tls_session& session, bool renegotiation_enabled) {
    session.set_type(session_type_t::tls);
    return_t ret = test_configure_tls12_renegotiation_ccs_session(session);
    if (errorcode_t::success != ret) {
        return ret;
    }

    auto& protection = session.get_tls_protection();
    protection.set_flow(tls_flow_t::one_rtt);
    session.reset_session_status();
    session.update_session_status(session_status_client_finished);
    session.update_session_status(session_status_server_finished);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.get_keyvalue().set(session_conf_enable_tls12_renegotiation, renegotiation_enabled ? 1 : 0);
    session.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
    session.get_keyvalue().set(session_tls1_2_ticket_resumed, 1);
    protection.get_secrets().assign(tls_secret_t::client_verifydata, binary_t(12, 0x31));
    protection.get_secrets().assign(tls_secret_t::server_verifydata, binary_t(12, 0x42));

    constexpr uint64 sequence_max = ~static_cast<uint64>(0);
    constexpr uint64 sequence_reserve = 65535;
    constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
    session.set_recordno(from_client, sequence_reserve_start);
    return errorcode_t::success;
}

static void test_tls12_socket_send_triggers_renegotiation() {
    // Scenario: a TLS 1.2 client application send reaches the first reserved
    // write-sequence value, with local renegotiation policy disabled or enabled.
    // Action: send application data through the client socket wrapper.
    // Expected: disabled policy retires without emitting ClientHello; enabled
    // policy renegotiates first and retries application data only after success.
    const char* function_name = __FUNCTION__;
    const binary_t plaintext{'r', 'e', 'n', 'e', 'w'};
    const uint32 completed_status = session_status_client_finished | session_status_server_finished;

    _test_case.begin("TLS 1.2 client socket renegotiates at the application-data sequence reserve");

    {
        test_trial_tls_client_socket client;
        tls_session* session = client.get_session();
        return_t setup_ret = test_configure_tls12_client_reserve_session(*session, false);
        _test_case.test(setup_ret, function_name, "prepare an established TLS 1.2 session with local renegotiation disabled");

        size_t sent = 99;
        return_t ret = client.send((const char*)plaintext.data(), plaintext.size(), &sent);
        _test_case.assert(errorcode_t::negotiation_failure == ret, function_name, "surface the local renegotiation policy refusal");
        _test_case.assert(0 == sent, function_name, "do not report application data sent after local policy refusal");
        _test_case.assert(0 == client.send_count(), function_name, "do not write ClientHello when local renegotiation is disabled");
        _test_case.assert(1 == client.disconnect_count(), function_name, "notify the secure consumer that the connection is terminal");
        _test_case.assert(1 == client.close_count(), function_name, "retire the transport after local policy refusal");
        _test_case.assert(session->is_terminal(), function_name, "prevent further TLS I/O on the retired session");
    }

    {
        test_trial_tls_client_socket client;
        tls_session* session = client.get_session();
        return_t setup_ret = test_configure_tls12_client_reserve_session(*session, true);
        _test_case.test(setup_ret, function_name, "prepare secure TLS 1.2 renegotiation for the peer-refusal case");

        client.set_send_handler([&](tls_session* current, binary_t& wire) -> return_t {
            if (1 == client.send_count()) {
                _test_case.assert((false == wire.empty()) && (tls_content_type_t::handshake == static_cast<tls_content_type_t>(wire[0])), function_name,
                                  "send the renegotiation ClientHello before peer refusal");
                current->reset_session_status();
                current->update_session_status(static_cast<session_status_t>(completed_status));
                current->get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                current->get_session_info(from_server).set_status(tls_handshake_type_t::finished);
                current->get_tls_protection().set_flow(tls_flow_t::one_rtt);
            }
            return errorcode_t::success;
        });

        size_t sent = 99;
        return_t ret = client.send((const char*)plaintext.data(), plaintext.size(), &sent);
        _test_case.assert(errorcode_t::negotiation_failure == ret, function_name, "return the peer's no_renegotiation outcome");
        _test_case.assert(0 == sent, function_name, "do not retry application data after peer refusal");
        _test_case.assert(1 == client.send_count(), function_name, "send only ClientHello and no application-data record");
        _test_case.assert(1 == client.disconnect_count(), function_name, "wake the secure consumer on peer refusal");
        _test_case.assert(1 == client.close_count(), function_name, "retire the refused renegotiation transport");
        _test_case.assert(session->is_terminal(), function_name, "make the refused connection terminal");
    }

    {
        test_trial_tls_client_socket client;
        tls_session* session = client.get_session();
        return_t setup_ret = test_configure_tls12_client_reserve_session(*session, true);
        _test_case.test(setup_ret, function_name, "prepare secure TLS 1.2 abbreviated renegotiation");

        client.set_send_handler([&](tls_session* current, binary_t& wire) -> return_t {
            if (1 == client.send_count()) {
                _test_case.assert((false == wire.empty()) && (tls_content_type_t::handshake == static_cast<tls_content_type_t>(wire[0])), function_name,
                                  "send ClientHello before the simulated server flight");
                auto& protection = current->get_tls_protection();
                auto& secrets = protection.get_secrets();
                const binary_t master_secret = secrets.get(tls_secret_t::master);
                const binary_t client_random = secrets.get(tls_secret_t::client_hello_random);
                const binary_t server_random(32, 0x53);
                secrets.assign(tls_secret_t::server_hello_random, server_random);
                return_t keyblock_ret = protection.calc_keyblock(hash_algorithm_t::sha2_256, master_secret, client_random, server_random, 0xc02f);
                if (errorcode_t::success != keyblock_ret) {
                    return keyblock_ret;
                }
                current->update_session_status(session_status_server_hello);
                current->update_session_status(session_status_server_key_exchange);
                current->update_session_status(session_status_client_key_exchange);
                current->update_session_status(session_status_server_finished);
            }
            return errorcode_t::success;
        });

        size_t sent = 0;
        return_t ret = client.send((const char*)plaintext.data(), plaintext.size(), &sent);
        _test_case.assert(errorcode_t::success == ret, function_name, "complete the abbreviated renegotiation before retrying application data");
        _test_case.assert(plaintext.size() == sent, function_name, "report the original application payload sent after renegotiation");
        _test_case.assert(3 == client.send_count(), function_name, "serialize ClientHello, client CCS/Finished, then retried application data");
        _test_case.assert(0 == client.disconnect_count() && 0 == client.close_count(), function_name, "keep the transport open after successful renegotiation");
        _test_case.assert(false == session->is_terminal(), function_name, "keep the session usable after successful renegotiation");
        _test_case.assert(tls_flow_t::one_rtt == session->get_tls_protection().get_flow(), function_name, "return to one_rtt before retrying application data");
        _test_case.assert(session->get_recordno(from_client) >= 2, function_name, "consume fresh directional sequence numbers for Finished and application data");
    }
}

void testcase_gpt_renegotiation() {
    test_tls12_renegotiation_option_and_client_initiation();
    test_tls12_renegotiation_ccs_transition();
    test_tls12_initial_secure_renegotiation_scsv();
    test_tls12_hello_request_secure_renegotiation();
    test_tls12_renegotiation_policy_and_binding();
    test_tls12_composer_reports_renegotiation_refusal();
    test_tls12_socket_send_triggers_renegotiation();
    test_tls12_server_initiated_renegotiation();
    test_tls12_server_composer_renegotiation();
    test_tls12_server_send_joins_peer_initiated_renegotiation();
    test_tls12_server_outbound_reserve_requires_secure_renegotiation();
    test_tls12_directional_cipher_suite_switch_at_ccs();
    test_tls13_renegotiation_option_is_ignored();
}
