/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_renegotiation.cpp
 * @author GPT
 * @desc   TLS 1.2 RFC 5746 renegotiation policy, initiation, and directional cipher-suite tests.
 */

#include <algorithm>

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

void testcase_gpt_renegotiation() {
    test_tls12_renegotiation_option_and_client_initiation();
    test_tls12_server_initiated_renegotiation();
    test_tls12_directional_cipher_suite_switch_at_ccs();
    test_tls13_renegotiation_option_is_ignored();
}
