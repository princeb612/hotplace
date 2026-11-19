/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_early_data.cpp
 * @author GPT
 * @desc   TLS 1.3 early-data offer, acceptance, rejection, and handshake-flow tests.
 */

#include <atomic>
#include <chrono>
#include <thread>

#include "testcase_gpt_common.hpp"

static void test_tls13_fatal_reset_clears_hrr_flow() {
    // Scenario under test: TLS 1.3 fatal reset clears HelloRetryRequest flow.
    // Expected: clear aggregate handshake status after fatal failure.
    _test_case.begin("TLS 1.3 fatal reset clears HelloRetryRequest flow");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_flow(tls_flow_t::hello_retry_request);
    session.update_session_status(session_status_hello_retry_request);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);

    session.reset_session_status();

    _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "clear aggregate handshake status after fatal failure");
    _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "do not retain HRR flow for a fresh handshake");
    _test_case.assert(tls_handshake_type_t::client_hello == session.get_session_info(from_client).get_status(), __FUNCTION__, "reset the client handshake cursor");
    _test_case.assert(tls_handshake_type_t::client_hello == session.get_session_info(from_server).get_status(), __FUNCTION__, "reset the server handshake cursor");

    protection.set_flow(tls_flow_t::zero_rtt);
    session.reset_session_status();
    _test_case.assert(tls_flow_t::zero_rtt == protection.get_flow(), __FUNCTION__, "preserve the active zero-RTT flow during status reset");

    protection.set_flow(tls_flow_t::one_rtt);
    session.reset_session_status();
    _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "preserve the active one-RTT flow during status reset");
}

static void test_tls13_encrypted_extensions_failure_after_hrr_disables_client_protection() {
    // Scenario under test: a fatal EncryptedExtensions error after HRR retires any residual client protection.
    // Expected: reset_session_status() may clear HRR flow, but rollback must still reset the client direction.
    _test_case.begin("TLS 1.3 EncryptedExtensions failure after HRR disables client protection");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::hello_retry_request);
    session.update_session_status(session_status_hello_retry_request);
    session.get_session_info(from_client).begin_protection();

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::resumption_early, binary_t(32, 0x11));
    secrets.assign(tls_secret_t::resumption_binder_hash, binary_t(32, 0x22));
    secrets.assign(tls_secret_t::resumption_binder_key, binary_t(32, 0x33));
    secrets.assign(tls_secret_t::resumption_finished_key, binary_t(32, 0x44));
    secrets.assign(tls_secret_t::resumption_finished, binary_t(32, 0x55));
    secrets.assign(tls_secret_t::c_e_traffic, binary_t(32, 0x66));
    secrets.assign(tls_secret_t::e_exp_master, binary_t(32, 0x77));
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x88));
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x99));

    // An early_data indication is invalid here: HRR has already rejected 0-RTT
    // and the final ServerHello has not yet completed the retry.
    binary_t wire = {static_cast<byte_t>(tls_handshake_type_t::encrypted_extensions), 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
    tls_handshake_encrypted_extensions encrypted_extensions(&session);
    size_t pos = 0;
    return_t ret = encrypted_extensions.read(from_server, wire.data(), wire.size(), pos);

    size_t illegal_parameter_count = 0;
    session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++illegal_parameter_count;
        }
    });
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject early_data acceptance after HRR");
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for early_data acceptance after HRR");
    _test_case.assert(tls_flow_t::one_rtt == protection.get_flow(), __FUNCTION__, "clear HRR flow after fatal EncryptedExtensions failure");
    _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "disable residual client-direction protection after HRR failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "clear the provisional PSK Early Secret after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_binder_hash).empty(), __FUNCTION__, "clear the provisional binder hash after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_binder_key).empty(), __FUNCTION__, "clear the provisional binder key after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_finished_key).empty(), __FUNCTION__,
                      "clear the provisional binder Finished key after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_finished).empty(), __FUNCTION__,
                      "clear the provisional binder Finished value after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic).empty(), __FUNCTION__, "clear the client early traffic secret after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::e_exp_master).empty(), __FUNCTION__, "clear the early exporter master secret after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_key).empty(), __FUNCTION__, "clear the client early traffic key after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic_iv).empty(), __FUNCTION__, "clear the client early traffic IV after EncryptedExtensions failure");
}

static void test_tls13_encrypted_extensions_failure_clears_selected_psk_state() {
    // Scenario under test: invalid EncryptedExtensions after final ServerHello must retire the selected PSK state.
    // Expected: clear the peer-selected identity and ticket snapshots while retaining installed handshake keys for the fatal alert.
    _test_case.begin("TLS 1.3 EncryptedExtensions failure clears selected PSK state");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);

    tls_resumption_ticket ticket;
    ticket.identity = binary_t(1, 0x01);
    ticket.psk = binary_t(32, 0x11);
    ticket.version = tls_13;
    ticket.cipher_suite = 0x1301;
    ticket.max_early_data_size = 4096;
    session.set_offered_resumption_tickets(std::vector<tls_resumption_ticket>{ticket});
    session.set_early_data_ticket(ticket);
    session.get_keyvalue().set(session_server_psk_selected_identity, 1);
    session.get_keyvalue().set(session_server_psk_key_exchange_mode, 1);
    session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);

    auto& early_data_state = session.get_session_info(from_server).get_keyvalue();
    early_data_state.set(session_early_data_offered, 1);
    early_data_state.set(session_early_data_limit, 4096);

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::resumption_early, binary_t(32, 0x22));
    secrets.assign(tls_secret_t::resumption_binder_hash, binary_t(32, 0x33));
    secrets.assign(tls_secret_t::resumption_binder_key, binary_t(32, 0x44));
    secrets.assign(tls_secret_t::resumption_finished_key, binary_t(32, 0x55));
    secrets.assign(tls_secret_t::resumption_finished, binary_t(32, 0x66));
    secrets.assign(tls_secret_t::c_e_traffic, binary_t(32, 0x77));
    secrets.assign(tls_secret_t::e_exp_master, binary_t(32, 0x88));
    secrets.assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x99));
    secrets.assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0xaa));
    secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0xbb));

    session.get_session_info(from_client).begin_protection();
    session.set_recordno(from_client, 7);

    // Identity one cannot be used when the server accepts early data.
    binary_t wire = {static_cast<byte_t>(tls_handshake_type_t::encrypted_extensions), 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
    tls_handshake_encrypted_extensions encrypted_extensions(&session);
    size_t pos = 0;
    return_t ret = encrypted_extensions.read(from_server, wire.data(), wire.size(), pos);

    size_t illegal_parameter_count = 0;
    session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++illegal_parameter_count;
        }
    });
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject early_data acceptance for selected identity one");
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter");
    _test_case.assert(0xffff == session.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "clear the selected PSK identity after EncryptedExtensions failure");
    _test_case.assert(0xffff == session.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                      "clear the selected PSK key-exchange mode after EncryptedExtensions failure");
    _test_case.assert(0 == session.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "clear the selected PSK ticket cipher suite after EncryptedExtensions failure");
    _test_case.assert(session.get_offered_resumption_tickets().empty(), __FUNCTION__, "clear the offered-ticket snapshot after EncryptedExtensions failure");
    _test_case.assert(session.get_early_data_ticket().identity.empty(), __FUNCTION__, "clear the early-data ticket snapshot after EncryptedExtensions failure");
    _test_case.assert(secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "clear the rejected PSK Early Secret");
    _test_case.assert(secrets.get(tls_secret_t::c_e_traffic).empty(), __FUNCTION__, "clear the early traffic secret");
    _test_case.assert(false == secrets.get(tls_secret_t::c_hs_traffic).empty(), __FUNCTION__, "preserve the installed client handshake secret for the fatal alert");
    _test_case.assert(true == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "retain client handshake protection after final ServerHello");
    _test_case.assert(0 == session.get_recordno(from_client), __FUNCTION__, "reset the client record sequence for handshake protection");
}

static void test_tls13_fatal_reset_wakes_status_waiter() {
    // Scenario under test: TLS 1.3 fatal reset wakes handshake status waiters.
    // Expected: consume the prior status notification before waiting.
    _test_case.begin("TLS 1.3 fatal reset wakes handshake status waiters");

    tls_session session;
    session.update_session_status(session_status_server_hello);
    return_t ret = session.wait_change_session_status(session_status_server_finished, 1);
    _test_case.assert(errorcode_t::timeout == ret, __FUNCTION__, "consume the prior status notification before waiting");

    std::atomic<bool> wait_started(false);
    return_t wait_result = errorcode_t::success;
    std::thread waiter([&]() {
        wait_started.store(true);
        wait_result = session.wait_change_session_status(session_status_server_finished, 1000);
    });
    while (false == wait_started.load()) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    session.reset_session_status();
    waiter.join();

    _test_case.assert(errorcode_t::mismatch == wait_result, __FUNCTION__, "wake a blocked status waiter and report that its requested status was cleared");
}

static void test_tls13_end_of_early_data_usage_reset() {
    // Scenario under test: TLS 1.3 EndOfEarlyData directional usage reset.
    // Action: serialize EndOfEarlyData and switch the client traffic key.
    // Expected: serialize exactly the empty EndOfEarlyData handshake message.
    _test_case.begin("TLS 1.3 EndOfEarlyData directional usage reset");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);

    const binary_t client_handshake_secret(32, 0x11);
    const binary_t server_handshake_secret(32, 0x22);
    protection.get_secrets().assign(tls_secret_t::c_hs_traffic, client_handshake_secret);
    protection.get_secrets().assign(tls_secret_t::s_hs_traffic, server_handshake_secret);
    protection.reset_transcript_hash(&session);

    session.set_recordno(from_client, 5);
    session.set_recordno(from_server, 7);
    auto& client_usage = session.get_session_info(from_client).get_keyvalue();
    auto& server_usage = session.get_session_info(from_server).get_keyvalue();
    // Model the EncryptedExtensions acceptance and the preceding Server Finished.
    server_usage.set(session_early_data_accepted, 1);
    session.update_session_status(session_status_server_finished);
    client_usage.set(session_tls13_key_usage_bytes, 100);
    server_usage.set(session_tls13_key_usage_bytes, 200);

    tls_handshake_end_of_early_data end_of_early_data(&session);
    binary_t handshake;
    return_t ret = end_of_early_data.write(from_client, handshake);
    _test_case.test(ret, __FUNCTION__, "serialize EndOfEarlyData and switch the client traffic key");
    const binary_t expected_end_of_early_data{(byte_t)tls_handshake_type_t::end_of_early_data, 0, 0, 0};
    _test_case.assert(expected_end_of_early_data == handshake, __FUNCTION__, "serialize exactly the empty EndOfEarlyData handshake message");

    if (errorcode_t::success == ret) {
        uint64 client_recordno = session.get_recordno(from_client);
        uint64 server_recordno = session.get_recordno(from_server);
        uint64 client_usage_bytes = client_usage.get(session_tls13_key_usage_bytes);
        uint64 server_usage_bytes = server_usage.get(session_tls13_key_usage_bytes);
        _test_case.assert(0 == client_recordno, __FUNCTION__, "reset the client sequence for the handshake traffic key");
        _test_case.assert(7 == server_recordno, __FUNCTION__, "preserve the server sequence because its traffic key did not change");
        _test_case.assert(0 == client_usage_bytes, __FUNCTION__, "reset client key usage when leaving early data");
        _test_case.assert(200 == server_usage_bytes, __FUNCTION__, "preserve server key usage across the client EndOfEarlyData message");
    }
}

static void test_tls13_end_of_early_data_requires_server_finished() {
    // Scenario under test: TLS 1.3 EndOfEarlyData requires Server Finished.
    // Expected: reject EndOfEarlyData before Server Finished.
    _test_case.begin("TLS 1.3 EndOfEarlyData requires Server Finished");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls_13);
    session.get_tls_protection().set_cipher_suite(0x1301);
    session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    session.get_session_info(from_server).get_keyvalue().set(session_early_data_accepted, 1);

    tls_handshake_end_of_early_data end_of_early_data(&session);
    binary_t wire;
    return_t ret = end_of_early_data.write(from_client, wire);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject EndOfEarlyData before Server Finished");
    _test_case.assert(wire.empty(), __FUNCTION__, "emit no EndOfEarlyData bytes before Server Finished");

    size_t fatal_alert_count = 0;
    session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++fatal_alert_count;
        }
    });
    _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal unexpected_message before Server Finished");
}

static void test_tls13_end_of_early_data_read_validation() {
    // Scenario under test: TLS 1.3 EndOfEarlyData read validation.
    // Action: accept an empty EndOfEarlyData after server Finished.
    // Expected: mark the client early-data phase complete after a valid EndOfEarlyData.
    _test_case.begin("TLS 1.3 EndOfEarlyData read validation");

    auto prepare_session = [](tls_session& session, bool accepted, bool server_finished) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.get_secrets().assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x11));
        protection.get_secrets().assign(tls_secret_t::s_hs_traffic, binary_t(32, 0x22));
        protection.reset_transcript_hash(&session);
        if (accepted) {
            session.get_session_info(from_server).get_keyvalue().set(session_early_data_accepted, 1);
        }
        if (server_finished) {
            session.update_session_status(session_status_server_finished);
        }
    };

    {
        tls_session session;
        prepare_session(session, true, true);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire{(byte_t)tls_handshake_type_t::end_of_early_data, 0, 0, 0};
        size_t pos = 0;
        return_t ret = end_of_early_data.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "accept an empty EndOfEarlyData after server Finished");
        _test_case.assert(1 == session.get_session_info(from_server).get_keyvalue().get(session_early_data_finished), __FUNCTION__,
                          "mark the client early-data phase complete after a valid EndOfEarlyData");
    }

    {
        tls_session session;
        prepare_session(session, true, true);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire{(byte_t)tls_handshake_type_t::end_of_early_data, 0, 0, 1, 0};
        size_t pos = 0;
        return_t ret = end_of_early_data.read(from_client, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a non-empty EndOfEarlyData body");
        size_t fatal_decode_error_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
                ++fatal_decode_error_count;
            }
        });
        _test_case.assert(1 == fatal_decode_error_count, __FUNCTION__, "send one fatal decode_error for a non-empty EndOfEarlyData");
        _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "reset handshake state after malformed EndOfEarlyData");
        _test_case.assert(0 == session.get_session_info(from_server).get_keyvalue().get(session_early_data_finished), __FUNCTION__,
                          "do not mark early data complete when EndOfEarlyData is malformed");
    }

    {
        tls_session session;
        prepare_session(session, true, true);
        session.update_session_status(session_status_client_cert);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire;
        return_t ret = end_of_early_data.write(from_client, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject EndOfEarlyData after client Certificate has already started the client flight");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no EndOfEarlyData after client authentication has started");
    }

    {
        tls_session session;
        prepare_session(session, true, true);
        session.update_session_status(session_status_client_cert_verified);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire{(byte_t)tls_handshake_type_t::end_of_early_data, 0, 0, 0};
        size_t pos = 0;
        return_t ret = end_of_early_data.read(from_client, wire.data(), wire.size(), pos);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject received EndOfEarlyData after client CertificateVerify");
        size_t fatal_unexpected_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_unexpected_count;
            }
        });
        _test_case.assert(1 == fatal_unexpected_count, __FUNCTION__, "send fatal unexpected_message for late EndOfEarlyData");
    }

    {
        tls_session session;
        prepare_session(session, false, true);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire;
        return_t ret = end_of_early_data.write(from_client, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject EndOfEarlyData when the server did not accept early data");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no EndOfEarlyData when early data was rejected");
        size_t fatal_unexpected_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_unexpected_count;
            }
        });
        _test_case.assert(1 == fatal_unexpected_count, __FUNCTION__, "send one fatal unexpected_message when EndOfEarlyData was not negotiated");
    }

    {
        tls_session session;
        prepare_session(session, true, true);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire;
        return_t ret = end_of_early_data.write(from_server, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject EndOfEarlyData in the server-to-client direction");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no server-to-client EndOfEarlyData");
    }

    {
        tls_session session;
        prepare_session(session, true, true);
        session.get_session_info(from_server).get_keyvalue().set(session_early_data_finished, 1);
        tls_handshake_end_of_early_data end_of_early_data(&session);
        binary_t wire;
        return_t ret = end_of_early_data.write(from_client, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject a duplicate EndOfEarlyData");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for a duplicate EndOfEarlyData");
    }

    {
        tls_session session;
        prepare_session(session, true, false);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_encrypted_extensions);
        tls_handshake_finished finished(&session);
        binary_t wire;
        return_t ret = finished.write(from_client, wire);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "require EndOfEarlyData before client Finished when early data was accepted");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no client Finished when accepted early data has not ended");
    }
}

static void test_tls13_application_data_finished_direction_policy() {
    // Scenario under test: TLS 1.3 Application Data Finished direction policy.
    // Action: accept server Application Data after Server Finished but before Client Finished.
    // Expected: deliver server Application Data.
    _test_case.begin("TLS 1.3 Application Data Finished direction policy");

    {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_application_data_with_finished_status(from_server, true, false, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept server Application Data after Server Finished but before Client Finished");
        if (errorcode_t::success == ret && 1 == records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(binary_t{'a', 'p', 'p'} == decoded->get_binary(), __FUNCTION__, "deliver server Application Data");
        } else {
            _test_case.assert(false, __FUNCTION__, "server Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_application_data_with_finished_status(from_server, false, true, reader, records);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject server Application Data before Server Finished");
        size_t fatal_alert_count = 0;
        reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::unexpected_message == desc) {
                ++fatal_alert_count;
            }
        });
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal unexpected_message for early server Application Data");
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "reset state after early server Application Data");
    }

    {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_application_data_with_finished_status(from_client, true, false, reader, records);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject client Application Data before Client Finished");
        size_t fatal_alert_count = 0;
        reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::unexpected_message == desc) {
                ++fatal_alert_count;
            }
        });
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal unexpected_message for early client Application Data");
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "reset state after early client Application Data");
    }

    {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_application_data_with_finished_status(from_client, false, true, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept client Application Data after Client Finished");
        if (errorcode_t::success == ret && 1 == records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(binary_t{'a', 'p', 'p'} == decoded->get_binary(), __FUNCTION__, "deliver client Application Data");
        } else {
            _test_case.assert(false, __FUNCTION__, "client Application Data record is available");
        }
    }
}

static void test_tls13_handshake_protection_transition() {
    // Scenario under test: TLS 1.3 handshake protection transition.
    // Action: construct ClientHello state for coalesced ServerHello reader test.
    // Expected: reject plaintext ClientHello writer after ServerHello.
    _test_case.begin("TLS 1.3 handshake protection transition");

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.update_session_status(session_status_client_hello);
        writer.update_session_status(session_status_server_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_client).begin_protection();

        tls_record_handshake record(&writer);
        record << new tls_handshake_client_hello(&writer);
        binary_t wire;
        return_t ret = record.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject plaintext ClientHello writer after ServerHello");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no plaintext ClientHello after ServerHello");
        _test_case.assert(writer.get_session_info(from_client).apply_protection(), __FUNCTION__, "retain client protection after rejected plaintext ClientHello write");
    }

    {
        // Exercise the real record reader with two ServerHello messages in one
        // plaintext Handshake record. The first message advances the session;
        // the second must be rejected by its message-level phase guard.
        tls_session client;
        binary_t client_hello;
        return_t ret = test_client_supportedversion_clienthello(&client, tls_13, tls_13, client_hello);
        _test_case.test(ret, __FUNCTION__, "construct ClientHello state for coalesced ServerHello reader test");
        if (errorcode_t::success == ret) {
            // The ClientHello advertises TLS 1.3, but the negotiated version
            // is not committed until ServerHello is parsed. Seed the selected
            // version here because this fixture specifically exercises the
            // TLS 1.3 plaintext-record pre-scan before parsing either message.
            client.get_tls_protection().set_tls_version(tls_13);

            size_t pos = 9 + 2 + 32;
            uint8 session_id_len = client_hello[pos++];
            binary_t session_id(client_hello.begin() + pos, client_hello.begin() + pos + session_id_len);
            pos += session_id_len;
            uint16 cipher_suites_len = test_read_u16(client_hello, pos);
            _test_case.assert(cipher_suites_len >= 2 && pos + 2 + cipher_suites_len <= client_hello.size(), __FUNCTION__, "ClientHello contains an offered cipher suite");
            pos += 2;
            uint16 cipher_suite = test_read_u16(client_hello, pos);

            binary_t body;
            body.push_back(0x03);
            body.push_back(0x03);
            body.resize(body.size() + 32, 0);
            body.push_back(session_id_len);
            body.insert(body.end(), session_id.begin(), session_id.end());
            body.push_back((byte_t)(cipher_suite >> 8));
            body.push_back((byte_t)cipher_suite);
            body.push_back(0);
            body.push_back(0);
            body.push_back(6);
            body.push_back(0);
            body.push_back(0x2b);
            body.push_back(0);
            body.push_back(2);
            body.push_back(0x03);
            body.push_back(0x04);

            binary_t handshake{0x02, (byte_t)(body.size() >> 16), (byte_t)(body.size() >> 8), (byte_t)body.size()};
            handshake.insert(handshake.end(), body.begin(), body.end());
            binary_t coalesced = handshake;
            coalesced.insert(coalesced.end(), handshake.begin(), handshake.end());

            binary_t wire{0x16, 0x03, 0x03, (byte_t)(coalesced.size() >> 8), (byte_t)coalesced.size()};
            wire.insert(wire.end(), coalesced.begin(), coalesced.end());

            tls_records records;
            ret = records.read(&client, from_server, wire);
            _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate ServerHello in one plaintext Handshake record");
            _test_case.assert(0 == client.get_session_status(), __FUNCTION__, "reset session state after coalesced duplicate ServerHello");
            _test_case.assert(0 == records.size(), __FUNCTION__, "do not publish a partially parsed coalesced Handshake record");

            size_t fatal_alert_count = 0;
            std::set<tls_alertdesc_t> fatal_alerts;
            client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if (tls_alertlevel_t::fatal == level) {
                    ++fatal_alert_count;
                    fatal_alerts.insert(desc);
                }
            });
            _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                              "queue exactly one fatal unexpected_message for duplicate ServerHello");
        }
    }

    {
        // Disable the default distinct-type constraint only for this test so the
        // writer can be given two ServerHello objects in one record collection.
        // Both messages use the production ServerHello body serializer; only the
        // postprocess hook is isolated from key-schedule setup.
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.get_tls_protection().set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);

        auto first = new test_tls13_server_hello_writer_probe(&writer);
        first->set_version(tls_12);  // TLS 1.3 ServerHello legacy_version
        auto first_version = new tls_extension_server_supported_versions(first);
        first_version->set(tls_13);
        first->get_extensions().add(first_version);

        auto second = new test_tls13_server_hello_writer_probe(&writer);
        second->set_version(tls_12);
        auto second_version = new tls_extension_server_supported_versions(second);
        second_version->set(tls_13);
        second->get_extensions().add(second_version);

        tls_record_handshake record(&writer);
        record.get_handshakes().get_container().set_flags(0);
        record << first;
        record << second;

        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate ServerHello during record serialization");
        _test_case.assert(first->postprocessed() && (false == second->postprocessed()), __FUNCTION__,
                          "serialize and postprocess the first ServerHello before rejecting the second");
        _test_case.assert(first->serialized_body_valid(), __FUNCTION__,
                          "emit a structurally valid TLS 1.3 ServerHello with legacy_version, cipher suite, and supported_versions");
        _test_case.assert(wire.empty(), __FUNCTION__, "roll back the partially serialized duplicate ServerHello record");
        _test_case.assert(0 == writer.get_session_status(), __FUNCTION__, "reset session state after duplicate ServerHello writer rejection");

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        writer.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_alert_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                          "queue exactly one fatal unexpected_message for duplicate ServerHello writer");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);

        test_tls13_server_hello_phase_probe server_hello(&writer);
        return_t ret = server_hello.validate_phase(from_server);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow the first ServerHello after ClientHello");

        // Model the state transition performed by the first ServerHello.
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        writer.update_session_status(session_status_server_hello);

        ret = server_hello.validate_phase(from_server);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject a second ServerHello in the same plaintext flight");
    }

    {
        tls_session retry;
        retry.set_type(session_type_t::tls);
        retry.get_tls_protection().set_tls_version(tls_13);
        retry.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        retry.update_session_status(session_status_client_hello);
        retry.update_session_status(session_status_hello_retry_request);
        retry.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        retry.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);

        test_tls13_server_hello_phase_probe server_hello(&retry);
        return_t ret = server_hello.validate_phase(from_server);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow the final ServerHello after the retry ClientHello");

        // The final ServerHello advances the client-side handshake cursor.
        retry.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        retry.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        retry.update_session_status(session_status_server_hello);
        ret = server_hello.validate_phase(from_server);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject another ServerHello after the final ServerHello in an HRR handshake");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.update_session_status(session_status_client_hello);
        writer.update_session_status(session_status_server_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).begin_protection();

        tls_record_handshake record(&writer);
        record << new tls_handshake_server_hello(&writer);
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate plaintext ServerHello writer");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no duplicate plaintext ServerHello");
        _test_case.assert(writer.get_session_info(from_server).apply_protection(), __FUNCTION__, "retain server protection after rejected duplicate ServerHello write");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);

        tls_record_handshake record(&writer);
        auto failing_client_hello = new test_tls13_failing_client_hello(&writer);
        record << failing_client_hello;
        binary_t wire;
        return_t ret = record.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "propagate a failed plaintext ClientHello serialization");
        _test_case.assert(failing_client_hello->preprocess_called(), __FUNCTION__, "reach ClientHello preprocessing before the forced serialization failure");
        _test_case.assert(wire.empty(), __FUNCTION__, "roll back bytes from a failed plaintext ClientHello serialization");
        _test_case.assert(false == writer.get_session_info(from_client).apply_protection(), __FUNCTION__,
                          "leave client protection inactive when plaintext Handshake serialization fails");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls_13);
        session.set_recordno(from_client, 7);
        session.set_recordno(from_server, 11);

        tls_handshake_server_hello server_hello(&session);
        server_hello.run_scheduled(from_server);

        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate client-direction handshake protection after ServerHello");
        _test_case.assert(session.get_session_info(from_server).apply_protection(), __FUNCTION__, "activate server-direction handshake protection after ServerHello");
        _test_case.assert(0 == session.get_recordno(from_client), __FUNCTION__, "reset client handshake record number");
        _test_case.assert(0 == session.get_recordno(from_server), __FUNCTION__, "reset server handshake record number");

        tls_record_builder builder;
        auto record = builder.set(&session).set(tls_content_type_t::handshake).set(from_server).construct().build();
        _test_case.assert((nullptr != record) && (tls_content_type_t::application_data == record->get_type()), __FUNCTION__,
                          "select encrypted application_data encapsulation after ServerHello without CCS");
        if (record) {
            record->release();
        }
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        session.get_session_info(from_client).begin_protection();  // early-data protection was activated after ClientHello
        session.set_recordno(from_client, 5);
        session.set_recordno(from_server, 7);

        tls_handshake_server_hello server_hello(&session);
        server_hello.run_scheduled(from_server);

        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "keep client early-data protection active across ServerHello");
        _test_case.assert(5 == session.get_recordno(from_client), __FUNCTION__, "preserve client early-data sequence number until EndOfEarlyData");
        _test_case.assert(session.get_session_info(from_server).apply_protection(), __FUNCTION__, "activate server handshake protection after ServerHello");
        _test_case.assert(0 == session.get_recordno(from_server), __FUNCTION__, "reset server handshake sequence number after ServerHello");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);

        tls_handshake_server_hello hello_retry_request(&session);
        hello_retry_request.run_scheduled(from_server);

        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "do not activate client protection for HelloRetryRequest");
        _test_case.assert(false == session.get_session_info(from_server).apply_protection(), __FUNCTION__, "do not activate server protection for HelloRetryRequest");

        tls_record_builder builder;
        auto record = builder.set(&session).set(tls_content_type_t::handshake).set(from_server).construct().build();
        _test_case.assert((nullptr != record) && (tls_content_type_t::handshake == record->get_type()), __FUNCTION__,
                          "keep HelloRetryRequest response path in plaintext");
        if (record) {
            record->release();
        }
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_server_hello);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_client).begin_protection();
        reader.get_session_info(from_server).begin_protection();

        // A plaintext EncryptedExtensions message must not be accepted after ServerHello.
        binary_t record{0x16, 0x03, 0x03, 0x00, 0x06, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
        tls_records records;
        return_t ret = records.read(&reader, from_server, record);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject plaintext EncryptedExtensions after ServerHello");

        size_t fatal_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                          "queue exactly one fatal unexpected_message for plaintext post-ServerHello Handshake");
        _test_case.assert(reader.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "do not clear active protection while rejecting a plaintext Handshake record");
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "reset aggregate session status after fatal protocol error");
        _test_case.assert(tls_handshake_type_t::client_hello == reader.get_session_info(from_client).get_status(), __FUNCTION__,
                          "reset client handshake cursor after fatal protocol error");
        _test_case.assert(tls_handshake_type_t::client_hello == reader.get_session_info(from_server).get_status(), __FUNCTION__,
                          "reset server handshake cursor after fatal protocol error");

        // A new connection reuses the session object in PCAP replay. Its first
        // ClientHello must pass the initial-handshake phase guard after reset.
        binary_t next_connection_client_hello{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
        tls_records next_connection_records;
        ret = next_connection_records.read(&reader, from_client, next_connection_client_hello);
        _test_case.assert(errorcode_t::unexpected != ret, __FUNCTION__, "allow a new initial ClientHello after fatal-state reset");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_server_hello);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        // Fatal alerts may arrive as decrypted TLSInnerPlaintext. The common
        // plaintext parser must record the alert and reset both handshake cursors.
        tls_record_alert alert(&reader);
        binary_t alert_payload{(byte_t)tls_alertlevel_t::fatal, (byte_t)tls_alertdesc_t::certificate_unknown};
        size_t alert_pos = 0;
        return_t ret = alert.read_plaintext(from_server, alert_payload.data(), alert_payload.size(), alert_pos);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "parse a fatal alert from decrypted TLS 1.3 content");
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "reset aggregate status after fatal alert");
        _test_case.assert(tls_handshake_type_t::client_hello == reader.get_session_info(from_client).get_status(), __FUNCTION__,
                          "reset client handshake cursor after fatal alert");
        _test_case.assert(tls_handshake_type_t::client_hello == reader.get_session_info(from_server).get_status(), __FUNCTION__,
                          "reset server handshake cursor after fatal alert");

        size_t fatal_count = 0;
        reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::certificate_unknown == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "preserve fatal alert when resetting handshake state");
    }

    auto verify_rejected_plaintext = [&](tls_direction_t dir, const binary_t& record, const char* message) -> void {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.get_tls_protection().set_flow(tls_flow_t::one_rtt);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_server_hello);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(dir).begin_protection();

        tls_records records;
        return_t ret = records.read(&reader, dir, record);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, message);
        _test_case.assert(reader.get_session_info(dir).apply_protection(), __FUNCTION__, "retain active protection when rejecting an out-of-phase plaintext Handshake");

        size_t fatal_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        reader.get_alert(dir, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                          "queue exactly one fatal unexpected_message for an out-of-phase plaintext Handshake");
    };

    // A ClientHello or ServerHello after the final ServerHello must not reopen
    // the plaintext handshake window.
    verify_rejected_plaintext(from_client, binary_t{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}, "reject plaintext ClientHello after the final ServerHello");
    verify_rejected_plaintext(from_server, binary_t{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
                              "reject duplicate plaintext ServerHello after the final ServerHello");

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_hello_retry_request);
        reader.update_session_status(session_status_server_hello);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).begin_protection();

        // The final ServerHello after HRR closes the plaintext handshake window
        // just like an initial ServerHello. A later plaintext ServerHello must
        // not be accepted merely because the connection used the retry flow.
        binary_t duplicate_server_hello{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
        tls_records records;
        return_t ret = records.read(&reader, from_server, duplicate_server_hello);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject plaintext duplicate ServerHello after the final ServerHello in an HRR handshake");
        _test_case.assert(reader.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "retain server-direction protection after rejecting post-HRR plaintext ServerHello");

        size_t fatal_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                          "queue exactly one fatal unexpected_message for post-HRR plaintext ServerHello");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        writer.update_session_status(session_status_client_hello);
        writer.update_session_status(session_status_hello_retry_request);
        writer.update_session_status(session_status_server_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        writer.get_session_info(from_server).begin_protection();

        tls_record_handshake record(&writer);
        record << new tls_handshake_server_hello(&writer);
        binary_t wire;
        return_t ret = record.write(from_server, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject post-HRR duplicate ServerHello in the writer");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no plaintext bytes for post-HRR duplicate ServerHello");
        _test_case.assert(writer.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "retain server-direction protection after post-HRR duplicate ServerHello writer rejection");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.get_tls_protection().set_flow(tls_flow_t::one_rtt);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_server_hello);
        reader.update_session_status(session_status_server_finished);
        reader.update_session_status(session_status_client_finished);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        // RFC 8448 section 4 starts a resumed 0-RTT handshake on the
        // established session. The new ClientHello is valid after Finished.
        binary_t resumed_client_hello{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
        tls_records records;
        return_t ret = records.read(&reader, from_client, resumed_client_hello);
        _test_case.assert(errorcode_t::unexpected != ret, __FUNCTION__, "allow a resumed ClientHello after both Finished messages");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        reader.update_session_status(session_status_hello_retry_request);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);

        // An empty ClientHello body is malformed, but it must reach the ClientHello
        // parser rather than being rejected as an out-of-phase plaintext record.
        binary_t retry_client_hello{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
        tls_records records;
        return_t ret = records.read(&reader, from_client, retry_client_hello);
        _test_case.assert(errorcode_t::unexpected != ret, __FUNCTION__, "keep the second ClientHello plaintext after HelloRetryRequest");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        reader.update_session_status(session_status_client_hello);
        reader.update_session_status(session_status_hello_retry_request);
        reader.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        reader.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);

        // Model the second ClientHello having been accepted after HRR.
        binary_t retry_server_hello{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
        tls_records records;
        return_t ret = records.read(&reader, from_server, retry_server_hello);
        _test_case.assert(errorcode_t::unexpected != ret, __FUNCTION__, "keep the second ServerHello plaintext after the retry ClientHello");
    }
    {
        // Exercise the production ServerHello postprocess branch that handles
        // a second HelloRetryRequest. With no negotiated key-share group,
        // tls_protection::calc() returns warn_retry; the first call models the
        // initial HRR and the second models a retry ClientHello that still
        // cannot produce a usable share.
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.get_protection_context().add_supported_version(tls_13);
        session.update_session_status(session_status_client_hello);

        test_tls13_server_hello_postprocess_probe server_hello(&session);
        server_hello.set_version(tls_13);

        return_t ret = server_hello.postprocess_read();
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept the first HelloRetryRequest in production ServerHello postprocess");
        _test_case.assert(session_status_hello_retry_request & session.get_session_status(), __FUNCTION__, "record the first HelloRetryRequest state");
        _test_case.assert(tls_flow_t::hello_retry_request == protection.get_flow(), __FUNCTION__, "enter HelloRetryRequest flow after the first retry");

        // Model receipt of the retry ClientHello while preserving the fact
        // that one HelloRetryRequest has already occurred.
        session.reset_session_status();
        session.update_session_status(session_status_hello_retry_request);
        session.update_session_status(session_status_client_hello);

        ret = server_hello.postprocess_read();
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "abort a second HelloRetryRequest in production ServerHello postprocess");
        _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "reset aggregate handshake state after a second HelloRetryRequest");
        size_t fatal_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::unexpected_message}, __FUNCTION__,
                          "queue exactly one fatal unexpected_message for a second HelloRetryRequest");
    }
}

static void test_tls13_server_rejects_early_data_for_nonzero_selected_identity() {
    // Scenario under test: TLS 1.3 server early-data acceptance requires selected_identity zero.
    // Expected: reject server early-data acceptance when selected_identity is not zero.
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
    // Scenario under test: TLS 1.3 server advertises early-data acceptance only for an eligible ticket.
    // Action: serialize early_data extension filtering after HelloRetryRequest.
    // Expected: emit early_data only when the selected ticket and ClientHello permit 0-RTT.
    _test_case.begin("TLS 1.3 server advertises early-data acceptance only for an eligible ticket");

    auto verify_server_acceptance = [](uint16 selected_identity, uint64 early_data_limit, uint64 early_data_offered, uint16 negotiated_suite, uint16 ticket_suite,
                                       uint16 ticket_version, const binary_t& ticket_alpn, const binary_t& negotiated_alpn, bool expect_success,
                                       const char* description) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(negotiated_suite);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.reset_transcript_hash(&session);
        session.set_recordno(from_client, 7);
        session.get_keyvalue().set(session_server_psk_selected_identity, selected_identity);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, ticket_suite);
        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, early_data_offered);
        early_state.set(session_early_data_limit, early_data_limit);
        tls_resumption_ticket early_ticket;
        early_ticket.identity = binary_t{0x01};
        early_ticket.version = ticket_version;
        early_ticket.cipher_suite = ticket_suite;
        early_ticket.alpn = ticket_alpn;
        early_ticket.max_early_data_size = static_cast<uint32>(early_data_limit);
        session.set_early_data_ticket(early_ticket);

        tls_handshake_encrypted_extensions encrypted_extensions(&session);
        if ((false == negotiated_alpn.empty())) {
            auto alpn = new tls_extension_alpn(&encrypted_extensions);
            alpn->set_protocols(negotiated_alpn);
            encrypted_extensions.get_extensions().add(alpn);
        }
        encrypted_extensions.get_extensions().add(new tls_extension_early_data(&encrypted_extensions));
        binary_t wire;
        return_t ret = encrypted_extensions.write(from_server, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, description);
        bool early_data_emitted = false;
        for (size_t i = 0; i + 3 < wire.size(); ++i) {
            if ((0x00 == wire[i]) && (0x2a == wire[i + 1]) && (0x00 == wire[i + 2]) && (0x00 == wire[i + 3])) {
                early_data_emitted = true;
                break;
            }
        }
        _test_case.assert(expect_success == early_data_emitted, __FUNCTION__, "emit early_data only when the selected ticket and ClientHello permit 0-RTT");
        _test_case.assert(expect_success ? (tls_flow_t::zero_rtt == protection.get_flow()) : (tls_flow_t::one_rtt == protection.get_flow()), __FUNCTION__,
                          "retain early traffic keys only when the server accepts early data");
        _test_case.assert(expect_success ? (1 == early_state.get(session_early_data_accepted)) : (0 == early_state.get(session_early_data_accepted)), __FUNCTION__,
                          "record the EncryptedExtensions acceptance decision");
        _test_case.assert(expect_success ? (7 == session.get_recordno(from_client, false)) : (0 == session.get_recordno(from_client, false)), __FUNCTION__,
                          "reset the client record sequence only when switching away from early traffic keys");
    };

    const binary_t alpn_h2{0x02, 'h', '2'};
    const binary_t alpn_h3{0x02, 'h', '3'};
    const uint16 tls13_version = static_cast<uint16>(tls_13);
    verify_server_acceptance(0, 4096, 1, 0x1301, 0x1301, tls13_version, binary_t(), binary_t(), true,
                             "accept early data for identity zero with matching version, cipher suite, ALPN and ticket allowance");
    verify_server_acceptance(0, 0, 1, 0x1301, 0x1301, tls13_version, binary_t(), binary_t(), false, "do not accept early data when the selected ticket has no allowance");
    verify_server_acceptance(0, 4096, 0, 0x1301, 0x1301, tls13_version, binary_t(), binary_t(), false,
                             "do not accept early data when ClientHello omitted the early_data extension");
    verify_server_acceptance(1, 4096, 1, 0x1301, 0x1301, tls13_version, binary_t(), binary_t(), false,
                             "do not accept early data when the selected PSK identity is not zero");
    verify_server_acceptance(0xffff, 4096, 1, 0x1301, 0x1301, tls13_version, binary_t(), binary_t(), false, "do not accept early data when no PSK identity was selected");
    verify_server_acceptance(0, 4096, 1, 0x1303, 0x1301, tls13_version, binary_t(), binary_t(), false,
                             "do not accept early data when the negotiated cipher suite differs from the ticket suite");
    verify_server_acceptance(0, 4096, 1, 0x1301, 0x1301, static_cast<uint16>(tls_12), binary_t(), binary_t(), false,
                             "do not accept early data when the ticket was established under a different TLS version");
    verify_server_acceptance(0, 4096, 1, 0x1301, 0x1301, tls13_version, alpn_h2, alpn_h3, false,
                             "do not accept early data when the negotiated ALPN differs from the ticket ALPN");
    verify_server_acceptance(0, 4096, 1, 0x1301, 0x1301, tls13_version, alpn_h2, alpn_h2, true, "accept early data when the negotiated ALPN matches the ticket ALPN");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    auto& hrr_protection = hrr_session.get_tls_protection();
    hrr_protection.set_tls_version(tls_13);
    hrr_protection.set_cipher_suite(0x1301);
    hrr_protection.set_flow(tls_flow_t::hello_retry_request);
    const binary_t hrr_resumption_secret(32, 0x5a);
    hrr_protection.get_secrets().assign(tls_secret_t::resumption_early, hrr_resumption_secret);
    hrr_session.get_keyvalue().set(session_server_psk_selected_identity, 0);
    hrr_session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);
    auto& hrr_early_state = hrr_session.get_session_info(from_server).get_keyvalue();
    hrr_early_state.set(session_early_data_offered, 1);
    hrr_early_state.set(session_early_data_limit, 4096);
    tls_resumption_ticket hrr_ticket;
    hrr_ticket.identity = binary_t{0x01};
    hrr_ticket.version = tls13_version;
    hrr_ticket.cipher_suite = 0x1301;
    hrr_ticket.alpn = alpn_h2;
    hrr_ticket.max_early_data_size = 4096;
    hrr_session.set_early_data_ticket(hrr_ticket);
    tls_handshake_encrypted_extensions hrr_ee(&hrr_session);
    hrr_ee.get_extensions().add(new tls_extension_early_data(&hrr_ee));
    binary_t hrr_wire;
    return_t hrr_ret = hrr_ee.get_extensions().write(from_server, hrr_wire);
    _test_case.test(hrr_ret, __FUNCTION__, "serialize early_data extension filtering after HelloRetryRequest");
    bool hrr_early_data_emitted = false;
    for (size_t i = 0; i + 3 < hrr_wire.size(); ++i) {
        if ((0x00 == hrr_wire[i]) && (0x2a == hrr_wire[i + 1]) && (0x00 == hrr_wire[i + 2]) && (0x00 == hrr_wire[i + 3])) {
            hrr_early_data_emitted = true;
            break;
        }
    }
    _test_case.assert(false == hrr_early_data_emitted, __FUNCTION__, "never accept early_data after HelloRetryRequest");
    _test_case.assert(0 == hrr_session.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "retain the selected PSK identity for the post-HRR 1-RTT handshake");
    _test_case.assert(hrr_resumption_secret == hrr_protection.get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                      "retain the compatible PSK secret even though early data is rejected");
    _test_case.assert(0 == hrr_early_state.get(session_early_data_accepted), __FUNCTION__, "do not mark early data accepted when HRR requires a second ClientHello");
    _test_case.assert(tls_flow_t::hello_retry_request == hrr_protection.get_flow(), __FUNCTION__,
                      "preserve the HRR transcript flow while suppressing early-data acceptance");
}

static void test_tls13_client_requires_psk_for_early_data_offer() {
    // Scenario under test: TLS 1.3 client requires pre_shared_key before offering early_data.
    // Action: serialize ClientHello with early_data but no pre_shared_key.
    // Expected: do not record an early_data offer when pre_shared_key is absent.
    _test_case.begin("TLS 1.3 client requires pre_shared_key before offering early_data");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls_13);
    session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    session.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

    tls_handshake_client_hello client_hello(&session);
    client_hello.get_extensions().add(new tls_extension_early_data(&client_hello));
    binary_t extensions;
    return_t ret = client_hello.get_extensions().write(from_client, extensions);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello with early_data but no pre_shared_key");
    _test_case.assert(0 == session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not record an early_data offer when pre_shared_key is absent");
    _test_case.assert(extensions.empty(), __FUNCTION__, "omit early_data unless pre_shared_key is also present");

    tls_session direct_session;
    direct_session.set_type(session_type_t::tls);
    direct_session.get_tls_protection().set_tls_version(tls_13);
    direct_session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    direct_session.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);
    tls_handshake_client_hello direct_hello(&direct_session);
    direct_hello.get_extensions().add(new tls_extension_client_psk(&direct_hello));
    tls_extension_early_data direct_offer(&direct_hello);
    binary_t direct_offer_wire;
    ret = direct_offer.write(from_client, direct_offer_wire);
    _test_case.test(ret, __FUNCTION__, "directly serialize early_data alongside a PSK offer");
    _test_case.assert(false == direct_offer_wire.empty(), __FUNCTION__, "emit the directly serialized client early_data extension");
    _test_case.assert(1 == direct_session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "remember the early_data offer after a direct ClientHello extension write");
    _test_case.assert(1 == direct_session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial), __FUNCTION__,
                      "retain the initial offer marker after a direct ClientHello extension write");

    tls_session rejected_session;
    rejected_session.set_type(session_type_t::tls);
    rejected_session.get_tls_protection().set_tls_version(tls_13);
    rejected_session.get_tls_protection().set_flow(tls_flow_t::one_rtt);
    tls_handshake_client_hello rejected_hello(&rejected_session);
    rejected_hello.get_extensions().add(new tls_extension_early_data(&rejected_hello));
    binary_t rejected_extensions;
    ret = rejected_hello.get_extensions().write(from_client, rejected_extensions);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello without a usable 0-RTT flow");
    _test_case.assert(0 == rejected_session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not record an early_data offer when the extension was omitted");
    _test_case.assert(rejected_extensions.empty(), __FUNCTION__, "omit early_data from a non-zero-RTT ClientHello");

    tls_session no_allowance_session;
    no_allowance_session.set_type(session_type_t::tls);
    no_allowance_session.get_tls_protection().set_tls_version(tls_13);
    no_allowance_session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    tls_handshake_client_hello no_allowance_hello(&no_allowance_session);
    no_allowance_hello.get_extensions().add(new tls_extension_early_data(&no_allowance_hello));
    binary_t no_allowance_extensions;
    ret = no_allowance_hello.get_extensions().write(from_client, no_allowance_extensions);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello with a ticket that has no early-data allowance");
    _test_case.assert(no_allowance_extensions.empty(), __FUNCTION__, "do not offer early_data when identity zero has max_early_data_size zero");
    _test_case.assert(0 == no_allowance_session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not record early_data as offered when the extension was omitted");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    hrr_session.get_tls_protection().set_tls_version(tls_13);
    hrr_session.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
    tls_handshake_client_hello client_hello2(&hrr_session);
    auto hrr_early_data = new tls_extension_early_data(&client_hello2);
    client_hello2.get_extensions().add(hrr_early_data);
    binary_t hrr_extensions;
    ret = client_hello2.get_extensions().write(from_client, hrr_extensions);
    _test_case.test(ret, __FUNCTION__, "omit early_data from ClientHello2 after HelloRetryRequest");
    _test_case.assert(hrr_extensions.empty(), __FUNCTION__, "do not emit the forbidden ClientHello2 early_data extension");

    binary_t direct_hrr_extension;
    ret = hrr_early_data->write(from_client, direct_hrr_extension);
    _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "reject direct serialization of early_data in ClientHello2 after HelloRetryRequest");
    _test_case.assert(direct_hrr_extension.empty(), __FUNCTION__, "do not write a forbidden early_data extension header");

    hrr_session.update_session_status(session_status_hello_retry_request);
    auto& hrr_early_state = hrr_session.get_session_info(from_server).get_keyvalue();
    hrr_early_state.set(session_early_data_offered_initial, 1);
    tls_record_application_data post_hrr_application_data(&hrr_session);
    post_hrr_application_data.set_binary(binary_t{0x41, 0x42});
    binary_t post_hrr_record;
    ret = post_hrr_application_data.write(from_client, post_hrr_record);
    _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "refuse client application data after HRR before the handshake completes");
    _test_case.assert(post_hrr_record.empty(), __FUNCTION__, "do not emit 0-RTT or plaintext application data after HRR");
}

static void test_tls13_server_records_early_data_offer_during_extension_parse() {
    // Scenario under test: TLS 1.3 server records early_data before parsing the final PSK extension.
    // Action: parse the ClientHello early_data extension.
    // Expected: record the offer before the following pre_shared_key extension is processed.
    _test_case.begin("TLS 1.3 server records early_data before parsing the final PSK extension");

    tls_session session;
    session.set_type(session_type_t::tls);
    session.get_tls_protection().set_tls_version(tls_13);
    session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    tls_handshake_client_hello client_hello(&session);

    binary_t early_data_extension{0x00, 0x2a, 0x00, 0x00};
    size_t pos = 0;
    return_t ret = client_hello.get_extensions().read(&client_hello, from_client, early_data_extension.data(), early_data_extension.size(), pos);
    _test_case.test(ret, __FUNCTION__, "parse the ClientHello early_data extension");
    _test_case.assert(1 == session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "record the offer before the following pre_shared_key extension is processed");
    _test_case.assert(session.get_early_data_discard_limit() == session.get_session_info(from_server).get_keyvalue().get(session_early_data_discard_limit), __FUNCTION__,
                      "initialize the independent discard budget even before a PSK extension is parsed");

    tls_session duplicate_session;
    duplicate_session.set_type(session_type_t::tls);
    duplicate_session.update_session_status(session_status_client_hello);
    tls_handshake_client_hello duplicate_client_hello(&duplicate_session);
    const binary_t duplicate_early_data_extensions{0x00, 0x2a, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00};
    size_t duplicate_pos = 0;
    ret = duplicate_client_hello.get_extensions().read(&duplicate_client_hello, from_client, duplicate_early_data_extensions.data(),
                                                       duplicate_early_data_extensions.size(), duplicate_pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject a duplicate early_data extension in ClientHello");
    _test_case.assert(4 == duplicate_pos, __FUNCTION__, "reject the duplicate before parsing its body or mutating extension state");
    _test_case.assert(0 == duplicate_session.get_session_status(), __FUNCTION__, "reset the handshake after a duplicate extension");
    size_t duplicate_illegal_parameter_count = 0;
    duplicate_session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++duplicate_illegal_parameter_count;
        }
    });
    _test_case.assert(1 == duplicate_illegal_parameter_count, __FUNCTION__, "queue exactly one fatal illegal_parameter for duplicate extensions");

    tls_session ee_session;
    ee_session.set_type(session_type_t::tls);
    tls_handshake_encrypted_extensions encrypted_extensions(&ee_session);
    size_t ee_pos = 0;
    ret = encrypted_extensions.get_extensions().read(&encrypted_extensions, from_server, early_data_extension.data(), early_data_extension.size(), ee_pos);
    _test_case.test(ret, __FUNCTION__, "parse the empty EncryptedExtensions early_data body");

    {
        tls_session ticket_session;
        ticket_session.set_type(session_type_t::tls);
        tls_handshake_new_session_ticket ticket_handshake(&ticket_session);
        const binary_t valid_ticket_early_data{0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00};
        size_t ticket_pos = 0;
        ret = ticket_handshake.get_extensions().read(&ticket_handshake, from_server, valid_ticket_early_data.data(), valid_ticket_early_data.size(), ticket_pos);
        _test_case.test(ret, __FUNCTION__, "parse NewSessionTicket early_data max_early_data_size");
        auto ticket_extension = static_cast<tls_extension_early_data*>(ticket_handshake.get_extensions().get(tls_extension_type_t::early_data));
        _test_case.assert(ticket_extension && (4096 == ticket_extension->get_max_early_data_size()), __FUNCTION__,
                          "retain the exact NewSessionTicket early-data allowance");
    }

    {
        tls_session ticket_session;
        ticket_session.set_type(session_type_t::tls);
        tls_handshake_new_session_ticket ticket_handshake(&ticket_session);
        const binary_t truncated_ticket_early_data{0x00, 0x2a, 0x00, 0x03, 0x00, 0x00, 0x10};
        size_t ticket_pos = 0;
        ret = ticket_handshake.get_extensions().read(&ticket_handshake, from_server, truncated_ticket_early_data.data(), truncated_ticket_early_data.size(), ticket_pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a truncated NewSessionTicket early_data allowance");
    }

    {
        tls_session ticket_session;
        ticket_session.set_type(session_type_t::tls);
        tls_handshake_new_session_ticket ticket_handshake(&ticket_session);
        const binary_t oversized_ticket_early_data{0x00, 0x2a, 0x00, 0x05, 0x00, 0x00, 0x10, 0x00, 0x00};
        size_t ticket_pos = 0;
        ret = ticket_handshake.get_extensions().read(&ticket_handshake, from_server, oversized_ticket_early_data.data(), oversized_ticket_early_data.size(), ticket_pos);
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject trailing bytes after NewSessionTicket early_data allowance");
    }

    const binary_t malformed_early_data_extension{0x00, 0x2a, 0x00, 0x01, 0x00};
    tls_session malformed_client_session;
    malformed_client_session.set_type(session_type_t::tls);
    malformed_client_session.update_session_status(session_status_client_hello);
    tls_handshake_client_hello malformed_client_hello(&malformed_client_session);
    size_t malformed_pos = 0;
    ret = malformed_client_hello.get_extensions().read(&malformed_client_hello, from_client, malformed_early_data_extension.data(), malformed_early_data_extension.size(),
                                                       malformed_pos);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a non-empty ClientHello early_data body");
    _test_case.assert(0 == malformed_client_session.get_session_status(), __FUNCTION__, "reset handshake state after malformed ClientHello early_data");
    _test_case.assert(0 == malformed_client_session.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not commit the early-data offer before validating its empty body");
    size_t malformed_client_decode_error_count = 0;
    malformed_client_session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
            ++malformed_client_decode_error_count;
        }
    });
    _test_case.assert(1 == malformed_client_decode_error_count, __FUNCTION__, "queue exactly one fatal decode_error for malformed ClientHello early_data");

    tls_session malformed_ee_session;
    malformed_ee_session.set_type(session_type_t::tls);
    malformed_ee_session.update_session_status(session_status_client_hello);
    tls_handshake_encrypted_extensions malformed_ee(&malformed_ee_session);
    size_t malformed_ee_pos = 0;
    ret = malformed_ee.get_extensions().read(&malformed_ee, from_server, malformed_early_data_extension.data(), malformed_early_data_extension.size(), malformed_ee_pos);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a non-empty EncryptedExtensions early_data body");
    _test_case.assert(0 == malformed_ee_session.get_session_status(), __FUNCTION__, "reset handshake state after malformed EncryptedExtensions early_data");
    size_t malformed_ee_decode_error_count = 0;
    malformed_ee_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
            ++malformed_ee_decode_error_count;
        }
    });
    _test_case.assert(1 == malformed_ee_decode_error_count, __FUNCTION__, "queue exactly one fatal decode_error for malformed EncryptedExtensions early_data");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    hrr_session.get_tls_protection().set_tls_version(tls_13);
    hrr_session.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
    tls_handshake_client_hello client_hello2(&hrr_session);
    size_t hrr_pos = 0;
    ret = client_hello2.get_extensions().read(&client_hello2, from_client, early_data_extension.data(), early_data_extension.size(), hrr_pos);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject early_data in ClientHello2 after HRR");
    _test_case.assert(hrr_session.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__, "raise a fatal illegal_parameter alert for early_data in ClientHello2");

    {
        tls_session invalid_session;
        invalid_session.set_type(session_type_t::tls);
        invalid_session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        invalid_session.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);
        tls_handshake_client_hello invalid_handshake(&invalid_session);
        tls_extension_early_data invalid_extension(&invalid_handshake);
        binary_t invalid_wire;
        ret = invalid_extension.write(from_client, invalid_wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "prevent direct client serialization of early_data without a pre_shared_key extension");
        _test_case.assert(invalid_wire.empty(), __FUNCTION__, "emit no bytes for a direct early_data write without PSK");
    }

    {
        tls_session invalid_session;
        invalid_session.set_type(session_type_t::tls);
        tls_handshake_server_hello invalid_handshake(&invalid_session);
        size_t invalid_pos = 0;
        ret = invalid_handshake.get_extensions().read(&invalid_handshake, from_server, early_data_extension.data(), early_data_extension.size(), invalid_pos);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject early_data in ServerHello");
        size_t illegal_parameter_count = 0;
        invalid_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "raise exactly one fatal illegal_parameter for early_data in ServerHello");
    }

    {
        tls_session invalid_session;
        invalid_session.set_type(session_type_t::tls);
        tls_handshake_client_hello invalid_handshake(&invalid_session);
        size_t invalid_pos = 0;
        ret = invalid_handshake.get_extensions().read(&invalid_handshake, from_server, early_data_extension.data(), early_data_extension.size(), invalid_pos);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject server-sent early_data in ClientHello");
        size_t illegal_parameter_count = 0;
        invalid_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "raise exactly one fatal illegal_parameter for server-sent ClientHello early_data");
    }

    {
        tls_session invalid_session;
        invalid_session.set_type(session_type_t::tls);
        tls_handshake_encrypted_extensions invalid_handshake(&invalid_session);
        tls_extension_early_data invalid_extension(&invalid_handshake);
        binary_t invalid_wire;
        ret = invalid_extension.write(from_client, invalid_wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "prevent client-side serialization of EncryptedExtensions early_data");
        _test_case.assert(invalid_wire.empty(), __FUNCTION__, "emit no bytes for early_data in the wrong direction");
    }

    {
        tls_session invalid_session;
        invalid_session.set_type(session_type_t::tls);
        tls_handshake_encrypted_extensions invalid_handshake(&invalid_session);
        tls_extension_early_data invalid_extension(&invalid_handshake);
        binary_t invalid_wire;
        ret = invalid_extension.write(from_server, invalid_wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__,
                          "prevent direct server serialization of EncryptedExtensions early_data without an eligible identity-zero PSK");
        _test_case.assert(invalid_wire.empty(), __FUNCTION__, "emit no bytes for an ineligible direct server early_data write");
    }
}

static void test_tls13_client_validates_early_data_acceptance_parameters() {
    // Scenario under test: TLS 1.3 client validates PSK parameters when the server accepts early data.
    // Action: mark early data accepted after valid EncryptedExtensions.
    // Expected: reject mismatched early-data parameters with one fatal illegal_parameter.
    _test_case.begin("TLS 1.3 client validates PSK parameters when the server accepts early data");

    auto verify_acceptance = [](bool early_data_offered, uint16 selected_identity, uint64 early_data_limit, uint16 ticket_version, uint16 ticket_suite,
                                const binary_t& ticket_alpn, uint16 negotiated_suite, const binary_t& negotiated_alpn, bool expect_success, const char* description) {
        tls_session session;
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(negotiated_suite);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.reset_transcript_hash(&session);
        session.get_keyvalue().set(session_server_psk_selected_identity, selected_identity);
        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, early_data_offered ? 1 : 0);
        early_state.set(session_early_data_limit, early_data_limit);

        tls_resumption_ticket ticket;
        ticket.identity = binary_t{0x01};
        ticket.version = ticket_version;
        ticket.cipher_suite = ticket_suite;
        ticket.alpn = ticket_alpn;
        ticket.max_early_data_size = static_cast<uint32>(early_data_limit);
        session.set_early_data_ticket(ticket);

        binary_t extensions;
        if ((false == negotiated_alpn.empty())) {
            binary_t alpn_body;
            alpn_body.push_back(0x00);
            alpn_body.push_back(0x03);
            alpn_body.insert(alpn_body.end(), negotiated_alpn.begin(), negotiated_alpn.end());
            extensions.push_back(0x00);
            extensions.push_back(0x10);
            extensions.push_back(0x00);
            extensions.push_back(static_cast<byte_t>(alpn_body.size()));
            extensions.insert(extensions.end(), alpn_body.begin(), alpn_body.end());
        }
        extensions.insert(extensions.end(), {0x00, 0x2a, 0x00, 0x00});
        binary_t wire{0x08, 0x00, 0x00, static_cast<byte_t>(2 + extensions.size()), static_cast<byte_t>(extensions.size() >> 8), static_cast<byte_t>(extensions.size())};
        wire.insert(wire.end(), extensions.begin(), extensions.end());

        tls_handshake_encrypted_extensions encrypted_extensions(&session);
        size_t pos = 0;
        return_t ret = encrypted_extensions.read(from_server, wire.data(), wire.size(), pos);
        if (expect_success) {
            _test_case.test(ret, __FUNCTION__, description);
            _test_case.assert(1 == early_state.get(session_early_data_accepted), __FUNCTION__, "mark early data accepted after valid EncryptedExtensions");
        } else {
            _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, description);
            size_t illegal_parameter_count = 0;
            session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                    ++illegal_parameter_count;
                }
            });
            _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "reject mismatched early-data parameters with one fatal illegal_parameter");
        }
    };

    const binary_t alpn_h2{0x02, 'h', '2'};
    const binary_t alpn_h3{0x02, 'h', '3'};
    const uint16 tls13_version = static_cast<uint16>(tls_13);
    verify_acceptance(true, 0, 4096, tls13_version, 0x1301, alpn_h2, 0x1301, alpn_h2, true, "accept early_data when version, suite and ALPN match the selected PSK");
    verify_acceptance(false, 0, 4096, tls13_version, 0x1301, alpn_h2, 0x1301, alpn_h2, false,
                      "reject unsolicited early_data acceptance when the client did not offer it");
    verify_acceptance(true, 1, 4096, tls13_version, 0x1301, alpn_h2, 0x1301, alpn_h2, false, "reject early_data when the server selected a nonzero PSK identity");
    verify_acceptance(true, 0xffff, 4096, tls13_version, 0x1301, alpn_h2, 0x1301, alpn_h2, false, "reject early_data when the server did not select a PSK");
    verify_acceptance(true, 0, 0, tls13_version, 0x1301, alpn_h2, 0x1301, alpn_h2, false, "reject early_data when the ticket allowance is zero");
    verify_acceptance(true, 0, 4096, tls13_version, 0x1301, alpn_h3, 0x1301, alpn_h2, false, "reject early_data when negotiated ALPN differs from the selected PSK");
    verify_acceptance(true, 0, 4096, static_cast<uint16>(tls_12), 0x1301, alpn_h2, 0x1301, alpn_h2, false,
                      "reject early_data when the selected PSK is bound to another TLS version");
    verify_acceptance(true, 0, 4096, tls13_version, 0x1301, alpn_h2, 0x1303, alpn_h2, false,
                      "reject early_data when the negotiated cipher suite differs from the selected PSK");

    tls_session rejected_session;
    rejected_session.set_type(session_type_t::tls);
    auto& rejected_protection = rejected_session.get_tls_protection();
    rejected_protection.set_tls_version(tls_13);
    rejected_protection.set_cipher_suite(0x1301);
    rejected_protection.set_flow(tls_flow_t::zero_rtt);
    rejected_protection.reset_transcript_hash(&rejected_session);
    rejected_session.update_session_status(session_status_server_hello);
    rejected_session.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
    rejected_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    rejected_session.get_session_info(from_client).begin_protection();
    rejected_session.set_recordno(from_client, 7);
    auto& rejected_client_usage = rejected_session.get_session_info(from_client).get_keyvalue();
    rejected_client_usage.set(session_tls13_key_usage_bytes, 100);
    rejected_session.get_session_info(from_server).get_keyvalue().set(session_early_data_offered, 1);
    // The PSK was selected in ServerHello; rejecting only early data in
    // EncryptedExtensions must not undo the resumption key schedule.
    rejected_session.get_keyvalue().set(session_server_psk_selected_identity, 0);
    rejected_session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);
    const binary_t selected_psk_early_secret(32, 0x5a);
    rejected_protection.get_secrets().assign(tls_secret_t::early_secret, selected_psk_early_secret);
    binary_t rejected_ee{0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
    tls_handshake_encrypted_extensions rejected_extensions(&rejected_session);
    size_t rejected_pos = 0;
    return_t rejected_ret = rejected_extensions.read(from_server, rejected_ee.data(), rejected_ee.size(), rejected_pos);
    _test_case.test(rejected_ret, __FUNCTION__, "read EncryptedExtensions that declines early data");
    _test_case.assert(tls_flow_t::one_rtt == rejected_protection.get_flow(), __FUNCTION__, "switch to handshake traffic keys after early-data rejection");
    _test_case.assert(0 == rejected_session.get_recordno(from_client, false), __FUNCTION__, "reset the client record sequence for handshake keys");
    _test_case.assert(0 == rejected_client_usage.get(session_tls13_key_usage_bytes), __FUNCTION__,
                      "reset client AEAD usage when switching from early-data to handshake traffic keys");
    _test_case.assert(0 == rejected_session.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "retain the PSK selection when only early data is rejected");
    _test_case.assert(0x1301 == rejected_session.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "retain the selected PSK ticket suite after early-data rejection");
    _test_case.assert(selected_psk_early_secret == rejected_protection.get_secrets().get(tls_secret_t::early_secret), __FUNCTION__,
                      "preserve the PSK-derived Early Secret when EncryptedExtensions declines only 0-RTT");
    tls_record_application_data rejected_application_data(&rejected_session);
    rejected_application_data.set_binary(binary_t{0x01, 0x02});
    binary_t rejected_application_wire;
    return_t rejected_write_ret = rejected_application_data.write(from_client, rejected_application_wire);
    _test_case.assert(errorcode_t::bad_request == rejected_write_ret, __FUNCTION__,
                      "do not silently drop application data before the client's Finished after 0-RTT rejection");
    _test_case.assert(rejected_application_wire.empty(), __FUNCTION__, "do not emit rejected early data as 1-RTT application data");

    tls_session failed_acceptance_session;
    failed_acceptance_session.set_type(session_type_t::tls);
    auto& failed_acceptance_protection = failed_acceptance_session.get_tls_protection();
    failed_acceptance_protection.set_tls_version(tls_13);
    failed_acceptance_protection.set_cipher_suite(0x1301);
    failed_acceptance_protection.set_flow(tls_flow_t::zero_rtt);
    // Model a final ServerHello: the client handshake traffic secret exists,
    // so an invalid EncryptedExtensions fatal alert must use handshake keys.
    failed_acceptance_protection.get_secrets().assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x33));
    failed_acceptance_protection.reset_transcript_hash(&failed_acceptance_session);
    failed_acceptance_session.get_session_info(from_client).begin_protection();
    failed_acceptance_session.set_recordno(from_client, 7);
    failed_acceptance_session.get_keyvalue().set(session_server_psk_selected_identity, 1);
    auto& failed_acceptance_state = failed_acceptance_session.get_session_info(from_server).get_keyvalue();
    failed_acceptance_state.set(session_early_data_offered, 1);
    failed_acceptance_state.set(session_early_data_limit, 4096);
    tls_resumption_ticket failed_acceptance_ticket;
    failed_acceptance_ticket.identity = binary_t{0x01};
    failed_acceptance_ticket.version = static_cast<uint16>(tls_13);
    failed_acceptance_ticket.cipher_suite = 0x1301;
    failed_acceptance_ticket.max_early_data_size = 4096;
    failed_acceptance_session.set_early_data_ticket(failed_acceptance_ticket);

    // The server illegally accepts early data for a nonzero selected identity.
    // The client must send its fatal alert under the handshake traffic keys
    // installed after ServerHello, not with plaintext protection disabled.
    binary_t failed_acceptance_ee{0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
    tls_handshake_encrypted_extensions failed_acceptance_extensions(&failed_acceptance_session);
    size_t failed_acceptance_pos = 0;
    return_t failed_acceptance_ret = failed_acceptance_extensions.read(from_server, failed_acceptance_ee.data(), failed_acceptance_ee.size(), failed_acceptance_pos);
    _test_case.assert(errorcode_t::handshake_failure == failed_acceptance_ret, __FUNCTION__,
                      "reject EncryptedExtensions that accepts early data for a nonzero PSK identity");
    _test_case.assert(tls_flow_t::one_rtt == failed_acceptance_protection.get_flow(), __FUNCTION__, "leave zero-RTT flow after rejecting invalid EncryptedExtensions");
    _test_case.assert(failed_acceptance_session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                      "retain client handshake protection so the fatal alert is encrypted");
    tls_record_builder failed_alert_builder;
    auto failed_alert_record = failed_alert_builder.set(&failed_acceptance_session).set(tls_content_type_t::alert).set(from_client).construct().build();
    _test_case.assert((nullptr != failed_alert_record) && (tls_content_type_t::application_data == failed_alert_record->get_type()), __FUNCTION__,
                      "select encrypted application_data encapsulation for the fatal alert");
    if (failed_alert_record) {
        failed_alert_record->release();
    }
    _test_case.assert(0 == failed_acceptance_session.get_recordno(from_client, false), __FUNCTION__,
                      "reset the client record sequence for the handshake-protected fatal alert");
    size_t failed_acceptance_alert_count = 0;
    failed_acceptance_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++failed_acceptance_alert_count;
        }
    });
    _test_case.assert(1 == failed_acceptance_alert_count, __FUNCTION__, "queue exactly one fatal illegal_parameter alert");

    tls_session unsolicited_acceptance_session;
    unsolicited_acceptance_session.set_type(session_type_t::tls);
    auto& unsolicited_protection = unsolicited_acceptance_session.get_tls_protection();
    unsolicited_protection.set_tls_version(tls_13);
    unsolicited_protection.set_cipher_suite(0x1301);
    unsolicited_protection.set_flow(tls_flow_t::one_rtt);
    unsolicited_protection.reset_transcript_hash(&unsolicited_acceptance_session);
    unsolicited_acceptance_session.get_session_info(from_client).begin_protection();
    unsolicited_acceptance_session.set_recordno(from_client, 3);
    unsolicited_acceptance_session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
    auto& unsolicited_early_state = unsolicited_acceptance_session.get_session_info(from_server).get_keyvalue();
    unsolicited_early_state.set(session_early_data_offered, 0);
    binary_t unsolicited_ee{0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
    tls_handshake_encrypted_extensions unsolicited_extensions(&unsolicited_acceptance_session);
    size_t unsolicited_pos = 0;
    return_t unsolicited_ret = unsolicited_extensions.read(from_server, unsolicited_ee.data(), unsolicited_ee.size(), unsolicited_pos);
    _test_case.assert(errorcode_t::handshake_failure == unsolicited_ret, __FUNCTION__, "reject unsolicited early-data acceptance after ServerHello");
    _test_case.assert(unsolicited_acceptance_session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                      "preserve already-active handshake protection after EncryptedExtensions failure");
    tls_record_builder unsolicited_alert_builder;
    auto unsolicited_alert_record = unsolicited_alert_builder.set(&unsolicited_acceptance_session).set(tls_content_type_t::alert).set(from_client).construct().build();
    _test_case.assert((nullptr != unsolicited_alert_record) && (tls_content_type_t::application_data == unsolicited_alert_record->get_type()), __FUNCTION__,
                      "keep the fatal alert encrypted when EncryptedExtensions fails outside the zero-RTT flow");
    if (unsolicited_alert_record) {
        unsolicited_alert_record->release();
    }
}

static void test_tls13_client_sends_bounded_early_data() {
    // Scenario under test: TLS 1.3 client sends 0-RTT data only within the ticket allowance.
    // Action: write early application data within max_early_data_size.
    // Expected: emit a protected 0-RTT application_data record.
    _test_case.begin("TLS 1.3 client sends 0-RTT data only within the ticket allowance");

    auto prepare_client = [](tls_session& session, uint64 limit) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
        session.update_session_status(session_status_client_hello);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        session.get_session_info(from_client).begin_protection();
        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        early_state.set(session_early_data_limit, limit);
        early_state.set(session_early_data_sent, 0);
    };

    tls_session accepted_session;
    prepare_client(accepted_session, 4);
    tls_record_application_data accepted_record(&accepted_session);
    accepted_record.set_binary(binary_t{0x01, 0x02, 0x03});
    binary_t accepted_wire;
    return_t ret = accepted_record.write(from_client, accepted_wire);
    _test_case.test(ret, __FUNCTION__, "write early application data within max_early_data_size");
    _test_case.assert((false == accepted_wire.empty()), __FUNCTION__, "emit a protected 0-RTT application_data record");
    _test_case.assert(3 == accepted_session.get_session_info(from_server).get_keyvalue().get(session_early_data_sent), __FUNCTION__,
                      "account for early-data bytes sent across records");
    tls_record_application_data cumulative_overflow(&accepted_session);
    cumulative_overflow.set_binary(binary_t{0x04, 0x05});
    binary_t cumulative_overflow_wire;
    ret = cumulative_overflow.write(from_client, cumulative_overflow_wire);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce max_early_data_size cumulatively across records");
    _test_case.assert(cumulative_overflow_wire.empty(), __FUNCTION__, "do not emit a record that exceeds the remaining early-data allowance");
    _test_case.assert(3 == accepted_session.get_session_info(from_server).get_keyvalue().get(session_early_data_sent), __FUNCTION__,
                      "preserve the sent-byte counter after cumulative overflow");

    tls_session accepted_reader;
    accepted_reader.set_type(session_type_t::tls);
    auto& accepted_reader_protection = accepted_reader.get_tls_protection();
    accepted_reader_protection.set_tls_version(tls_13);
    accepted_reader_protection.set_cipher_suite(0x1301);
    accepted_reader_protection.set_flow(tls_flow_t::zero_rtt);
    accepted_reader_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    accepted_reader_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    accepted_reader.update_session_status(session_status_client_hello);
    accepted_reader.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    accepted_reader.get_session_info(from_client).begin_protection();
    accepted_reader.get_keyvalue().set(session_server_psk_selected_identity, 0);
    auto& accepted_reader_state = accepted_reader.get_session_info(from_server).get_keyvalue();
    accepted_reader_state.set(session_early_data_offered, 1);
    accepted_reader_state.set(session_early_data_accepted, 1);
    accepted_reader_state.set(session_early_data_limit, 4);
    accepted_reader_state.set(session_early_data_received, 0);
    tls_records accepted_records;
    ret = accepted_records.read(&accepted_reader, from_client, accepted_wire);
    _test_case.test(ret, __FUNCTION__, "decrypt and deliver accepted 0-RTT application data");
    _test_case.assert(1 == accepted_records.size(), __FUNCTION__, "retain the accepted early-data record");
    if (accepted_records.size()) {
        auto decoded = static_cast<tls_record_application_data*>(accepted_records.getat(0));
        _test_case.assert(binary_t({0x01, 0x02, 0x03}) == decoded->get_binary(), __FUNCTION__, "deliver the authenticated early-data plaintext");
    }
    _test_case.assert(3 == accepted_reader_state.get(session_early_data_received), __FUNCTION__, "account accepted early-data bytes against the ticket limit");

    tls_session bad_mac_reader;
    bad_mac_reader.set_type(session_type_t::tls);
    auto& bad_mac_protection = bad_mac_reader.get_tls_protection();
    bad_mac_protection.set_tls_version(tls_13);
    bad_mac_protection.set_cipher_suite(0x1301);
    bad_mac_protection.set_flow(tls_flow_t::zero_rtt);
    bad_mac_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    bad_mac_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    bad_mac_reader.update_session_status(session_status_client_hello);
    bad_mac_reader.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    bad_mac_reader.get_session_info(from_client).begin_protection();
    bad_mac_reader.get_keyvalue().set(session_server_psk_selected_identity, 0);
    auto& bad_mac_state = bad_mac_reader.get_session_info(from_server).get_keyvalue();
    bad_mac_state.set(session_early_data_offered, 1);
    bad_mac_state.set(session_early_data_accepted, 1);
    bad_mac_state.set(session_early_data_limit, 4);
    bad_mac_state.set(session_early_data_received, 0);
    binary_t corrupted_early_wire = accepted_wire;
    if (false == corrupted_early_wire.empty()) {
        corrupted_early_wire.back() ^= 0x01;
    }
    tls_records corrupted_early_records;
    return_t bad_mac_ret = corrupted_early_records.read(&bad_mac_reader, from_client, corrupted_early_wire);
    _test_case.assert(errorcode_t::success != bad_mac_ret, __FUNCTION__, "abort when an accepted 0-RTT record fails AEAD authentication");
    _test_case.assert(0 == corrupted_early_records.size(), __FUNCTION__, "do not deliver unauthenticated accepted early data");
    size_t fatal_bad_record_mac_count = 0;
    bad_mac_reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::bad_record_mac == desc)) {
            ++fatal_bad_record_mac_count;
        }
    });
    _test_case.assert(1 == fatal_bad_record_mac_count, __FUNCTION__, "send exactly one fatal bad_record_mac for failed accepted early-data authentication");

    tls_session server_overflow_reader;
    server_overflow_reader.set_type(session_type_t::tls);
    auto& server_overflow_protection = server_overflow_reader.get_tls_protection();
    server_overflow_protection.set_tls_version(tls_13);
    server_overflow_protection.set_cipher_suite(0x1301);
    server_overflow_protection.set_flow(tls_flow_t::zero_rtt);
    server_overflow_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    server_overflow_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    server_overflow_reader.update_session_status(session_status_client_hello);
    server_overflow_reader.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    server_overflow_reader.get_session_info(from_client).begin_protection();
    server_overflow_reader.get_keyvalue().set(session_server_psk_selected_identity, 0);
    auto& server_overflow_state = server_overflow_reader.get_session_info(from_server).get_keyvalue();
    server_overflow_state.set(session_early_data_offered, 1);
    server_overflow_state.set(session_early_data_accepted, 1);
    server_overflow_state.set(session_early_data_limit, 2);
    tls_records server_overflow_records;
    ret = server_overflow_records.read(&server_overflow_reader, from_client, accepted_wire);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject accepted early data that exceeds the ticket allowance");
    _test_case.assert(server_overflow_reader.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__, "raise a fatal alert for excess early-data bytes");
    size_t early_data_overflow_alert_count = 0;
    server_overflow_reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++early_data_overflow_alert_count;
        }
    });
    _test_case.assert(1 == early_data_overflow_alert_count, __FUNCTION__,
                      "report exactly one fatal unexpected_message for accepted early data beyond max_early_data_size");

    tls_session overflow_session;
    prepare_client(overflow_session, 2);
    tls_record_application_data overflow_record(&overflow_session);
    overflow_record.set_binary(binary_t{0x01, 0x02, 0x03});
    binary_t overflow_wire;
    ret = overflow_record.write(from_client, overflow_wire);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject early data that exceeds max_early_data_size");
    _test_case.assert(overflow_wire.empty(), __FUNCTION__, "do not emit an over-limit 0-RTT record");
    _test_case.assert(0 == overflow_session.get_session_info(from_server).get_keyvalue().get(session_early_data_sent), __FUNCTION__,
                      "do not advance the sent-byte counter after an over-limit write");

    tls_session no_offer_session;
    prepare_client(no_offer_session, 4);
    no_offer_session.get_session_info(from_server).get_keyvalue().set(session_early_data_offered, 0);
    tls_record_application_data no_offer_record(&no_offer_session);
    no_offer_record.set_binary(binary_t{0x01});
    binary_t no_offer_wire;
    ret = no_offer_record.write(from_client, no_offer_wire);
    _test_case.assert(errorcode_t::bad_request == ret, __FUNCTION__, "reject 0-RTT writes when ClientHello did not offer early_data");
    _test_case.assert(no_offer_wire.empty(), __FUNCTION__, "do not emit early data without the extension");
}

static void test_tls13_server_requires_consistent_early_data_acceptance_signal() {
    // Scenario under test: TLS 1.3 server acceptance state matches the serialized EncryptedExtensions early_data signal.
    // Action: write EncryptedExtensions while declining an ineligible early-data offer.
    // Expected: still emit EncryptedExtensions after declining early data.
    _test_case.begin("TLS 1.3 server acceptance state matches the serialized EncryptedExtensions early_data signal");

    auto prepare_server = [](tls_session& session, bool eligible) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.reset_transcript_hash(&session);
        session.update_session_status(session_status_server_hello);
        session.get_keyvalue().set(session_server_psk_selected_identity, 0);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);

        tls_resumption_ticket ticket;
        ticket.identity = binary_t{0x01};
        ticket.version = tls_13;
        ticket.cipher_suite = 0x1301;
        ticket.max_early_data_size = 1024;
        session.set_early_data_ticket(ticket);

        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        // Acceptance is an outcome of successfully writing the EE signal,
        // not an input flag that must already be set by the caller.
        early_state.set(session_early_data_accepted, 0);
        early_state.set(session_early_data_limit, eligible ? 1024 : 0);
    };

    tls_session unapproved_session;
    prepare_server(unapproved_session, false);
    tls_handshake_encrypted_extensions unapproved_ee(&unapproved_session);
    unapproved_ee.get_extensions().add(new tls_extension_early_data(&unapproved_ee));
    binary_t unapproved_wire;
    return_t ret = unapproved_ee.write(from_server, unapproved_wire);
    _test_case.test(ret, __FUNCTION__, "write EncryptedExtensions while declining an ineligible early-data offer");
    _test_case.assert(false == unapproved_wire.empty(), __FUNCTION__, "still emit EncryptedExtensions after declining early data");
    bool unapproved_early_data_emitted = false;
    for (size_t i = 0; i + 3 < unapproved_wire.size(); ++i) {
        if ((0x00 == unapproved_wire[i]) && (0x2a == unapproved_wire[i + 1]) && (0x00 == unapproved_wire[i + 2]) && (0x00 == unapproved_wire[i + 3])) {
            unapproved_early_data_emitted = true;
            break;
        }
    }
    _test_case.assert(false == unapproved_early_data_emitted, __FUNCTION__, "omit early_data for an ineligible ticket");
    _test_case.assert(tls_flow_t::one_rtt == unapproved_session.get_tls_protection().get_flow(), __FUNCTION__,
                      "switch to handshake traffic keys after declining early data");
    _test_case.assert(0 == unapproved_session.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "do not record acceptance when the extension is omitted");

    tls_session accepted_session;
    prepare_server(accepted_session, true);
    tls_handshake_encrypted_extensions accepted_ee(&accepted_session);
    accepted_ee.get_extensions().add(new tls_extension_early_data(&accepted_ee));
    binary_t accepted_wire;
    ret = accepted_ee.write(from_server, accepted_wire);
    _test_case.test(ret, __FUNCTION__, "serialize early_data for a valid offered ticket before recording acceptance");
    _test_case.assert(false == accepted_wire.empty(), __FUNCTION__, "emit the accepted early_data indication");
    _test_case.assert(tls_flow_t::zero_rtt == accepted_session.get_tls_protection().get_flow(), __FUNCTION__, "retain zero_rtt while the acceptance indication is sent");
    _test_case.assert(1 == accepted_session.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record acceptance after the EncryptedExtensions signal is serialized");

    tls_session direct_session;
    prepare_server(direct_session, true);
    tls_handshake_encrypted_extensions direct_ee(&direct_session);
    tls_extension_early_data direct_extension(&direct_ee);
    binary_t direct_wire;
    ret = direct_extension.write(from_server, direct_wire);
    _test_case.test(ret, __FUNCTION__, "directly serialize an eligible EncryptedExtensions early_data extension");
    _test_case.assert(false == direct_wire.empty(), __FUNCTION__, "emit the directly serialized early_data indication");
    _test_case.assert(1 == direct_session.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record acceptance after a direct EncryptedExtensions early_data write");

    tls_session failed_session;
    prepare_server(failed_session, true);
    auto failed_ticket = failed_session.get_early_data_ticket();
    failed_ticket.alpn = binary_t{0x02, 'h', '2'};
    failed_session.set_early_data_ticket(failed_ticket);
    const binary_t previous_alpn{0x02, 'h', '1'};
    failed_session.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, previous_alpn);
    failed_session.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 4096);
    tls_handshake_encrypted_extensions failed_ee(&failed_session);
    auto failed_alpn = new tls_extension_alpn(&failed_ee);
    failed_alpn->set_protocols(failed_ticket.alpn);
    failed_ee.get_extensions().add(failed_alpn);
    auto failed_record_limit = new tls_extension_record_size_limit(&failed_ee);
    failed_record_limit->set_record_size_limit(2048);
    failed_ee.get_extensions().add(failed_record_limit);
    failed_ee.get_extensions().add(new tls_extension_early_data(&failed_ee));
    auto invalid_modes = new tls_extension_psk_key_exchange_modes(&failed_ee);
    invalid_modes->add(1);
    failed_ee.get_extensions().add(invalid_modes);
    binary_t failed_wire;
    ret = failed_ee.write(from_server, failed_wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "fail EncryptedExtensions serialization after writing ALPN, record_size_limit, and early_data");
    _test_case.assert(0 == failed_session.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "roll back provisional early-data acceptance when the complete extension block fails");
    _test_case.assert(previous_alpn == failed_session.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                      "restore the previous negotiated ALPN when the extension block fails");
    _test_case.assert(4096 == failed_session.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                      "restore the previous record size limit when the extension block fails");
    _test_case.assert(tls_flow_t::zero_rtt == failed_session.get_tls_protection().get_flow(), __FUNCTION__,
                      "preserve the early-data flow when EncryptedExtensions serialization fails");
    _test_case.assert(0 == (session_status_encrypted_extensions & failed_session.get_session_status()), __FUNCTION__,
                      "do not commit EncryptedExtensions status after serialization failure");

    tls_session omitted_session;
    prepare_server(omitted_session, true);
    tls_handshake_encrypted_extensions omitted_ee(&omitted_session);
    binary_t omitted_wire;
    ret = omitted_ee.write(from_server, omitted_wire);
    _test_case.test(ret, __FUNCTION__, "write EncryptedExtensions without early_data");
    _test_case.assert(tls_flow_t::one_rtt == omitted_session.get_tls_protection().get_flow(), __FUNCTION__,
                      "reject early data when EncryptedExtensions does not carry the acceptance signal");
    _test_case.assert(0 == omitted_session.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "clear stale acceptance state when the extension is omitted");
}

static void test_tls13_encrypted_extensions_rejects_truncated_extension_header() {
    _test_case.begin("TLS 1.3 EncryptedExtensions rejects a truncated trailing extension header");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    session.update_session_status(session_status_server_hello);

    // The extension vector declares one byte, which cannot contain an extension
    // header. The handshake message itself is complete and fully length-bounded.
    binary_t wire = {static_cast<byte_t>(tls_handshake_type_t::encrypted_extensions), 0x00, 0x00, 0x03, 0x00, 0x01, 0x00};
    tls_handshake_encrypted_extensions encrypted_extensions(&session);
    size_t pos = 0;
    return_t ret = encrypted_extensions.read(from_server, wire.data(), wire.size(), pos);

    size_t decode_error_count = 0;
    session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
            ++decode_error_count;
        }
    });
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject the incomplete extension header in a complete EncryptedExtensions message");
    _test_case.assert(1 == decode_error_count, __FUNCTION__, "report exactly one fatal decode_error for the truncated EncryptedExtensions extension vector");
    _test_case.assert(0 == (session_status_encrypted_extensions & session.get_session_status()), __FUNCTION__,
                      "do not commit EncryptedExtensions status after extension parsing fails");
}

void testcase_gpt_early_data() {
    test_tls13_fatal_reset_clears_hrr_flow();
    test_tls13_encrypted_extensions_failure_after_hrr_disables_client_protection();
    test_tls13_encrypted_extensions_failure_clears_selected_psk_state();
    test_tls13_encrypted_extensions_rejects_truncated_extension_header();
    test_tls13_fatal_reset_wakes_status_waiter();
    test_tls13_server_requires_consistent_early_data_acceptance_signal();
    test_tls13_server_rejects_early_data_for_nonzero_selected_identity();
    test_tls13_server_requires_early_data_ticket_permission();
    test_tls13_client_requires_psk_for_early_data_offer();
    test_tls13_server_records_early_data_offer_during_extension_parse();
    test_tls13_client_validates_early_data_acceptance_parameters();
    test_tls13_client_sends_bounded_early_data();
    test_tls13_end_of_early_data_usage_reset();
    test_tls13_end_of_early_data_requires_server_finished();
    test_tls13_end_of_early_data_read_validation();
    test_tls13_application_data_finished_direction_policy();
    test_tls13_handshake_protection_transition();
}