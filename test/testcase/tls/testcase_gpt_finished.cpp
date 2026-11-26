/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_finished.cpp
 * @author GPT
 * @desc   TLS Finished verification and record-epoch transition tests.
 */

#include "testcase_gpt_common.hpp"

static void configure_tls13_finished_application_epoch(tls_session& session) {
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
    protection.use_pre_master_secret(true);
    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::s_hs_traffic, binary_t(32, 0x11));
    secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x22));
    secrets.assign(tls_secret_t::s_ap_traffic, binary_t(32, 0x33));
    secrets.assign(tls_secret_t::c_ap_traffic, binary_t(32, 0x44));
    secrets.assign(tls_secret_t::application, binary_t(32, 0x99));
    secrets.assign(tls_secret_t::handshake_server_key, binary_t(16, 0x55));
    secrets.assign(tls_secret_t::handshake_server_iv, binary_t(12, 0x66));
    secrets.assign(tls_secret_t::handshake_client_key, binary_t(16, 0x77));
    secrets.assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x88));
    session.update_session_status(session_status_server_hello);
    session.update_session_status(session_status_encrypted_extensions);
    session.update_session_status(session_status_server_cert_verified);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::certificate_verify);
    session.get_session_info(from_server).begin_protection();
    session.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
    session.get_session_info(from_client).begin_protection();
    session.set_recordno(from_server, 7);
    session.set_recordno(from_client, 9);
}

static void configure_tls13_psk_finished(tls_session& session, bool psk_selected) {
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.use_pre_master_secret(true);
    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::s_hs_traffic, binary_t(32, 0x11));
    secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x22));
    secrets.assign(tls_secret_t::s_ap_traffic, binary_t(32, 0x33));
    secrets.assign(tls_secret_t::c_ap_traffic, binary_t(32, 0x44));
    secrets.assign(tls_secret_t::application, binary_t(32, 0x99));
    secrets.assign(tls_secret_t::handshake_server_key, binary_t(16, 0x55));
    secrets.assign(tls_secret_t::handshake_server_iv, binary_t(12, 0x66));
    secrets.assign(tls_secret_t::handshake_client_key, binary_t(16, 0x77));
    secrets.assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x88));
    session.update_session_status(session_status_server_hello);
    session.update_session_status(session_status_encrypted_extensions);
    session.get_keyvalue().set(session_client_psk_identity_count, psk_selected ? 1 : 0);
    session.get_keyvalue().set(session_server_psk_selected_identity, psk_selected ? 0 : 0xffff);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::encrypted_extensions);
    session.get_session_info(from_server).begin_protection();
    session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    session.get_session_info(from_client).begin_protection();
}

static void configure_tls12_finished_sequence(tls_session& session) {
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    protection.get_secrets().assign(tls_secret_t::master, binary_t(48, 0x55));
    protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
    protection.get_secrets().assign(tls_secret_t::client_iv, binary_t(4, 0x22));
    protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x33));
    protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x44));
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.update_session_status(session_status_server_key_exchange);
    session.update_session_status(session_status_client_key_exchange);
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).begin_protection();
    session.set_recordno(from_client, 0);
    session.set_recordno(from_server, 0);
}

static bool exchange_tls12_interleaved_application_records(tls_session& writer, tls_session& reader, const char* test_function) {
    for (uint64 index = 0; index < 3; ++index) {
        const auto expected_client_sequence = 3 + index;
        const std::string client_message = "client application record " + std::to_string(index);
        tls_record_application_data client_record(&writer, client_message);
        binary_t client_wire;
        return_t ret = client_record.write(from_client, client_wire);
        _test_case.test(ret, test_function, "write consecutive TLS 1.2 Client Application Data");
        if (errorcode_t::success != ret) return false;
        _test_case.assert(expected_client_sequence == writer.get_recordno(from_client), test_function,
                          "increment client write sequence for each Application Data record");
        tls_records client_records;
        ret = client_records.read(&reader, from_client, client_wire);
        _test_case.test(ret, test_function, "read consecutive TLS 1.2 Client Application Data");
        if (errorcode_t::success != ret || 1 != client_records.size()) {
            _test_case.assert(false, test_function, "decode consecutive TLS 1.2 Client Application Data");
            return false;
        }
        auto decoded_client = (tls_record_application_data*)client_records.getat(0);
        binary_t expected_client(client_message.begin(), client_message.end());
        _test_case.assert(expected_client == decoded_client->get_binary(), test_function, "authenticate each consecutive client record with its sequence");
        _test_case.assert(expected_client_sequence == reader.get_recordno(from_client), test_function, "increment client read sequence for each Application Data record");
        const auto expected_server_sequence = 3 + index;
        const std::string server_message = "server application record " + std::to_string(index);
        tls_record_application_data server_record(&writer, server_message);
        binary_t server_wire;
        ret = server_record.write(from_server, server_wire);
        _test_case.test(ret, test_function, "write consecutive TLS 1.2 Server Application Data");
        if (errorcode_t::success != ret) return false;
        _test_case.assert(expected_server_sequence == writer.get_recordno(from_server), test_function,
                          "increment server write sequence for each Application Data record");
        tls_records server_records;
        ret = server_records.read(&reader, from_server, server_wire);
        _test_case.test(ret, test_function, "read consecutive TLS 1.2 Server Application Data");
        if (errorcode_t::success != ret || 1 != server_records.size()) {
            _test_case.assert(false, test_function, "decode consecutive TLS 1.2 Server Application Data");
            return false;
        }
        auto decoded_server_record = (tls_record_application_data*)server_records.getat(0);
        binary_t expected_server(server_message.begin(), server_message.end());
        _test_case.assert(expected_server == decoded_server_record->get_binary(), test_function, "authenticate each consecutive server record with its sequence");
        _test_case.assert(expected_server_sequence == reader.get_recordno(from_server), test_function, "increment server read sequence for each Application Data record");
        _test_case.assert(expected_client_sequence == writer.get_recordno(from_client), test_function, "server records do not alter client write sequence");
        _test_case.assert(expected_server_sequence == writer.get_recordno(from_server), test_function, "client records do not alter server write sequence");
        _test_case.assert(expected_client_sequence == reader.get_recordno(from_client), test_function, "server records do not alter client read sequence");
        _test_case.assert(expected_server_sequence == reader.get_recordno(from_server), test_function, "client records do not alter server read sequence");
    }
    return true;
}

static void test_finished_record_sequence_transition() {
    // Action: exchange Finished messages and inspect the record sequence in each direction.
    // Scenario under test: TLS Finished record sequence transition.
    // Expected: preserve TLS 1.2 client record sequence after Finished.
    _test_case.begin("TLS Finished record sequence transition");

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_2);

        session.set_recordno(from_client, 1);
        tls_handshake_finished client_finished(&session);
        client_finished.run_scheduled(from_client);
        _test_case.assert(1 == session.get_recordno(from_client), __FUNCTION__, "preserve TLS 1.2 client record sequence after Finished");

        session.set_recordno(from_server, 1);
        tls_handshake_finished server_finished(&session);
        server_finished.run_scheduled(from_server);
        _test_case.assert(1 == session.get_recordno(from_server), __FUNCTION__, "preserve TLS 1.2 server record sequence after Finished");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);

        session.set_recordno(from_client, 9);
        tls_handshake_finished client_finished(&session);
        client_finished.run_scheduled(from_client);
        _test_case.assert(0 == session.get_recordno(from_client), __FUNCTION__, "reset TLS 1.3 client record sequence at application traffic key transition");

        session.set_recordno(from_server, 11);
        tls_handshake_finished server_finished(&session);
        server_finished.run_scheduled(from_server);
        _test_case.assert(0 == session.get_recordno(from_server), __FUNCTION__, "reset TLS 1.3 server record sequence at application traffic key transition");
    }
}

static void test_tls13_finished_record_boundary() {
    // Action: serialize Finished followed by NewSessionTicket in the same record stream.
    // Scenario under test: TLS 1.3 Finished record boundary.
    // Expected: reject NewSessionTicket coalesced after TLS 1.3 Finished.
    _test_case.begin("TLS 1.3 Finished record boundary");

    tls_session writer;
    writer.set_type(session_type_t::tls);
    writer.get_tls_protection().set_tls_version(tls1_3);
    writer.update_session_status(session_status_server_hello);

    tls_record_application_data outgoing(&writer);
    outgoing << new tls_handshake_finished(&writer);
    outgoing << new tls_handshake_new_session_ticket(&writer);

    binary_t wire;
    return_t ret = outgoing.write(from_server, wire);
    _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject NewSessionTicket coalesced after TLS 1.3 Finished");
    _test_case.assert(wire.empty(), __FUNCTION__, "emit no record when Finished is not the final handshake message");
}

static void test_tls13_finished_application_epoch_integration() {
    // Scenario under test: TLS 1.3 Finished application traffic epoch integration.
    // Action: select the expected server-direction traffic key.
    // Expected: select the expected server-direction traffic IV.
    _test_case.begin("TLS 1.3 Finished application traffic epoch integration");

    tls_session writer;
    tls_session reader;
    configure_tls13_finished_application_epoch(writer);
    configure_tls13_finished_application_epoch(reader);

    auto assert_server_key = [](tls_session& session, tls_secret_t expected_key, tls_secret_t expected_iv, const char* message) -> void {
        tls_secret_t actual_key{};
        tls_secret_t actual_iv{};
        auto& protection = session.get_tls_protection();
        return_t ret = protection.get_aead_key(&session, from_server, protection_space_t::tls, actual_key, actual_iv);
        _test_case.test(ret, __FUNCTION__, message);
        _test_case.assert(expected_key == actual_key, __FUNCTION__, "select the expected server-direction traffic key");
        _test_case.assert(expected_iv == actual_iv, __FUNCTION__, "select the expected server-direction traffic IV");
    };

    auto assert_client_key = [](tls_session& session, tls_secret_t expected_key, tls_secret_t expected_iv, const char* message) -> void {
        tls_secret_t actual_key{};
        tls_secret_t actual_iv{};
        auto& protection = session.get_tls_protection();
        return_t ret = protection.get_aead_key(&session, from_client, protection_space_t::tls, actual_key, actual_iv);
        _test_case.test(ret, __FUNCTION__, message);
        _test_case.assert(expected_key == actual_key, __FUNCTION__, "select the expected client-direction traffic key");
        _test_case.assert(expected_iv == actual_iv, __FUNCTION__, "select the expected client-direction traffic IV");
    };

    assert_server_key(writer, tls_secret_t::handshake_server_key, tls_secret_t::handshake_server_iv, "select handshake traffic key before Server Finished");
    assert_server_key(reader, tls_secret_t::handshake_server_key, tls_secret_t::handshake_server_iv, "select handshake traffic key before inbound Server Finished");
    assert_client_key(writer, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv, "select client handshake traffic key before Client Finished");
    assert_client_key(reader, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv,
                      "select client handshake traffic key before inbound Client Finished");

    tls_record_application_data outgoing_finished(&writer);
    outgoing_finished << new tls_handshake_finished(&writer);
    binary_t finished_wire;
    return_t ret = outgoing_finished.write(from_server, finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Server Finished under handshake traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset outbound sequence at Server Finished epoch transition");

    tls_records decoded_finished;
    ret = decoded_finished.read(&reader, from_server, finished_wire);
    _test_case.test(ret, __FUNCTION__, "read and verify Server Finished under handshake traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "reset inbound sequence at Server Finished epoch transition");
    _test_case.assert(0 != (reader.get_session_status() & session_status_server_finished), __FUNCTION__, "record successful Server Finished");

    assert_server_key(writer, tls_secret_t::application_server_key, tls_secret_t::application_server_iv, "select application traffic key after outbound Server Finished");
    assert_server_key(reader, tls_secret_t::application_server_key, tls_secret_t::application_server_iv, "select application traffic key after inbound Server Finished");

    assert_client_key(writer, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv, "retain client handshake traffic key until Client Finished");
    assert_client_key(reader, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv, "retain inbound client handshake traffic key until Client Finished");

    tls_record_application_data outgoing_client_finished(&writer);
    outgoing_client_finished << new tls_handshake_finished(&writer);
    binary_t client_finished_wire;
    ret = outgoing_client_finished.write(from_client, client_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Client Finished under client handshake traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset outbound client sequence at Client Finished epoch transition");

    tls_records decoded_client_finished;
    ret = decoded_client_finished.read(&reader, from_client, client_finished_wire);
    _test_case.test(ret, __FUNCTION__, "read and verify Client Finished under client handshake traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "reset inbound client sequence at Client Finished epoch transition");
    _test_case.assert(0 != (reader.get_session_status() & session_status_client_finished), __FUNCTION__, "record successful Client Finished");

    assert_client_key(writer, tls_secret_t::application_client_key, tls_secret_t::application_client_iv,
                      "select client application traffic key after outbound Client Finished");
    assert_client_key(reader, tls_secret_t::application_client_key, tls_secret_t::application_client_iv,
                      "select client application traffic key after inbound Client Finished");

    auto& writer_secrets = writer.get_tls_protection().get_secrets();
    auto& reader_secrets = reader.get_tls_protection().get_secrets();
    _test_case.assert(16 == writer_secrets.get(tls_secret_t::application_server_key).size(), __FUNCTION__,
                      "derive server application traffic key from application traffic secret");
    _test_case.assert(12 == writer_secrets.get(tls_secret_t::application_server_iv).size(), __FUNCTION__,
                      "derive server application traffic IV from application traffic secret");
    _test_case.assert(writer_secrets.get(tls_secret_t::application_server_key) == reader_secrets.get(tls_secret_t::application_server_key), __FUNCTION__,
                      "derive matching server application traffic keys at both endpoints");
    _test_case.assert(writer_secrets.get(tls_secret_t::application_server_key) != writer_secrets.get(tls_secret_t::handshake_server_key), __FUNCTION__,
                      "replace the server handshake key with a distinct application key");
    _test_case.assert(16 == writer_secrets.get(tls_secret_t::application_client_key).size(), __FUNCTION__,
                      "derive client application traffic key from application traffic secret");
    _test_case.assert(12 == writer_secrets.get(tls_secret_t::application_client_iv).size(), __FUNCTION__,
                      "derive client application traffic IV from application traffic secret");
    _test_case.assert(writer_secrets.get(tls_secret_t::application_client_key) == reader_secrets.get(tls_secret_t::application_client_key), __FUNCTION__,
                      "derive matching client application traffic keys at both endpoints");
    _test_case.assert(writer_secrets.get(tls_secret_t::application_client_key) != writer_secrets.get(tls_secret_t::handshake_client_key), __FUNCTION__,
                      "replace the client handshake key with a distinct application key");

    const std::string message = "TLS 1.3 application data after Server Finished";
    tls_record_application_data outgoing_application(&writer, message);
    binary_t application_wire;
    ret = outgoing_application.write(from_server, application_wire);
    _test_case.test(ret, __FUNCTION__, "write Application Data with server application traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == writer.get_recordno(from_server), __FUNCTION__, "start application epoch at outbound sequence zero");

    tls_records decoded_application;
    ret = decoded_application.read(&reader, from_server, application_wire);
    _test_case.test(ret, __FUNCTION__, "read Application Data with server application traffic key");
    if (errorcode_t::success != ret || 1 != decoded_application.size()) {
        _test_case.assert(false, __FUNCTION__, "decode TLS 1.3 Application Data after Server Finished");
        return;
    }
    auto decoded = (tls_record_application_data*)decoded_application.getat(0);
    binary_t expected(message.begin(), message.end());
    _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "authenticate Application Data in the new server application epoch");
    _test_case.assert(1 == reader.get_recordno(from_server), __FUNCTION__, "consume application epoch inbound sequence zero");

    const std::string client_message = "TLS 1.3 client application data after Client Finished";
    tls_record_application_data outgoing_client_application(&writer, client_message);
    binary_t client_application_wire;
    ret = outgoing_client_application.write(from_client, client_application_wire);
    _test_case.test(ret, __FUNCTION__, "write Application Data with client application traffic key");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == writer.get_recordno(from_client), __FUNCTION__, "start client application epoch at outbound sequence zero");

    tls_records decoded_client_application;
    ret = decoded_client_application.read(&reader, from_client, client_application_wire);
    _test_case.test(ret, __FUNCTION__, "read Application Data with client application traffic key");
    if (errorcode_t::success != ret || 1 != decoded_client_application.size()) {
        _test_case.assert(false, __FUNCTION__, "decode TLS 1.3 client Application Data after Client Finished");
        return;
    }
    auto decoded_client = (tls_record_application_data*)decoded_client_application.getat(0);
    binary_t expected_client(client_message.begin(), client_message.end());
    _test_case.assert(expected_client == decoded_client->get_binary(), __FUNCTION__, "authenticate client Application Data in the new client application epoch");
    _test_case.assert(1 == reader.get_recordno(from_client), __FUNCTION__, "consume client application epoch inbound sequence zero");
}

static void test_tls13_psk_finished_without_certificate_authentication() {
    // Scenario under test: TLS 1.3 PSK-authenticated Finished without certificate authentication.
    // Action: exchange Server Finished and Client Finished after EncryptedExtensions.
    // Expected: accept both Finished messages without server certificate verification.
    _test_case.begin("TLS 1.3 PSK Finished does not require certificate authentication");

    tls_session writer;
    tls_session reader;
    configure_tls13_psk_finished(writer, true);
    configure_tls13_psk_finished(reader, true);

    _test_case.assert(0 == (writer.get_session_status() & session_status_server_cert_verified), __FUNCTION__,
                      "begin the PSK handshake without server certificate verification");
    _test_case.assert(0 == (reader.get_session_status() & session_status_server_cert_verified), __FUNCTION__,
                      "receive the PSK handshake without server certificate verification");

    tls_record_application_data outgoing_server_finished(&writer);
    outgoing_server_finished << new tls_handshake_finished(&writer);
    binary_t server_finished_wire;
    return_t ret = outgoing_server_finished.write(from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write PSK-authenticated Server Finished after EncryptedExtensions");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records decoded_server_finished;
    ret = decoded_server_finished.read(&reader, from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "verify PSK-authenticated Server Finished without a certificate");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 != (reader.get_session_status() & session_status_server_finished), __FUNCTION__, "record successful PSK-authenticated Server Finished");

    tls_record_application_data outgoing_client_finished(&writer);
    outgoing_client_finished << new tls_handshake_finished(&writer);
    binary_t client_finished_wire;
    ret = outgoing_client_finished.write(from_client, client_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Client Finished after the PSK-authenticated Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records decoded_client_finished;
    ret = decoded_client_finished.read(&reader, from_client, client_finished_wire);
    _test_case.test(ret, __FUNCTION__, "verify Client Finished in the PSK-authenticated handshake");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 != (reader.get_session_status() & session_status_client_finished), __FUNCTION__, "record successful PSK-authenticated Client Finished");

    // Keep the full-handshake prerequisite intact: without a selected PSK,
    // Finished must still wait for server certificate verification.
    tls_session unauthenticated_full_handshake;
    configure_tls13_psk_finished(unauthenticated_full_handshake, false);
    tls_record_application_data premature_server_finished(&unauthenticated_full_handshake);
    premature_server_finished << new tls_handshake_finished(&unauthenticated_full_handshake);
    binary_t rejected_server_finished_wire;
    ret = premature_server_finished.write(from_server, rejected_server_finished_wire);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject full-handshake Server Finished before server certificate verification");

    size_t unexpected_message_count = test_count_fatal_alert(unauthenticated_full_handshake, from_server, tls_alertdesc_t::unexpected_message);
    _test_case.assert(1 == unexpected_message_count, __FUNCTION__, "retain the fatal unexpected_message alert for a full handshake without certificate verification");
}

static void test_tls12_finished_record_sequence_integration() {
    // Scenario under test: TLS 1.2 Finished record sequence integration.
    // Action: write protected TLS 1.2 Client Finished.
    // Expected: consume one TLS 1.2 record sequence number for outbound Finished.
    _test_case.begin("TLS 1.2 Finished record sequence integration");

    tls_session writer;
    tls_session reader;
    configure_tls12_finished_sequence(writer);
    configure_tls12_finished_sequence(reader);

    tls_record_handshake outgoing_finished(&writer);
    outgoing_finished << new tls_handshake_finished(&writer);
    binary_t finished_wire;
    return_t ret = outgoing_finished.write(from_client, finished_wire);
    _test_case.test(ret, __FUNCTION__, "write protected TLS 1.2 Client Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == writer.get_recordno(from_client), __FUNCTION__, "consume one TLS 1.2 record sequence number for outbound Finished");

    tls_records decoded_finished;
    ret = decoded_finished.read(&reader, from_client, finished_wire);
    _test_case.test(ret, __FUNCTION__, "read and verify protected TLS 1.2 Client Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == reader.get_recordno(from_client), __FUNCTION__, "preserve the consumed TLS 1.2 sequence number after inbound Finished");
    _test_case.assert(0 != (reader.get_session_status() & session_status_client_finished), __FUNCTION__, "record Client Finished state after successful verification");

    // RFC 5077: the server sends NewSessionTicket after Client Finished but
    // before Server Finished. The client must stage it until Server Finished
    // has been successfully authenticated.
    const binary_t ticket_identity{0x10, 0x20, 0x30, 0x40};
    writer.get_tls_protection().get_secrets().assign(tls_secret_t::new_session_ticket, ticket_identity);
    writer.get_session_info(from_server).get_keyvalue().set(session_ticket_lifetime, 3600);
    tls_handshake_new_session_ticket outgoing_ticket(&writer);
    binary_t ticket_wire;
    ret = outgoing_ticket.write(from_server, ticket_wire);
    _test_case.test(ret, __FUNCTION__, "write TLS 1.2 NewSessionTicket after Client Finished");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_handshake_new_session_ticket incoming_ticket(&reader);
    size_t ticket_pos = 0;
    ret = incoming_ticket.read(from_server, ticket_wire.data(), ticket_wire.size(), ticket_pos);
    _test_case.test(ret, __FUNCTION__, "read TLS 1.2 NewSessionTicket before Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    auto& reader_secrets = reader.get_tls_protection().get_secrets();
    auto& reader_ticket_state = reader.get_session_info(from_server).get_keyvalue();
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__,
                      "do not publish a TLS 1.2 ticket before Server Finished authentication");
    _test_case.assert(ticket_identity == reader_secrets.get(tls_secret_t::new_session_ticket_pending), __FUNCTION__, "retain the received TLS 1.2 ticket as pending");
    _test_case.assert(1 == reader_ticket_state.get(session_ticket_pending), __FUNCTION__, "mark the received ticket pending");

    tls_record_handshake outgoing_server_finished(&writer);
    outgoing_server_finished << new tls_handshake_finished(&writer);
    binary_t server_finished_wire;
    ret = outgoing_server_finished.write(from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write protected TLS 1.2 Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == writer.get_recordno(from_server), __FUNCTION__, "consume one TLS 1.2 record sequence number for outbound Server Finished");

    tls_records decoded_server_finished;
    ret = decoded_server_finished.read(&reader, from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "read and verify protected TLS 1.2 Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == reader.get_recordno(from_server), __FUNCTION__, "consume one TLS 1.2 record sequence number for inbound Server Finished");
    _test_case.assert(0 != (reader.get_session_status() & session_status_server_finished), __FUNCTION__, "record Server Finished state after successful verification");
    _test_case.assert(ticket_identity == reader_secrets.get(tls_secret_t::new_session_ticket), __FUNCTION__,
                      "publish the TLS 1.2 ticket only after authenticating Server Finished");
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket_pending).empty(), __FUNCTION__, "clear pending ticket bytes after activation");
    _test_case.assert(3600 == reader_ticket_state.get(session_ticket_lifetime), __FUNCTION__, "publish ticket lifetime metadata after Server Finished");
    _test_case.assert(0 == reader_ticket_state.get(session_ticket_pending), __FUNCTION__, "clear pending ticket state after activation");

    const auto cached_tls12_tickets = reader.get_tls1_2_resumption_tickets();
    _test_case.assert(1 == cached_tls12_tickets.size(), __FUNCTION__, "cache the received TLS 1.2 ticket after Server Finished authentication");
    if (1 == cached_tls12_tickets.size()) {
        _test_case.assert(ticket_identity == cached_tls12_tickets[0].identity, __FUNCTION__, "retain the received opaque ticket identity");
        _test_case.assert(binary_t(48, 0x55) == cached_tls12_tickets[0].master_secret, __FUNCTION__, "associate the authenticated ticket with the current Master Secret");
        _test_case.assert(3600 == cached_tls12_tickets[0].lifetime, __FUNCTION__, "retain the ticket lifetime in the client cache");
        _test_case.assert(tls1_2 == static_cast<tls_version_t>(cached_tls12_tickets[0].version), __FUNCTION__, "retain the negotiated TLS version");
        _test_case.assert(0xc02f == cached_tls12_tickets[0].cipher_suite, __FUNCTION__, "retain the negotiated cipher suite");
    }

    const std::string message = "application data after Finished";
    tls_record_application_data outgoing_application(&writer, message);
    binary_t application_wire;
    ret = outgoing_application.write(from_client, application_wire);
    _test_case.test(ret, __FUNCTION__, "write TLS 1.2 Application Data after Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(2 == writer.get_recordno(from_client), __FUNCTION__, "continue outbound TLS 1.2 sequence after Finished");

    tls_records decoded_application;
    ret = decoded_application.read(&reader, from_client, application_wire);
    _test_case.test(ret, __FUNCTION__, "read TLS 1.2 Application Data after Finished");
    if (errorcode_t::success != ret || 1 != decoded_application.size()) {
        _test_case.assert(false, __FUNCTION__, "decode TLS 1.2 Application Data after Finished");
        return;
    }
    auto decoded = (tls_record_application_data*)decoded_application.getat(0);
    binary_t expected(message.begin(), message.end());
    _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "authenticate Application Data using the continued TLS 1.2 sequence");
    _test_case.assert(2 == reader.get_recordno(from_client), __FUNCTION__, "continue inbound TLS 1.2 sequence after Finished");

    // The server direction has its own record sequence and must continue independently.
    const std::string response = "server application data after Finished";
    tls_record_application_data outgoing_response(&writer, response);
    binary_t response_wire;
    ret = outgoing_response.write(from_server, response_wire);
    _test_case.test(ret, __FUNCTION__, "write TLS 1.2 Server Application Data after Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(2 == writer.get_recordno(from_server), __FUNCTION__, "continue outbound server sequence independently of client sequence");
    _test_case.assert(2 == writer.get_recordno(from_client), __FUNCTION__, "preserve outbound client sequence while writing server data");

    tls_records decoded_response;
    ret = decoded_response.read(&reader, from_server, response_wire);
    _test_case.test(ret, __FUNCTION__, "read TLS 1.2 Server Application Data after Finished");
    if (errorcode_t::success != ret || 1 != decoded_response.size()) {
        _test_case.assert(false, __FUNCTION__, "decode TLS 1.2 Server Application Data after Finished");
        return;
    }
    auto decoded_server = (tls_record_application_data*)decoded_response.getat(0);
    binary_t expected_response(response.begin(), response.end());
    _test_case.assert(expected_response == decoded_server->get_binary(), __FUNCTION__, "authenticate server Application Data using its continued sequence");
    _test_case.assert(2 == reader.get_recordno(from_server), __FUNCTION__, "continue inbound server sequence independently of client sequence");
    _test_case.assert(2 == reader.get_recordno(from_client), __FUNCTION__, "preserve inbound client sequence while reading server data");

    // Exercise multiple records in both directions, interleaving the independent sequences.
    if (false == exchange_tls12_interleaved_application_records(writer, reader, __FUNCTION__)) {
        return;
    }
}

static void test_finished_calculation_propagates_invalid_algorithm() {
    // Scenario under test: Finished verify_data calculation with an unsupported hash algorithm.
    // Action: configure a Finished calculation with an invalid digest identifier.
    // Expected: propagate the digest failure instead of emitting verify_data.
    _test_case.begin("Finished calculation propagates an invalid hash algorithm");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);

    tls_secret_t typeof_secret{};
    binary_t verify_data;
    return_t ret = protection.calc_finished(from_server, hash_algorithm_t{}, 32, typeof_secret, verify_data);
    _test_case.assert(errorcode_t::unknown == ret, __FUNCTION__, "return the Finished calculation error to the caller");
    _test_case.assert(verify_data.empty(), __FUNCTION__, "do not produce verify_data after a calculation error");
}

static void test_tls13_finished_postprocess_unsupported_local_cipher_suite_is_terminal() {
    // Scenario under test: TLS 1.3 Finished cannot initialize transcript hashing from the unsupported local cipher suite.
    // Action: run Finished post-processing with no usable local cipher-suite hash.
    // Expected: terminate the session with internal_error before committing Finished state.
    _test_case.begin("TLS 1.3 Finished rejects an unsupported local cipher suite");

    class finished_postprocess_probe : public tls_handshake_finished {
       public:
        explicit finished_postprocess_probe(tls_session* session) : tls_handshake_finished(session) {}
        return_t run_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) { return do_postprocess(dir, tls_io_operation_t::read, stream, size); }
    };

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::one_rtt);
    protection.reset_transcript_hash(&session);
    // Cipher suite zero resolves to the TLS_NULL registry entry, which has no
    // block-cipher parameters and makes the local key-schedule calculation fail.
    protection.set_cipher_suite(0);

    session.update_session_status(session_status_server_hello);
    session.update_session_status(session_status_encrypted_extensions);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::encrypted_extensions);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    session.get_keyvalue().set(session_client_psk_identity_count, 1);
    session.get_keyvalue().set(session_server_psk_selected_identity, 0);

    finished_postprocess_probe finished(&session);
    const byte_t marker = 0;
    return_t ret = finished.run_postprocess(from_server, &marker, sizeof(marker));
    _test_case.assert(errorcode_t::internal_error == ret, __FUNCTION__, "map an unsupported local cipher suite to internal_error");

    _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "reset handshake status after local Finished processing failure");
    _test_case.assert(tls_handshake_type_t::client_hello == session.get_session_info(from_server).get_status(), __FUNCTION__,
                      "reset the server handshake cursor after local Finished processing failure");
    _test_case.assert(0 == session.get_keyvalue().get(session_handshake_finished), __FUNCTION__, "do not commit Finished after key-schedule failure");

    size_t fatal_internal_error_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::internal_error);
    _test_case.assert(1 == fatal_internal_error_count, __FUNCTION__, "queue exactly one fatal internal_error for local Finished processing failure");
}

static void test_tls13_finished_requires_cipher_suite() {
    // Action: attempt to serialize TLS 1.3 Finished before negotiating a cipher suite.
    // Scenario under test: TLS 1.3 Finished without a negotiated cipher suite.
    // Expected: fail before emitting a malformed empty Finished message.
    _test_case.begin("TLS 1.3 Finished requires a negotiated cipher suite");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_flow(tls_flow_t::one_rtt);
    session.update_session_status(session_status_server_hello);
    session.update_session_status(session_status_encrypted_extensions);
    // Satisfy the non-PSK Finished flow prerequisite so the test reaches
    // do_write_body() and specifically exercises the missing-cipher-suite path.
    session.update_session_status(session_status_server_cert_verified);

    tls_handshake_finished finished(&session);
    binary_t wire;
    return_t ret = finished.write(from_server, wire);
    _test_case.assert(errorcode_t::internal_error == ret, __FUNCTION__, "report internal_error when local Finished state has no negotiated cipher suite");
    _test_case.assert(wire.empty(), __FUNCTION__, "emit no partial or empty Finished handshake message");
    _test_case.assert(0 == session.get_keyvalue().get(session_handshake_finished), __FUNCTION__, "do not commit Finished status after the write failure");
    _test_case.assert(1 == test_count_fatal_alert(session, from_server, tls_alertdesc_t::internal_error), __FUNCTION__,
                      "queue exactly one fatal internal_error for the missing local cipher suite");
}

static void test_tls12_finished_rejects_invalid_verify_data_without_ticket_activation() {
    // Action: send an invalid Server Finished while a newly issued session ticket is pending confirmation.
    // Scenario under test: TLS 1.2 Server Finished verification failure with a pending session ticket.
    // Expected: reject Finished and keep the ticket unpublished.
    _test_case.begin("TLS 1.2 invalid Server Finished does not activate a pending session ticket");

    auto configure = [](tls_session& session) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_2);
        protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        protection.get_secrets().assign(tls_secret_t::master, binary_t(48, 0x55));
        protection.reset_transcript_hash(&session);
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
        session.update_session_status(session_status_client_finished);
        session.get_session_info(from_server).begin_protection();
    };

    tls_session writer;
    tls_session reader;
    configure(writer);
    configure(reader);

    const binary_t pending_ticket{0x10, 0x20, 0x30, 0x40};
    auto& reader_secrets = reader.get_tls_protection().get_secrets();
    auto& ticket_state = reader.get_session_info(from_server).get_keyvalue();
    reader_secrets.assign(tls_secret_t::new_session_ticket_pending, pending_ticket);
    ticket_state.set(session_ticket_pending_lifetime, 3600);
    ticket_state.set(session_ticket_pending_timestamp, uint64(123456789));
    ticket_state.set(session_ticket_pending, 1);

    tls_handshake_finished outgoing_finished(&writer);
    binary_t finished_wire;
    return_t ret = outgoing_finished.write(from_server, finished_wire);
    _test_case.test(ret, __FUNCTION__, "write a valid TLS 1.2 Server Finished for the negative-path fixture");
    if (errorcode_t::success != ret || finished_wire.empty()) {
        return;
    }

    // Corrupt verify_data, not the enclosing record ciphertext, so the test
    // reaches Finished MAC verification rather than record-layer authentication.
    finished_wire.back() ^= 0x01;

    tls_handshake_finished incoming_finished(&reader);
    size_t pos = 0;
    ret = incoming_finished.read(from_server, finished_wire.data(), finished_wire.size(), pos);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject Server Finished with mismatched verify_data");
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "do not publish the pending ticket after Finished verification fails");
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket_pending).empty(), __FUNCTION__,
                      "discard pending ticket bytes when Finished verification fails");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending), __FUNCTION__, "clear pending ticket state after Finished verification failure");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending_lifetime), __FUNCTION__, "clear pending ticket lifetime after Finished verification failure");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending_timestamp), __FUNCTION__, "clear pending ticket timestamp after Finished verification failure");
    _test_case.assert(0 == (reader.get_session_status() & session_status_server_finished), __FUNCTION__,
                      "do not mark Server Finished successful after verify_data mismatch");

    size_t fatal_handshake_failure_count = test_count_fatal_alert(reader, from_server, tls_alertdesc_t::handshake_failure);
    _test_case.assert(1 == fatal_handshake_failure_count, __FUNCTION__, "queue exactly one fatal handshake_failure alert");

    // A subsequent TLS 1.2 ClientHello starts a fresh handshake and must
    // discard ticket material left pending by the failed Server Finished.
    tls_handshake_client_hello next_client_hello(&reader);
    ret = next_client_hello.add_ciphersuite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    _test_case.test(ret, __FUNCTION__, "configure a fresh TLS 1.2 ClientHello after failed Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    next_client_hello.get_extensions().add(tls_extension_type_t::encrypt_then_mac, from_client, &next_client_hello);
    binary_t next_client_hello_wire;
    ret = next_client_hello.write(from_client, next_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "write a fresh TLS 1.2 ClientHello after failed Server Finished");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(false == next_client_hello_wire.empty(), __FUNCTION__, "serialize the fresh ClientHello");
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket).empty(), __FUNCTION__, "keep the active ticket empty after starting a fresh handshake");
    _test_case.assert(reader_secrets.get(tls_secret_t::new_session_ticket_pending).empty(), __FUNCTION__,
                      "discard pending ticket bytes when the fresh ClientHello starts");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending), __FUNCTION__, "clear pending ticket state on the fresh ClientHello");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending_lifetime), __FUNCTION__, "clear pending ticket lifetime on the fresh ClientHello");
    _test_case.assert(0 == ticket_state.get(session_ticket_pending_timestamp), __FUNCTION__, "clear pending ticket timestamp on the fresh ClientHello");
}

static void test_tls12_abbreviated_finished_rejects_invalid_client_verify_data_without_ticket_activation() {
    // Action: send an invalid abbreviated Client Finished after the server staged a ticket renewal.
    // Scenario under test: TLS 1.2 abbreviated Client Finished verification failure.
    // Expected: discard the server's pending renewal without removing an older confirmed ticket.
    _test_case.begin("TLS 1.2 invalid abbreviated Client Finished does not activate a pending ticket");

    auto configure = [](tls_session& session) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_2);
        protection.set_cipher_suite(0xc02f);
        protection.get_secrets().assign(tls_secret_t::master, binary_t(48, 0x55));
        protection.reset_transcript_hash(&session);
        session.get_keyvalue().set(session_tls1_2_ticket_resumed, 1);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
        session.update_session_status(session_status_server_finished);
        session.get_session_info(from_client).begin_protection();
    };

    tls_session writer;
    tls_session reader;
    configure(writer);
    configure(reader);

    tls1_2_resumption_ticket active_ticket;
    active_ticket.identity = binary_t{0x01, 0x02};
    active_ticket.master_secret = binary_t(48, 0x55);
    active_ticket.version = static_cast<uint16>(tls1_2);
    active_ticket.cipher_suite = 0xc02f;
    reader.stage_tls1_2_resumption_ticket(active_ticket);
    bool active_ticket_confirmed = reader.confirm_tls1_2_resumption_ticket(active_ticket.identity);
    _test_case.assert(active_ticket_confirmed, __FUNCTION__, "retain an older confirmed ticket before the failed abbreviated handshake");

    tls1_2_resumption_ticket pending_ticket = active_ticket;
    pending_ticket.identity = binary_t{0x03, 0x04};
    reader.stage_tls1_2_resumption_ticket(pending_ticket);
    _test_case.assert(1 == reader.get_pending_tls1_2_resumption_tickets().size(), __FUNCTION__, "stage the replacement ticket until Client Finished authentication");

    tls_handshake_finished outgoing_finished(&writer);
    binary_t finished_wire;
    return_t ret = outgoing_finished.write(from_client, finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Client Finished for the abbreviated negative-path fixture");
    if (errorcode_t::success != ret || finished_wire.empty()) {
        return;
    }

    // Corrupt verify_data so the reader reaches Finished MAC verification.
    finished_wire.back() ^= 0x01;

    tls_handshake_finished incoming_finished(&reader);
    size_t pos = 0;
    ret = incoming_finished.read(from_client, finished_wire.data(), finished_wire.size(), pos);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject abbreviated Client Finished with mismatched verify_data");
    _test_case.assert(reader.get_pending_tls1_2_resumption_tickets().empty(), __FUNCTION__,
                      "discard the unconfirmed server renewal after Client Finished verification failure");

    tls1_2_resumption_ticket cached_ticket;
    bool active_ticket_found = reader.find_tls1_2_resumption_ticket(active_ticket.identity, cached_ticket);
    _test_case.assert(active_ticket_found, __FUNCTION__, "preserve the older confirmed server ticket after the failed renewal");
    tls1_2_resumption_ticket unconfirmed_ticket;
    bool pending_ticket_found = reader.find_tls1_2_resumption_ticket(pending_ticket.identity, unconfirmed_ticket);
    _test_case.assert(false == pending_ticket_found, __FUNCTION__, "keep the failed renewal unavailable for future resumption");
    _test_case.assert(0 == (reader.get_session_status() & session_status_client_finished), __FUNCTION__,
                      "do not mark Client Finished successful after verify_data mismatch");

    size_t fatal_handshake_failure_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::handshake_failure);
    _test_case.assert(1 == fatal_handshake_failure_count, __FUNCTION__, "queue exactly one fatal handshake_failure for invalid Client Finished");
}

void testcase_gpt_finished() {
    test_finished_calculation_propagates_invalid_algorithm();
    test_tls13_finished_postprocess_unsupported_local_cipher_suite_is_terminal();
    test_tls13_finished_requires_cipher_suite();
    test_finished_record_sequence_transition();
    test_tls13_finished_record_boundary();
    test_tls13_finished_application_epoch_integration();
    test_tls13_psk_finished_without_certificate_authentication();
    test_tls12_finished_record_sequence_integration();
    test_tls12_finished_rejects_invalid_verify_data_without_ticket_activation();
    test_tls12_abbreviated_finished_rejects_invalid_client_verify_data_without_ticket_activation();
}
