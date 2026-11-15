/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_finished.cpp
 * @author GPT
 * @desc
 */

#include "testcase_gpt_common.hpp"

static void test_finished_record_sequence_transition() {
    _test_case.begin("TLS Finished record sequence transition");

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_12);

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
        session.get_tls_protection().set_tls_version(tls_13);

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
    _test_case.begin("TLS 1.3 Finished record boundary");

    tls_session writer;
    writer.set_type(session_type_t::tls);
    writer.get_tls_protection().set_tls_version(tls_13);
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
    _test_case.begin("TLS 1.3 Finished application traffic epoch integration");

    auto configure = [](tls_session& session) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
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
        session.update_session_status(session_status_server_cert_verified);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::certificate_verify);
        session.get_session_info(from_server).begin_protection();
        session.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_client).begin_protection();
        session.set_recordno(from_server, 7);
        session.set_recordno(from_client, 9);
    };

    tls_session writer;
    tls_session reader;
    configure(writer);
    configure(reader);

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

static void test_tls12_finished_record_sequence_integration() {
    _test_case.begin("TLS 1.2 Finished record sequence integration");

    auto configure = [](tls_session& session) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_12);
        protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        protection.get_secrets().assign(tls_secret_t::master, binary_t(48, 0x55));
        protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
        protection.get_secrets().assign(tls_secret_t::client_iv, binary_t(4, 0x22));
        protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x33));
        protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x44));
        session.get_keyvalue().set(session_tls_version, tls_12);
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).begin_protection();
        session.set_recordno(from_client, 0);
        session.set_recordno(from_server, 0);
    };

    tls_session writer;
    tls_session reader;
    configure(writer);
    configure(reader);

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
    for (uint64 index = 0; index < 3; ++index) {
        const auto expected_client_sequence = 3 + index;
        const std::string client_message = "client application record " + std::to_string(index);
        tls_record_application_data client_record(&writer, client_message);
        binary_t client_wire;
        ret = client_record.write(from_client, client_wire);
        _test_case.test(ret, __FUNCTION__, "write consecutive TLS 1.2 Client Application Data");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(expected_client_sequence == writer.get_recordno(from_client), __FUNCTION__, "increment client write sequence for each Application Data record");

        tls_records client_records;
        ret = client_records.read(&reader, from_client, client_wire);
        _test_case.test(ret, __FUNCTION__, "read consecutive TLS 1.2 Client Application Data");
        if (errorcode_t::success != ret || 1 != client_records.size()) {
            _test_case.assert(false, __FUNCTION__, "decode consecutive TLS 1.2 Client Application Data");
            return;
        }
        auto decoded_client = (tls_record_application_data*)client_records.getat(0);
        binary_t expected_client(client_message.begin(), client_message.end());
        _test_case.assert(expected_client == decoded_client->get_binary(), __FUNCTION__, "authenticate each consecutive client record with its sequence");
        _test_case.assert(expected_client_sequence == reader.get_recordno(from_client), __FUNCTION__, "increment client read sequence for each Application Data record");

        const auto expected_server_sequence = 3 + index;
        const std::string server_message = "server application record " + std::to_string(index);
        tls_record_application_data server_record(&writer, server_message);
        binary_t server_wire;
        ret = server_record.write(from_server, server_wire);
        _test_case.test(ret, __FUNCTION__, "write consecutive TLS 1.2 Server Application Data");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(expected_server_sequence == writer.get_recordno(from_server), __FUNCTION__, "increment server write sequence for each Application Data record");

        tls_records server_records;
        ret = server_records.read(&reader, from_server, server_wire);
        _test_case.test(ret, __FUNCTION__, "read consecutive TLS 1.2 Server Application Data");
        if (errorcode_t::success != ret || 1 != server_records.size()) {
            _test_case.assert(false, __FUNCTION__, "decode consecutive TLS 1.2 Server Application Data");
            return;
        }
        auto decoded_server_record = (tls_record_application_data*)server_records.getat(0);
        binary_t expected_server(server_message.begin(), server_message.end());
        _test_case.assert(expected_server == decoded_server_record->get_binary(), __FUNCTION__, "authenticate each consecutive server record with its sequence");
        _test_case.assert(expected_server_sequence == reader.get_recordno(from_server), __FUNCTION__, "increment server read sequence for each Application Data record");

        _test_case.assert(expected_client_sequence == writer.get_recordno(from_client), __FUNCTION__, "server records do not alter client write sequence");
        _test_case.assert(expected_server_sequence == writer.get_recordno(from_server), __FUNCTION__, "client records do not alter server write sequence");
        _test_case.assert(expected_client_sequence == reader.get_recordno(from_client), __FUNCTION__, "server records do not alter client read sequence");
        _test_case.assert(expected_server_sequence == reader.get_recordno(from_server), __FUNCTION__, "client records do not alter server read sequence");
    }
}

void testcase_gpt_finished() {
    test_finished_record_sequence_transition();
    test_tls13_finished_record_boundary();
    test_tls13_finished_application_epoch_integration();
    test_tls12_finished_record_sequence_integration();
}
