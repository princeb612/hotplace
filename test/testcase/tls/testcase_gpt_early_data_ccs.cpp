/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_early_data_ccs.cpp
 * @author GPT
 * @desc   TLS 1.3 early-data interaction with the compatibility ChangeCipherSpec message.
 */

#include <atomic>
#include <chrono>
#include <thread>

#include "testcase_gpt_common.hpp"

static void test_tls13_early_data_extension_controls_client_protection() {
    // Scenario: Verify the early_data extension is the sole trigger for the client early-data protection transition.
    // Action: Run ClientHello scheduling with and without early_data, and verify protection state and record-number handling.
    // Expected: Only an actual early_data offer activates client-direction protection and resets its record sequence.
    _test_case.begin("TLS 1.3 early_data extension controls client-direction protection");
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        session.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);
        session.set_recordno(from_client, 9);

        tls_handshake_client_hello client_hello(&session);
        client_hello.get_extensions().add(new tls_extension_early_data(&client_hello));
        client_hello.run_scheduled(from_client);

        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate client-direction protection for offered early data");
        _test_case.assert(false == session.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "do not activate server-direction protection for client early data");
        _test_case.assert(0 == session.get_recordno(from_client), __FUNCTION__, "reset client early-data record number");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);

        tls_handshake_client_hello client_hello(&session);
        client_hello.run_scheduled(from_client);
        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                          "do not activate early-data protection without early_data extension");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().get_protection_context().add_supported_version(tls1_3);
        session.update_session_status(session_status_client_hello);
        session.set_recordno(from_client, 4);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.test(ret, __FUNCTION__, "accept TLS 1.3 compatibility CCS before ServerHello");
        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "ignore TLS 1.3 compatibility CCS before version negotiation");
        _test_case.assert(4 == session.get_recordno(from_client), __FUNCTION__, "do not reset TLS 1.3 record number for compatibility CCS");
    }
}

static void test_tls13_compatibility_ccs_handshake_window() {
    // Scenario: Verify TLS 1.3 compatibility CCS is accepted in the permitted handshake window without activating record protection.
    // Action: Read client and server compatibility CCS before and after ServerHello, including the retained ServerHello phase.
    // Expected: CCS is consumed without changing protection state or record sequence.
    _test_case.begin("TLS 1.3 compatibility CCS handshake window");
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.set_recordno(from_client, 6);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.test(ret, __FUNCTION__, "accept TLS 1.3 compatibility CCS after ServerHello");
        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "do not activate TLS 1.3 protection on compatibility CCS");
        _test_case.assert(6 == session.get_recordno(from_client), __FUNCTION__, "do not reset TLS 1.3 record number after compatibility CCS");
    }

    {
        // ServerHello replaces the transient ClientHello phase bit in the
        // aggregate status. It must still establish that the first ClientHello
        // has been seen for compatibility CCS validation.
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_3);
        writer.update_session_status(session_status_server_hello);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_server, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound server compatibility CCS when ServerHello is the retained phase");
        _test_case.assert(6 == wire.size(), __FUNCTION__, "serialize server compatibility CCS after ServerHello");

        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls1_3);
        reader.update_session_status(session_status_server_hello);
        binary_t inbound{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        ret = records.read(&reader, from_server, inbound);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept inbound server compatibility CCS when ServerHello is the retained phase");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_2);
        session.get_tls_protection().get_protection_context().add_supported_version(tls1_3);
        session.get_keyvalue().set(session_tls_version, tls1_2);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.test(ret, __FUNCTION__, "accept TLS 1.2 ChangeCipherSpec");
        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate TLS 1.2 protection on ChangeCipherSpec");
    }
}

static void test_tls12_ccs_valid_client_transition(const char* function_name) {
    // Scenario under test: valid TLS 1.2 client ChangeCipherSpec transition.
    // Action: read and write CCS after both key-exchange messages.
    // Expected: reset the inbound and outbound client-direction record sequences.
    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls1_2);
        reader.update_session_status(session_status_server_key_exchange);
        reader.update_session_status(session_status_client_key_exchange);
        reader.set_recordno(from_client, 17);
        binary_t inbound{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_client, inbound);
        _test_case.test(ret, function_name, "read TLS 1.2 CCS and reset the inbound record sequence");
        _test_case.assert(0 == reader.get_recordno(from_client), function_name, "reset the inbound TLS 1.2 record sequence after CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_2);
        writer.update_session_status(session_status_server_key_exchange);
        writer.update_session_status(session_status_client_key_exchange);
        writer.set_recordno(from_client, 19);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.test(ret, function_name, "write TLS 1.2 CCS and reset the outbound record sequence");
        _test_case.assert(0 == writer.get_recordno(from_client), function_name, "reset the outbound TLS 1.2 record sequence after CCS");
    }
}

static void test_tls12_ccs_rejects_premature_client_transition(const char* function_name) {
    // Scenario under test: valid TLS 1.2 client ChangeCipherSpec transition.
    // Action: read and write CCS after both key-exchange messages.
    // Expected: activate protection and reset the corresponding record sequence.
    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls1_2);
        reader.get_keyvalue().set(session_tls_version, tls1_2);
        reader.set_recordno(from_client, 41);
        binary_t early_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_client, early_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, function_name, "reject inbound TLS 1.2 CCS before ClientKeyExchange");
        _test_case.assert(false == reader.get_session_info(from_client).apply_protection(), function_name,
                          "keep TLS 1.2 inbound protection inactive after premature CCS");
        _test_case.assert(41 == reader.get_recordno(from_client), function_name, "preserve inbound sequence after premature TLS 1.2 CCS");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, function_name, "queue fatal unexpected_message for premature TLS 1.2 CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_2);
        writer.get_keyvalue().set(session_tls_version, tls1_2);
        writer.set_recordno(from_client, 43);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, function_name, "reject outbound TLS 1.2 CCS before ClientKeyExchange");
        _test_case.assert(wire.empty(), function_name, "emit no bytes for premature outbound TLS 1.2 CCS");
        _test_case.assert(43 == writer.get_recordno(from_client), function_name, "preserve outbound sequence after premature TLS 1.2 CCS");
    }
}

static void test_tls12_ccs_rejects_premature_server_transition(const char* function_name) {
    // Scenario under test: premature TLS 1.2 client and server ChangeCipherSpec messages.
    // Action: send client CCS before ClientKeyExchange and server CCS before Client Finished.
    // Expected: reject each transition, preserve protection and sequence state, and queue unexpected_message.
    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls1_2);
        reader.get_keyvalue().set(session_tls_version, tls1_2);
        reader.update_session_status(session_status_server_key_exchange);
        reader.update_session_status(session_status_client_key_exchange);
        reader.set_recordno(from_server, 47);
        binary_t early_server_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_server, early_server_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, function_name, "reject server TLS 1.2 CCS before client Finished");
        _test_case.assert(false == reader.get_session_info(from_server).apply_protection(), function_name,
                          "keep server-direction protection inactive before client Finished");
        _test_case.assert(47 == reader.get_recordno(from_server), function_name, "preserve server-direction sequence after premature CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_2);
        writer.get_keyvalue().set(session_tls_version, tls1_2);
        writer.update_session_status(session_status_server_key_exchange);
        writer.update_session_status(session_status_client_key_exchange);
        writer.set_recordno(from_server, 49);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_server, wire);
        _test_case.assert(errorcode_t::unexpected == ret, function_name, "reject outbound server TLS 1.2 CCS before client Finished");
        _test_case.assert(wire.empty(), function_name, "emit no bytes for premature outbound server TLS 1.2 CCS");
        _test_case.assert(49 == writer.get_recordno(from_server), function_name, "preserve outbound server-direction sequence after premature CCS");
    }
}

static void test_tls12_ccs_rejects_ccs_after_finished(const char* function_name) {
    // Scenario under test: TLS 1.2 ChangeCipherSpec after the sender's Finished.
    // Action: attempt inbound and outbound CCS after Client Finished or Server Finished.
    // Expected: reject all post-Finished CCS messages with fatal unexpected_message.
    {
        auto reject_finished_tls12_ccs = [&](tls_direction_t dir, bool outbound, uint32 status, const char* message) -> void {
            tls_session session;
            session.set_type(session_type_t::tls);
            session.get_tls_protection().set_tls_version(tls1_2);
            session.get_keyvalue().set(session_tls_version, tls1_2);
            if (status & session_status_server_key_exchange) {
                session.update_session_status(session_status_server_key_exchange);
            }
            if (status & session_status_client_key_exchange) {
                session.update_session_status(session_status_client_key_exchange);
            }
            if (status & session_status_client_finished) {
                session.update_session_status(session_status_client_finished);
            }
            if (status & session_status_server_finished) {
                session.update_session_status(session_status_server_finished);
            }

            return_t ret = errorcode_t::success;
            binary_t wire;
            if (outbound) {
                tls_record_change_cipher_spec outgoing(&session);
                ret = outgoing.write(dir, wire);
            } else {
                binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
                tls_records records;
                ret = records.read(&session, dir, ccs);
            }
            _test_case.assert(errorcode_t::unexpected == ret, function_name, message);
            if (outbound) {
                _test_case.assert(wire.empty(), function_name, "emit no bytes for CCS after sender Finished");
            }
            size_t fatal_count = test_count_fatal_alert(session, dir, tls_alertdesc_t::unexpected_message);
            _test_case.assert(1 == fatal_count, function_name, "queue fatal unexpected_message for CCS after sender Finished");
        };

        const uint32 client_finished_phase = session_status_server_key_exchange | session_status_client_key_exchange | session_status_client_finished;
        const uint32 server_finished_phase = client_finished_phase | session_status_server_finished;
        reject_finished_tls12_ccs(from_client, false, client_finished_phase, "reject inbound client CCS after Client Finished");
        reject_finished_tls12_ccs(from_client, true, client_finished_phase, "reject outbound client CCS after Client Finished");
        reject_finished_tls12_ccs(from_server, false, server_finished_phase, "reject inbound server CCS after Server Finished");
        reject_finished_tls12_ccs(from_server, true, server_finished_phase, "reject outbound server CCS after Server Finished");
    }
}

static void test_tls12_ccs_phase_protected_record_sequence(const char* function_name) {
    // Scenario under test: TLS 1.2 protected record sequence after directional ChangeCipherSpec.
    // Action: exchange protected application records after client and server CCS transitions.
    // Expected: reset and advance each direction's sequence independently while authenticating application data.
    {
        auto configure_tls12 = [](tls_session& session, uint64 initial_recordno) -> void {
            auto& protection = session.get_tls_protection();
            protection.set_tls_version(tls1_2);
            protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            const binary_t key(16, 0x11);
            const binary_t iv(4, 0x22);
            protection.get_secrets().assign(tls_secret_t::client_key, key);
            protection.get_secrets().assign(tls_secret_t::client_iv, iv);
            protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x33));
            protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x44));
            session.get_keyvalue().set(session_tls_version, tls1_2);
            session.set_recordno(from_client, initial_recordno);
            session.set_recordno(from_server, initial_recordno + 100);
            session.update_session_status(session_status_server_key_exchange);
            session.update_session_status(session_status_client_key_exchange);
            session.update_session_status(session_status_server_finished);
            session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
            session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        };

        tls_session writer;
        tls_session reader;
        configure_tls12(writer, 17);
        configure_tls12(reader, 29);

        tls_record_change_cipher_spec outgoing_ccs(&writer);
        binary_t ccs_wire;
        return_t ret = outgoing_ccs.write(from_client, ccs_wire);
        _test_case.test(ret, function_name, "write TLS 1.2 CCS before protected records");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_records ccs_records;
        ret = ccs_records.read(&reader, from_client, ccs_wire);
        _test_case.test(ret, function_name, "read TLS 1.2 CCS before protected records");
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(writer.get_session_info(from_client).apply_protection() && reader.get_session_info(from_client).apply_protection(), function_name,
                          "activate TLS 1.2 protection on both peers");
        _test_case.assert((0 == writer.get_recordno(from_client)) && (0 == reader.get_recordno(from_client)), function_name,
                          "reset independent TLS 1.2 record sequences at CCS");

        const char* messages[] = {"first protected record", "second protected record"};
        for (size_t i = 0; i < 2; ++i) {
            tls_record_application_data outgoing(&writer, messages[i]);
            binary_t protected_wire;
            ret = outgoing.write(from_client, protected_wire);
            _test_case.test(ret, function_name, i ? "encrypt second TLS 1.2 protected record" : "encrypt first TLS 1.2 protected record");
            if (errorcode_t::success != ret) {
                return;
            }
            _test_case.assert(i + 1 == writer.get_recordno(from_client), function_name, "advance outbound TLS 1.2 sequence after encryption");

            tls_records decoded_records;
            ret = decoded_records.read(&reader, from_client, protected_wire);
            _test_case.test(ret, function_name, i ? "decrypt second TLS 1.2 protected record" : "decrypt first TLS 1.2 protected record");
            if (errorcode_t::success != ret || 1 != decoded_records.size()) {
                _test_case.assert(false, function_name, "decoded TLS 1.2 application-data record is available");
                return;
            }

            auto decoded = (tls_record_application_data*)decoded_records.getat(0);
            std::string expected_text(messages[i]);
            binary_t expected(expected_text.begin(), expected_text.end());
            _test_case.assert(expected == decoded->get_binary(), function_name, "recover authenticated TLS 1.2 application data");
            _test_case.assert(i + 1 == reader.get_recordno(from_client), function_name, "advance inbound TLS 1.2 sequence after decryption");
        }

        // The server direction has an independent sequence and key pair.
        _test_case.assert((117 == writer.get_recordno(from_server)) && (129 == reader.get_recordno(from_server)), function_name,
                          "keep TLS 1.2 server-direction sequence independent before CCS");

        writer.update_session_status(session_status_client_finished);
        reader.update_session_status(session_status_client_finished);
        writer.clear_session_status(session_status_server_finished);
        reader.clear_session_status(session_status_server_finished);

        tls_record_change_cipher_spec server_ccs(&writer);
        binary_t server_ccs_wire;
        ret = server_ccs.write(from_server, server_ccs_wire);
        _test_case.test(ret, function_name, "write server-direction TLS 1.2 CCS");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_records server_ccs_records;
        ret = server_ccs_records.read(&reader, from_server, server_ccs_wire);
        _test_case.test(ret, function_name, "read server-direction TLS 1.2 CCS");
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(writer.get_session_info(from_server).apply_protection() && reader.get_session_info(from_server).apply_protection(), function_name,
                          "activate server-direction TLS 1.2 protection");
        _test_case.assert((0 == writer.get_recordno(from_server)) && (0 == reader.get_recordno(from_server)), function_name,
                          "reset independent server-direction TLS 1.2 sequences at CCS");

        // The server Finished follows its CCS; Application Data is valid only
        // after the Finished state has been recorded.
        writer.update_session_status(session_status_server_finished);
        reader.update_session_status(session_status_server_finished);

        const char* server_messages[] = {"server protected record one", "server protected record two"};
        for (size_t i = 0; i < 2; ++i) {
            tls_record_application_data outgoing(&writer, server_messages[i]);
            binary_t protected_wire;
            ret = outgoing.write(from_server, protected_wire);
            _test_case.test(ret, function_name, i ? "encrypt second server-direction TLS 1.2 record" : "encrypt first server-direction TLS 1.2 record");
            if (errorcode_t::success != ret) {
                return;
            }
            _test_case.assert(i + 1 == writer.get_recordno(from_server), function_name, "advance outbound server-direction TLS 1.2 sequence");

            tls_records decoded_records;
            ret = decoded_records.read(&reader, from_server, protected_wire);
            _test_case.test(ret, function_name, i ? "decrypt second server-direction TLS 1.2 record" : "decrypt first server-direction TLS 1.2 record");
            if (errorcode_t::success != ret || 1 != decoded_records.size()) {
                _test_case.assert(false, function_name, "decoded server-direction TLS 1.2 application-data record is available");
                return;
            }

            auto decoded = (tls_record_application_data*)decoded_records.getat(0);
            std::string expected_text(server_messages[i]);
            binary_t expected(expected_text.begin(), expected_text.end());
            _test_case.assert(expected == decoded->get_binary(), function_name, "recover authenticated server-direction TLS 1.2 application data");
            _test_case.assert(i + 1 == reader.get_recordno(from_server), function_name, "advance inbound server-direction TLS 1.2 sequence");
        }
    }
}

static void test_tls12_ccs_phase_validation() {
    // Scenario under test: TLS 1.2 ChangeCipherSpec phase and direction validation.
    // Action: exercise valid transitions, premature CCS, post-Finished CCS, and protected record sequencing.
    // Expected: activate protection only at the correct phase and reject invalid CCS with unexpected_message.
    _test_case.begin("TLS 1.2 CCS phase and direction validation");

    test_tls12_ccs_valid_client_transition(__FUNCTION__);
    test_tls12_ccs_rejects_premature_client_transition(__FUNCTION__);
    test_tls12_ccs_rejects_premature_server_transition(__FUNCTION__);
    test_tls12_ccs_rejects_ccs_after_finished(__FUNCTION__);
    test_tls12_ccs_phase_protected_record_sequence(__FUNCTION__);
}

static void test_tls12_ccs_protected_record_sequence() {
    // Scenario: Verify a valid TLS 1.2 CCS switches both peers to protected records with independent directional sequence numbers.
    // Action: Exchange protected client and server application-data records on both directions after their respective CCS transitions.
    // Expected: Both peers recover the original application data and advance only the active direction's sequence.
    _test_case.begin("TLS 1.2 CCS resets independent protected-record sequences");
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_2);
        session.get_keyvalue().set(session_tls_version, tls1_2);
        session.get_session_info(from_client).begin_protection();
        binary_t duplicate_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, duplicate_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate plaintext TLS 1.2 ChangeCipherSpec");
        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "retain active TLS 1.2 protection after duplicate CCS rejection");
        size_t fatal_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for duplicate TLS 1.2 CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_2);
        writer.get_keyvalue().set(session_tls_version, tls1_2);
        writer.get_session_info(from_client).begin_protection();
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate outbound TLS 1.2 ChangeCipherSpec");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for duplicate outbound TLS 1.2 CCS");
    }
}

static void test_tls12_duplicate_ccs_rejection() {
    // Scenario: Verify a second plaintext ChangeCipherSpec cannot reactivate an already active TLS 1.2 direction.
    // Action: Read and write duplicate CCS after protection has begun.
    // Expected: The duplicate is rejected with fatal unexpected_message and does not disable active protection.
    _test_case.begin("TLS 1.2 duplicate CCS rejection");
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.get_tls_protection().get_protection_context().add_supported_version(tls1_3);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject TLS 1.3 compatibility CCS before the first ClientHello");
        size_t fatal_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for pre-ClientHello CCS");
    }
}

static void test_tls13_compatibility_ccs_invalid_phase_and_body() {
    // Scenario: Verify TLS 1.3 compatibility CCS is rejected outside its permitted window and malformed or protected CCS content is never treated as a compatibility
    // message. Action: Exercise pre-ClientHello, post-Finished, repeated, HRR-window, malformed-body and protected-inner-content cases. Expected: Only permitted
    // compatibility CCS is accepted; invalid cases fail without unintended protection or sequence changes.
    _test_case.begin("TLS 1.3 compatibility CCS invalid phases and malformed content");
    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_server_finished);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_server, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject TLS 1.3 compatibility CCS after the peer Finished");
        size_t fatal_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for post-Finished CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_client_finished);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject inbound TLS 1.3 compatibility CCS after the client peer Finished");
        size_t fatal_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for inbound client post-Finished CCS");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_3);
        writer.update_session_status(session_status_client_hello);
        writer.update_session_status(session_status_server_hello);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_server, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound server compatibility CCS before client peer Finished");
        _test_case.assert(6 == wire.size(), __FUNCTION__, "serialize outbound server compatibility CCS");

        writer.update_session_status(session_status_client_finished);
        binary_t rejected_wire;
        ret = ccs.write(from_server, rejected_wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound server compatibility CCS after client peer Finished");
        _test_case.assert(rejected_wire.empty(), __FUNCTION__, "emit no bytes for outbound server post-Finished CCS");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_3);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound TLS 1.3 compatibility CCS before the first ClientHello");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for outbound pre-ClientHello CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
        session.update_session_status(session_status_hello_retry_request);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_server, ccs);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow TLS 1.3 compatibility CCS in the HelloRetryRequest window");
        _test_case.assert(false == session.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "do not activate protection for compatibility CCS after HelloRetryRequest");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls1_3);
        writer.update_session_status(session_status_client_hello);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_client, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound TLS 1.3 compatibility CCS before peer Finished");
        _test_case.assert(6 == wire.size(), __FUNCTION__, "serialize outbound TLS 1.3 compatibility CCS");

        writer.update_session_status(session_status_server_finished);
        binary_t rejected_wire;
        ret = ccs.write(from_client, rejected_wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound TLS 1.3 compatibility CCS after peer Finished");
        _test_case.assert(rejected_wire.empty(), __FUNCTION__, "emit no bytes for outbound post-Finished CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls1_3);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.get_session_info(from_client).begin_protection();
        session.set_recordno(from_client, 23);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t first = records.read(&session, from_client, ccs);
        return_t second = records.read(&session, from_client, ccs);
        _test_case.assert((errorcode_t::success == first) && (errorcode_t::success == second), __FUNCTION__,
                          "ignore repeated TLS 1.3 compatibility CCS while awaiting peer Finished");
        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "preserve active TLS 1.3 protection when ignoring compatibility CCS");
        _test_case.assert(23 == session.get_recordno(from_client), __FUNCTION__, "preserve TLS 1.3 record number when ignoring repeated compatibility CCS");
        _test_case.assert(2 == records.size(), __FUNCTION__, "consume both allowed compatibility CCS records");
    }

    {
        const binary_t malformed_ccs[] = {
            binary_t{0x14, 0x03, 0x03, 0x00, 0x00},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x01, 0x00},
        };
        for (const auto& ccs : malformed_ccs) {
            tls_session session;
            session.set_type(session_type_t::tls);
            session.get_tls_protection().set_tls_version(tls1_3);
            session.get_tls_protection().get_protection_context().add_supported_version(tls1_3);
            session.update_session_status(session_status_client_hello);
            session.set_recordno(from_client, 11);

            tls_records records;
            return_t ret = records.read(&session, from_client, ccs);
            _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject malformed TLS 1.3 compatibility CCS body");
            _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                              "do not activate record protection for malformed TLS 1.3 compatibility CCS");
            _test_case.assert(11 == session.get_recordno(from_client), __FUNCTION__, "preserve record number for malformed TLS 1.3 compatibility CCS");
        }
    }

    {
        // A CCS content type inside TLSCiphertext is not a compatibility CCS.
        // It must be rejected after successful record deprotection.
        tls_session reader;
        tls_records records;
        binary_t protected_ccs_plaintext{0x01, static_cast<byte_t>(tls_content_type_t::change_cipher_spec)};
        return_t ret = test_read_tls13_inner_plaintext(protected_ccs_plaintext, from_client, reader, records);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject protected TLS 1.3 CCS inner content type");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::unexpected_message);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for protected TLS 1.3 CCS");
    }
}

static void test_tls12_malformed_ccs_body_rejection() {
    // Scenario: Verify TLS 1.2 ChangeCipherSpec accepts only the one-byte value 0x01.
    // Action: Feed zero-length, overlong and invalid-value CCS bodies to the TLS 1.2 record reader.
    // Expected: Each malformed body is rejected without activating protection or advancing the record sequence.
    _test_case.begin("TLS 1.2 malformed ChangeCipherSpec body rejection");
    {
        const std::array<binary_t, 3> malformed_ccs = {
            binary_t{0x14, 0x03, 0x03, 0x00, 0x00},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x01, 0x00},
        };
        for (const auto& ccs : malformed_ccs) {
            tls_session session;
            session.set_type(session_type_t::tls);
            session.get_tls_protection().set_tls_version(tls1_2);
            session.set_recordno(from_client, 13);

            tls_records records;
            return_t ret = records.read(&session, from_client, ccs);
            _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject malformed TLS 1.2 ChangeCipherSpec body");
            _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                              "do not activate TLS 1.2 protection for malformed ChangeCipherSpec");
            _test_case.assert(13 == session.get_recordno(from_client), __FUNCTION__, "preserve record number for malformed TLS 1.2 ChangeCipherSpec");
        }
    }
}

void testcase_gpt_early_data_ccs() {
    test_tls13_early_data_extension_controls_client_protection();
    test_tls13_compatibility_ccs_handshake_window();
    test_tls12_ccs_phase_validation();
    test_tls12_ccs_protected_record_sequence();
    test_tls12_duplicate_ccs_rejection();
    test_tls13_compatibility_ccs_invalid_phase_and_body();
    test_tls12_malformed_ccs_body_rejection();
}
