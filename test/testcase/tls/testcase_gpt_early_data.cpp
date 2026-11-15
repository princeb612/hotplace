/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_early_data.cpp
 * @author GPT
 * @desc
 */

#include "testcase_gpt_common.hpp"

static void test_tls13_end_of_early_data_usage_reset() {
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

static void test_tls13_application_data_finished_direction_policy() {
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

static void test_tls13_early_data_and_compatibility_ccs() {
    _test_case.begin("TLS 1.3 early-data protection and compatibility CCS");

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
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
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().set_flow(tls_flow_t::zero_rtt);

        tls_handshake_client_hello client_hello(&session);
        client_hello.run_scheduled(from_client);
        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__,
                          "do not activate early-data protection without early_data extension");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().get_protection_context().add_supported_version(tls_13);
        session.update_session_status(session_status_client_hello);
        session.set_recordno(from_client, 4);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.test(ret, __FUNCTION__, "accept TLS 1.3 compatibility CCS before ServerHello");
        _test_case.assert(false == session.get_session_info(from_client).apply_protection(), __FUNCTION__, "ignore TLS 1.3 compatibility CCS before version negotiation");
        _test_case.assert(4 == session.get_recordno(from_client), __FUNCTION__, "do not reset TLS 1.3 record number for compatibility CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
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
        writer.get_tls_protection().set_tls_version(tls_13);
        writer.update_session_status(session_status_server_hello);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_server, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound server compatibility CCS when ServerHello is the retained phase");
        _test_case.assert(6 == wire.size(), __FUNCTION__, "serialize server compatibility CCS after ServerHello");

        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_13);
        reader.update_session_status(session_status_server_hello);
        binary_t inbound{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        ret = records.read(&reader, from_server, inbound);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept inbound server compatibility CCS when ServerHello is the retained phase");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_12);
        session.get_tls_protection().get_protection_context().add_supported_version(tls_13);
        session.get_keyvalue().set(session_tls_version, tls_12);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.test(ret, __FUNCTION__, "accept TLS 1.2 ChangeCipherSpec");
        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate TLS 1.2 protection on ChangeCipherSpec");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_12);
        reader.update_session_status(session_status_server_key_exchange);
        reader.update_session_status(session_status_client_key_exchange);
        reader.set_recordno(from_client, 17);
        binary_t inbound{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_client, inbound);
        _test_case.test(ret, __FUNCTION__, "read TLS 1.2 CCS and reset the inbound record sequence");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "reset the inbound TLS 1.2 record sequence after CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_12);
        writer.update_session_status(session_status_server_key_exchange);
        writer.update_session_status(session_status_client_key_exchange);
        writer.set_recordno(from_client, 19);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "write TLS 1.2 CCS and reset the outbound record sequence");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset the outbound TLS 1.2 record sequence after CCS");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_12);
        reader.get_keyvalue().set(session_tls_version, tls_12);
        reader.set_recordno(from_client, 41);
        binary_t early_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_client, early_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject inbound TLS 1.2 CCS before ClientKeyExchange");
        _test_case.assert(false == reader.get_session_info(from_client).apply_protection(), __FUNCTION__, "keep TLS 1.2 inbound protection inactive after premature CCS");
        _test_case.assert(41 == reader.get_recordno(from_client), __FUNCTION__, "preserve inbound sequence after premature TLS 1.2 CCS");
        size_t fatal_count = 0;
        reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for premature TLS 1.2 CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_12);
        writer.get_keyvalue().set(session_tls_version, tls_12);
        writer.set_recordno(from_client, 43);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound TLS 1.2 CCS before ClientKeyExchange");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for premature outbound TLS 1.2 CCS");
        _test_case.assert(43 == writer.get_recordno(from_client), __FUNCTION__, "preserve outbound sequence after premature TLS 1.2 CCS");
    }

    {
        tls_session reader;
        reader.set_type(session_type_t::tls);
        reader.get_tls_protection().set_tls_version(tls_12);
        reader.get_keyvalue().set(session_tls_version, tls_12);
        reader.update_session_status(session_status_server_key_exchange);
        reader.update_session_status(session_status_client_key_exchange);
        reader.set_recordno(from_server, 47);
        binary_t early_server_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&reader, from_server, early_server_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject server TLS 1.2 CCS before client Finished");
        _test_case.assert(false == reader.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "keep server-direction protection inactive before client Finished");
        _test_case.assert(47 == reader.get_recordno(from_server), __FUNCTION__, "preserve server-direction sequence after premature CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_12);
        writer.get_keyvalue().set(session_tls_version, tls_12);
        writer.update_session_status(session_status_server_key_exchange);
        writer.update_session_status(session_status_client_key_exchange);
        writer.set_recordno(from_server, 49);
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_server, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound server TLS 1.2 CCS before client Finished");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for premature outbound server TLS 1.2 CCS");
        _test_case.assert(49 == writer.get_recordno(from_server), __FUNCTION__, "preserve outbound server-direction sequence after premature CCS");
    }

    {
        auto reject_finished_tls12_ccs = [&](tls_direction_t dir, bool outbound, uint32 status, const char* message) -> void {
            tls_session session;
            session.set_type(session_type_t::tls);
            session.get_tls_protection().set_tls_version(tls_12);
            session.get_keyvalue().set(session_tls_version, tls_12);
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
            _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, message);
            if (outbound) {
                _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for CCS after sender Finished");
            }
            size_t fatal_count = 0;
            session.get_alert(dir, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                    ++fatal_count;
                }
            });
            _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for CCS after sender Finished");
        };

        const uint32 client_finished_phase = session_status_server_key_exchange | session_status_client_key_exchange | session_status_client_finished;
        const uint32 server_finished_phase = client_finished_phase | session_status_server_finished;
        reject_finished_tls12_ccs(from_client, false, client_finished_phase, "reject inbound client CCS after Client Finished");
        reject_finished_tls12_ccs(from_client, true, client_finished_phase, "reject outbound client CCS after Client Finished");
        reject_finished_tls12_ccs(from_server, false, server_finished_phase, "reject inbound server CCS after Server Finished");
        reject_finished_tls12_ccs(from_server, true, server_finished_phase, "reject outbound server CCS after Server Finished");
    }

    {
        auto configure_tls12 = [](tls_session& session, uint64 initial_recordno) -> void {
            auto& protection = session.get_tls_protection();
            protection.set_tls_version(tls_12);
            protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            const binary_t key(16, 0x11);
            const binary_t iv(4, 0x22);
            protection.get_secrets().assign(tls_secret_t::client_key, key);
            protection.get_secrets().assign(tls_secret_t::client_iv, iv);
            protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x33));
            protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x44));
            session.get_keyvalue().set(session_tls_version, tls_12);
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
        _test_case.test(ret, __FUNCTION__, "write TLS 1.2 CCS before protected records");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_records ccs_records;
        ret = ccs_records.read(&reader, from_client, ccs_wire);
        _test_case.test(ret, __FUNCTION__, "read TLS 1.2 CCS before protected records");
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(writer.get_session_info(from_client).apply_protection() && reader.get_session_info(from_client).apply_protection(), __FUNCTION__,
                          "activate TLS 1.2 protection on both peers");
        _test_case.assert((0 == writer.get_recordno(from_client)) && (0 == reader.get_recordno(from_client)), __FUNCTION__,
                          "reset independent TLS 1.2 record sequences at CCS");

        const char* messages[] = {"first protected record", "second protected record"};
        for (size_t i = 0; i < 2; ++i) {
            tls_record_application_data outgoing(&writer, messages[i]);
            binary_t protected_wire;
            ret = outgoing.write(from_client, protected_wire);
            _test_case.test(ret, __FUNCTION__, i ? "encrypt second TLS 1.2 protected record" : "encrypt first TLS 1.2 protected record");
            if (errorcode_t::success != ret) {
                return;
            }
            _test_case.assert(i + 1 == writer.get_recordno(from_client), __FUNCTION__, "advance outbound TLS 1.2 sequence after encryption");

            tls_records decoded_records;
            ret = decoded_records.read(&reader, from_client, protected_wire);
            _test_case.test(ret, __FUNCTION__, i ? "decrypt second TLS 1.2 protected record" : "decrypt first TLS 1.2 protected record");
            if (errorcode_t::success != ret || 1 != decoded_records.size()) {
                _test_case.assert(false, __FUNCTION__, "decoded TLS 1.2 application-data record is available");
                return;
            }

            auto decoded = (tls_record_application_data*)decoded_records.getat(0);
            std::string expected_text(messages[i]);
            binary_t expected(expected_text.begin(), expected_text.end());
            _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "recover authenticated TLS 1.2 application data");
            _test_case.assert(i + 1 == reader.get_recordno(from_client), __FUNCTION__, "advance inbound TLS 1.2 sequence after decryption");
        }

        // The server direction has an independent sequence and key pair.
        _test_case.assert((117 == writer.get_recordno(from_server)) && (129 == reader.get_recordno(from_server)), __FUNCTION__,
                          "keep TLS 1.2 server-direction sequence independent before CCS");

        writer.update_session_status(session_status_client_finished);
        reader.update_session_status(session_status_client_finished);
        writer.clear_session_status(session_status_server_finished);
        reader.clear_session_status(session_status_server_finished);

        tls_record_change_cipher_spec server_ccs(&writer);
        binary_t server_ccs_wire;
        ret = server_ccs.write(from_server, server_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write server-direction TLS 1.2 CCS");
        if (errorcode_t::success != ret) {
            return;
        }

        tls_records server_ccs_records;
        ret = server_ccs_records.read(&reader, from_server, server_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "read server-direction TLS 1.2 CCS");
        if (errorcode_t::success != ret) {
            return;
        }

        _test_case.assert(writer.get_session_info(from_server).apply_protection() && reader.get_session_info(from_server).apply_protection(), __FUNCTION__,
                          "activate server-direction TLS 1.2 protection");
        _test_case.assert((0 == writer.get_recordno(from_server)) && (0 == reader.get_recordno(from_server)), __FUNCTION__,
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
            _test_case.test(ret, __FUNCTION__, i ? "encrypt second server-direction TLS 1.2 record" : "encrypt first server-direction TLS 1.2 record");
            if (errorcode_t::success != ret) {
                return;
            }
            _test_case.assert(i + 1 == writer.get_recordno(from_server), __FUNCTION__, "advance outbound server-direction TLS 1.2 sequence");

            tls_records decoded_records;
            ret = decoded_records.read(&reader, from_server, protected_wire);
            _test_case.test(ret, __FUNCTION__, i ? "decrypt second server-direction TLS 1.2 record" : "decrypt first server-direction TLS 1.2 record");
            if (errorcode_t::success != ret || 1 != decoded_records.size()) {
                _test_case.assert(false, __FUNCTION__, "decoded server-direction TLS 1.2 application-data record is available");
                return;
            }

            auto decoded = (tls_record_application_data*)decoded_records.getat(0);
            std::string expected_text(server_messages[i]);
            binary_t expected(expected_text.begin(), expected_text.end());
            _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "recover authenticated server-direction TLS 1.2 application data");
            _test_case.assert(i + 1 == reader.get_recordno(from_server), __FUNCTION__, "advance inbound server-direction TLS 1.2 sequence");
        }
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_12);
        session.get_keyvalue().set(session_tls_version, tls_12);
        session.get_session_info(from_client).begin_protection();
        binary_t duplicate_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, duplicate_ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate plaintext TLS 1.2 ChangeCipherSpec");
        _test_case.assert(session.get_session_info(from_client).apply_protection(), __FUNCTION__, "retain active TLS 1.2 protection after duplicate CCS rejection");
        size_t fatal_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for duplicate TLS 1.2 CCS");

        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_12);
        writer.get_keyvalue().set(session_tls_version, tls_12);
        writer.get_session_info(from_client).begin_protection();
        tls_record_change_cipher_spec outgoing(&writer);
        binary_t wire;
        ret = outgoing.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject duplicate outbound TLS 1.2 ChangeCipherSpec");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for duplicate outbound TLS 1.2 CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.get_tls_protection().get_protection_context().add_supported_version(tls_13);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject TLS 1.3 compatibility CCS before the first ClientHello");
        size_t fatal_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for pre-ClientHello CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_server_finished);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_server, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject TLS 1.3 compatibility CCS after the peer Finished");
        size_t fatal_count = 0;
        session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for post-Finished CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_client_finished);
        binary_t ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_records records;
        return_t ret = records.read(&session, from_client, ccs);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject inbound TLS 1.3 compatibility CCS after the client peer Finished");
        size_t fatal_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for inbound client post-Finished CCS");
    }

    {
        tls_session writer;
        writer.set_type(session_type_t::tls);
        writer.get_tls_protection().set_tls_version(tls_13);
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
        writer.get_tls_protection().set_tls_version(tls_13);
        tls_record_change_cipher_spec ccs(&writer);
        binary_t wire;
        return_t ret = ccs.write(from_client, wire);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "reject outbound TLS 1.3 compatibility CCS before the first ClientHello");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no bytes for outbound pre-ClientHello CCS");
    }

    {
        tls_session session;
        session.set_type(session_type_t::tls);
        session.get_tls_protection().set_tls_version(tls_13);
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
        writer.get_tls_protection().set_tls_version(tls_13);
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
        session.get_tls_protection().set_tls_version(tls_13);
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
            session.get_tls_protection().set_tls_version(tls_13);
            session.get_tls_protection().get_protection_context().add_supported_version(tls_13);
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
        size_t fatal_count = 0;
        reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++fatal_count;
            }
        });
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue fatal unexpected_message for protected TLS 1.3 CCS");
    }

    {
        const std::array<binary_t, 3> malformed_ccs = {
            binary_t{0x14, 0x03, 0x03, 0x00, 0x00},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01},
            binary_t{0x14, 0x03, 0x03, 0x00, 0x01, 0x00},
        };
        for (const auto& ccs : malformed_ccs) {
            tls_session session;
            session.set_type(session_type_t::tls);
            session.get_tls_protection().set_tls_version(tls_12);
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

void testcase_gpt_early_data() {
    test_tls13_end_of_early_data_usage_reset();
    test_tls13_end_of_early_data_requires_server_finished();
    test_tls13_application_data_finished_direction_policy();
    test_tls13_handshake_protection_transition();
    test_tls13_early_data_and_compatibility_ccs();
}
