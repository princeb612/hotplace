/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_early_data.cpp
 * @author GPT
 * @desc
 */

#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/encoding/base64.hpp>

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
}

static void test_tls13_client_requires_psk_for_early_data_offer() {
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
    tls_handshake_client_hello malformed_client_hello(&session);
    size_t malformed_pos = 0;
    ret = malformed_client_hello.get_extensions().read(&malformed_client_hello, from_client, malformed_early_data_extension.data(), malformed_early_data_extension.size(),
                                                       malformed_pos);
    _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject a non-empty ClientHello early_data body with a severe format error");

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
    rejected_session.get_session_info(from_server).get_keyvalue().set(session_early_data_offered, 1);
    binary_t rejected_ee{0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
    tls_handshake_encrypted_extensions rejected_extensions(&rejected_session);
    size_t rejected_pos = 0;
    return_t rejected_ret = rejected_extensions.read(from_server, rejected_ee.data(), rejected_ee.size(), rejected_pos);
    _test_case.test(rejected_ret, __FUNCTION__, "read EncryptedExtensions that declines early data");
    _test_case.assert(tls_flow_t::one_rtt == rejected_protection.get_flow(), __FUNCTION__, "switch to handshake traffic keys after early-data rejection");
    _test_case.assert(0 == rejected_session.get_recordno(from_client, false), __FUNCTION__, "reset the client record sequence for handshake keys");
    tls_record_application_data rejected_application_data(&rejected_session);
    rejected_application_data.set_binary(binary_t{0x01, 0x02});
    binary_t rejected_application_wire;
    return_t rejected_write_ret = rejected_application_data.write(from_client, rejected_application_wire);
    _test_case.assert(errorcode_t::bad_request == rejected_write_ret, __FUNCTION__,
                      "do not silently drop application data before the client's Finished after 0-RTT rejection");
    _test_case.assert(rejected_application_wire.empty(), __FUNCTION__, "do not emit rejected early data as 1-RTT application data");
}

static void test_tls13_client_sends_bounded_early_data() {
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

static void test_tls13_server_defers_inflight_early_data_until_encrypted_extensions() {
    _test_case.begin("TLS 1.3 server defers in-flight early data until EncryptedExtensions decides acceptance");

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls_13);
    client_protection.set_cipher_suite(0x1301);
    client_protection.set_flow(tls_flow_t::zero_rtt);
    client_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    client_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    client.update_session_status(session_status_client_hello);
    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    client.get_session_info(from_client).begin_protection();
    auto& client_early_state = client.get_session_info(from_server).get_keyvalue();
    client_early_state.set(session_early_data_offered, 1);
    client_early_state.set(session_early_data_limit, 4);
    client_early_state.set(session_early_data_sent, 0);

    tls_record_application_data client_early_record(&client);
    client_early_record.set_binary(binary_t{0x31, 0x32, 0x33});
    binary_t early_record_wire;
    return_t ret = client_early_record.write(from_client, early_record_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a valid protected 0-RTT record for the server");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session coalesced_client;
    coalesced_client.set_type(session_type_t::tls);
    auto& coalesced_client_protection = coalesced_client.get_tls_protection();
    coalesced_client_protection.set_tls_version(tls_13);
    coalesced_client_protection.set_cipher_suite(0x1301);
    // Generate an ordinary valid ClientHello, then add early_data to its
    // serialized extension vector below. The fixture has no PSK ticket, so
    // its composer flow must remain one_rtt.
    coalesced_client_protection.set_flow(tls_flow_t::one_rtt);
    binary_t coalesced_client_hello_wire;
    ret = test_client_supportedversion_clienthello(&coalesced_client, tls_13, tls_13, coalesced_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a baseline TLS 1.3 ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Add psk_key_exchange_modes, early_data, and a structurally valid
    // pre_shared_key extension. RFC 8446 requires the modes extension when PSK
    // is offered and pre_shared_key to be the final ClientHello extension.
    if (coalesced_client_hello_wire.size() < 9 || coalesced_client_hello_wire[0] != 0x16 || coalesced_client_hello_wire[5] != 0x01) {
        _test_case.assert(false, __FUNCTION__, "baseline ClientHello has TLS record and handshake framing");
        return;
    }
    size_t coalesced_handshake_end = 9 + test_read_u24(coalesced_client_hello_wire, 6);
    size_t coalesced_pos = 9 + 2 + 32;
    uint8 coalesced_session_id_len = coalesced_client_hello_wire[coalesced_pos++];
    coalesced_pos += coalesced_session_id_len;
    uint16 coalesced_cipher_suites_len = test_read_u16(coalesced_client_hello_wire, coalesced_pos);
    coalesced_pos += 2 + coalesced_cipher_suites_len;
    uint8 coalesced_compression_len = coalesced_client_hello_wire[coalesced_pos++];
    coalesced_pos += coalesced_compression_len;
    size_t coalesced_extensions_len_pos = coalesced_pos;
    uint16 coalesced_extensions_len = test_read_u16(coalesced_client_hello_wire, coalesced_extensions_len_pos);
    size_t coalesced_extensions_end = coalesced_extensions_len_pos + 2 + coalesced_extensions_len;
    if (coalesced_extensions_end != coalesced_handshake_end || coalesced_handshake_end != coalesced_client_hello_wire.size()) {
        _test_case.assert(false, __FUNCTION__, "baseline ClientHello extension vector is well framed");
        return;
    }
    // early_data (empty), then pre_shared_key with one identity and one
    // 32-byte binder. The binder is only structurally parsed in this test.
    binary_t coalesced_early_data_and_psk = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x29, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x01, 0x01, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x21, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // The composer may already include psk_key_exchange_modes. Keep the
    // synthesized ClientHello unique so this test reaches the pending-record
    // limit path rather than the independent duplicate-extension rejection.
    bool has_psk_key_exchange_modes = false;
    size_t existing_extension_pos = coalesced_extensions_len_pos + 2;
    while (existing_extension_pos + 4 <= coalesced_extensions_end) {
        uint16 extension_type = test_read_u16(coalesced_client_hello_wire, existing_extension_pos);
        uint16 extension_size = test_read_u16(coalesced_client_hello_wire, existing_extension_pos + 2);
        if (0x002d == extension_type) {
            has_psk_key_exchange_modes = true;
            break;
        }
        existing_extension_pos += 4 + extension_size;
    }
    if (has_psk_key_exchange_modes) {
        coalesced_early_data_and_psk.erase(coalesced_early_data_and_psk.begin(), coalesced_early_data_and_psk.begin() + 6);
    }
    coalesced_client_hello_wire.insert(coalesced_client_hello_wire.end(), coalesced_early_data_and_psk.begin(), coalesced_early_data_and_psk.end());
    test_write_u16(coalesced_client_hello_wire, coalesced_extensions_len_pos, coalesced_extensions_len + coalesced_early_data_and_psk.size());
    test_write_u24(coalesced_client_hello_wire, 6, test_read_u24(coalesced_client_hello_wire, 6) + coalesced_early_data_and_psk.size());
    test_write_u16(coalesced_client_hello_wire, 3, test_read_u16(coalesced_client_hello_wire, 3) + coalesced_early_data_and_psk.size());

    tls_session coalesced_server;
    coalesced_server.set_type(session_type_t::tls);
    auto& coalesced_server_protection = coalesced_server.get_tls_protection();
    coalesced_server_protection.set_tls_version(tls_13);
    coalesced_server_protection.set_cipher_suite(0x1301);
    coalesced_server_protection.set_flow(tls_flow_t::zero_rtt);
    coalesced_server_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    coalesced_server_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    binary_t coalesced_input = coalesced_client_hello_wire;
    coalesced_input.insert(coalesced_input.end(), early_record_wire.begin(), early_record_wire.end());
    auto coalesced_prosumer = coalesced_server.get_secure_prosumer();
    coalesced_prosumer->set_pending_early_data_buffer_limit(1);
    ret = coalesced_prosumer->produce(&coalesced_server, from_client, coalesced_input.data(), coalesced_input.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending ciphertext limit when ClientHello and 0-RTT arrive in one input chunk");
    _test_case.assert(0 == coalesced_server.get_session_status(), __FUNCTION__, "reset the handshake after coalesced pending ciphertext overflow");

    tls_session oversized_coalesced_server;
    oversized_coalesced_server.set_type(session_type_t::tls);
    auto& oversized_coalesced_protection = oversized_coalesced_server.get_tls_protection();
    oversized_coalesced_protection.set_tls_version(tls_13);
    oversized_coalesced_protection.set_cipher_suite(0x1301);
    oversized_coalesced_protection.set_flow(tls_flow_t::zero_rtt);
    oversized_coalesced_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    oversized_coalesced_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    auto oversized_coalesced_prosumer = oversized_coalesced_server.get_secure_prosumer();
    oversized_coalesced_prosumer->set_pending_early_data_buffer_limit(0);
    const size_t pending_record_wire_limit = 5 + 0xffff;
    const size_t pending_record_buffer_limit = 64 * pending_record_wire_limit;
    binary_t oversized_coalesced_input = coalesced_client_hello_wire;
    const size_t oversized_early_data_offset = oversized_coalesced_input.size();
    oversized_coalesced_input.resize(oversized_early_data_offset + pending_record_buffer_limit + 1, 0);
    for (size_t i = 0; i < 64; ++i) {
        size_t record_pos = oversized_early_data_offset + i * pending_record_wire_limit;
        oversized_coalesced_input[record_pos] = 0x17;
        oversized_coalesced_input[record_pos + 1] = 0x03;
        oversized_coalesced_input[record_pos + 2] = 0x03;
        oversized_coalesced_input[record_pos + 3] = 0xff;
        oversized_coalesced_input[record_pos + 4] = 0xff;
    }
    ret = oversized_coalesced_prosumer->produce(&oversized_coalesced_server, from_client, oversized_coalesced_input.data(), oversized_coalesced_input.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__,
                      "reject coalesced 0-RTT input beyond the hard buffer ceiling after parsing ClientHello but before buffering early records");
    _test_case.assert(0 == oversized_coalesced_server.get_session_status(), __FUNCTION__, "reset the handshake after coalesced hard-buffer overflow");

    auto prepare_server = [&](tls_session& session, bool eligible) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
        protection.reset_transcript_hash(&session);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_client).begin_protection();
        session.get_keyvalue().set(session_server_psk_selected_identity, 0);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);

        tls_resumption_ticket ticket;
        ticket.identity = binary_t{0x01};
        ticket.version = static_cast<uint16>(tls_13);
        ticket.cipher_suite = 0x1301;
        ticket.max_early_data_size = 4;
        session.set_early_data_ticket(ticket);

        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        early_state.set(session_early_data_accepted, 0);
        early_state.set(session_early_data_limit, eligible ? 4 : 0);
        early_state.set(session_early_data_received, 0);
        early_state.set(session_early_data_discard_limit, 4096);
        early_state.set(session_early_data_discarded, 0);
    };

    tls_session accepted_server;
    prepare_server(accepted_server, true);
    auto accepted_prosumer = accepted_server.get_secure_prosumer();
    _test_case.assert((1024 * 1024) == accepted_prosumer->get_pending_early_data_buffer_limit(), __FUNCTION__,
                      "apply a bounded 1 MiB pending ciphertext buffer by default");
    accepted_prosumer->set_pending_early_data_buffer_limit(early_record_wire.size());
    _test_case.assert(early_record_wire.size() == accepted_prosumer->get_pending_early_data_buffer_limit(), __FUNCTION__,
                      "allow the server to configure the pending ciphertext buffer limit");
    size_t first_fragment_size = 7;
    ret = accepted_prosumer->produce(&accepted_server, from_client, early_record_wire.data(), first_fragment_size);
    _test_case.test(ret, __FUNCTION__, "buffer a partial in-flight 0-RTT record until the server's EncryptedExtensions decision");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_received), __FUNCTION__,
                      "do not decrypt or account early data before the server decides");
    char accepted_output[8] = {};
    size_t accepted_read = 0;
    accepted_prosumer->consume(0, 0, accepted_output, sizeof(accepted_output), &accepted_read);
    _test_case.assert(0 == accepted_read, __FUNCTION__, "do not deliver early data before EncryptedExtensions");

    tls_handshake_encrypted_extensions accepted_ee(&accepted_server);
    accepted_ee.get_extensions().add(new tls_extension_early_data(&accepted_ee));
    binary_t accepted_ee_wire;
    ret = accepted_ee.write(from_server, accepted_ee_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the acceptance signal and resume buffered early data");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record server acceptance before resuming in-flight early data");
    ret = accepted_prosumer->produce(&accepted_server, from_client, early_record_wire.data() + first_fragment_size, early_record_wire.size() - first_fragment_size);
    _test_case.test(ret, __FUNCTION__, "complete the buffered TLS record after EncryptedExtensions has committed acceptance");
    size_t accepted_after_ee = 0;
    ret = accepted_prosumer->consume(0, 0, accepted_output, sizeof(accepted_output), &accepted_after_ee);
    _test_case.test(ret, __FUNCTION__, "deliver buffered early data after EncryptedExtensions acceptance");
    _test_case.assert(3 == accepted_after_ee, __FUNCTION__, "deliver the complete buffered early-data payload");
    _test_case.assert(3 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_received), __FUNCTION__,
                      "account the accepted early-data payload only after it is processed");
    _test_case.assert(binary_t({0x31, 0x32, 0x33}) == binary_t(accepted_output, accepted_output + accepted_after_ee), __FUNCTION__,
                      "preserve the buffered early-data plaintext");

    tls_session overflow_server;
    prepare_server(overflow_server, true);
    auto overflow_prosumer = overflow_server.get_secure_prosumer();
    overflow_prosumer->set_pending_early_data_buffer_limit(first_fragment_size);
    ret = overflow_prosumer->produce(&overflow_server, from_client, early_record_wire.data(), first_fragment_size);
    _test_case.test(ret, __FUNCTION__, "accept a pending ciphertext fragment exactly at the configured buffer limit");
    ret = overflow_prosumer->produce(&overflow_server, from_client, early_record_wire.data() + first_fragment_size, 1);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject cumulative pending 0-RTT ciphertext beyond the configured buffer limit");
    size_t pending_buffer_overflow_alert_count = 0;
    overflow_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
            ++pending_buffer_overflow_alert_count;
        }
    });
    _test_case.assert(1 == pending_buffer_overflow_alert_count, __FUNCTION__,
                      "raise exactly one fatal internal_error when the pending ciphertext buffer limit is exceeded");
    _test_case.assert(0 == overflow_server.get_session_status(), __FUNCTION__, "reset the handshake state after pending ciphertext buffer overflow");
    char overflow_output[8] = {};
    size_t overflow_read = 0;
    overflow_prosumer->consume(0, 0, overflow_output, sizeof(overflow_output), &overflow_read);
    _test_case.assert(0 == overflow_read, __FUNCTION__, "do not deliver data after the pending ciphertext buffer overflow");

    tls_session record_count_boundary_server;
    prepare_server(record_count_boundary_server, true);
    auto record_count_boundary_prosumer = record_count_boundary_server.get_secure_prosumer();
    record_count_boundary_prosumer->set_pending_early_data_buffer_limit(0);
    binary_t max_pending_records;
    for (size_t i = 0; i < 64; ++i) {
        max_pending_records.insert(max_pending_records.end(), early_record_wire.begin(), early_record_wire.end());
    }
    ret = record_count_boundary_prosumer->produce(&record_count_boundary_server, from_client, max_pending_records.data(), max_pending_records.size());
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow exactly 64 pending records when the byte cap is disabled");

    tls_session record_count_server;
    prepare_server(record_count_server, true);
    auto record_count_prosumer = record_count_server.get_secure_prosumer();
    record_count_prosumer->set_pending_early_data_buffer_limit(0);
    binary_t too_many_pending_records;
    for (size_t i = 0; i < 65; ++i) {
        too_many_pending_records.insert(too_many_pending_records.end(), early_record_wire.begin(), early_record_wire.end());
    }
    ret = record_count_prosumer->produce(&record_count_server, from_client, too_many_pending_records.data(), too_many_pending_records.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending 0-RTT record-count limit independently of the byte limit");

    tls_session record_buffer_limit_server;
    prepare_server(record_buffer_limit_server, true);
    auto record_buffer_limit_prosumer = record_buffer_limit_server.get_secure_prosumer();
    record_buffer_limit_prosumer->set_pending_early_data_buffer_limit(0);
    const size_t record_buffer_limit = 64 * (5 + 0xffff);
    binary_t oversized_pending_input(record_buffer_limit + 1, 0);
    oversized_pending_input[0] = 0x17;
    oversized_pending_input[1] = 0x03;
    oversized_pending_input[2] = 0x03;
    oversized_pending_input[3] = 0xff;
    oversized_pending_input[4] = 0xff;
    ret = record_buffer_limit_prosumer->produce(&record_buffer_limit_server, from_client, oversized_pending_input.data(), oversized_pending_input.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject input beyond the record-count-derived hard buffer ceiling before copying it");
    size_t record_count_overflow_alert_count = 0;
    record_count_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
            ++record_count_overflow_alert_count;
        }
    });
    _test_case.assert(1 == record_count_overflow_alert_count, __FUNCTION__, "raise exactly one fatal internal_error for pending record-count overflow");

    tls_session callback_overflow_server;
    prepare_server(callback_overflow_server, true);
    auto callback_overflow_prosumer = callback_overflow_server.get_secure_prosumer();
    callback_overflow_prosumer->set_pending_early_data_buffer_limit(1);
    bool callback_write_rejected = false;
    ret = callback_overflow_prosumer->produce(&callback_overflow_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        callback_write_rejected = (errorcode_t::overflow == stream.write(early_record_wire.data(), early_record_wire.size()));
    });
    _test_case.assert(callback_write_rejected, __FUNCTION__, "reject callback input before it grows the pending buffer beyond its byte limit");
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending ciphertext bound on callback-based input");
    size_t callback_overflow_alert_count = 0;
    callback_overflow_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
            ++callback_overflow_alert_count;
        }
    });
    _test_case.assert(1 == callback_overflow_alert_count, __FUNCTION__, "raise exactly one fatal internal_error for callback-based buffer overflow");

    tls_session callback_api_server;
    prepare_server(callback_api_server, true);
    auto callback_api_prosumer = callback_api_server.get_secure_prosumer();
    callback_api_prosumer->set_pending_early_data_buffer_limit(1);
    bool callback_printf_rejected = false;
    bool callback_large_printf_rejected = false;
    bool callback_insert_rejected = false;
    bool callback_fill_rejected = false;
    bool callback_resize_rejected = false;
    const std::string large_printf_output(4096, 'p');
    ret = callback_api_prosumer->produce(&callback_api_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        callback_printf_rejected = (errorcode_t::overflow == stream.printf("%s", "formatted output"));
        callback_large_printf_rejected = (errorcode_t::overflow == stream.printf("%s", large_printf_output.c_str()));
        callback_insert_rejected = (errorcode_t::overflow == stream.insert(0, early_record_wire.data(), early_record_wire.size()));
        callback_fill_rejected = (errorcode_t::overflow == stream.fill(2, 'x'));
        stream.resize(2);
        callback_resize_rejected = (0 == stream.size());
    });
    _test_case.assert(callback_printf_rejected, __FUNCTION__, "bound printf output before formatted data grows the pending buffer");
    _test_case.assert(callback_large_printf_rejected, __FUNCTION__, "bound a large formatted output chunk without materializing it in an intermediate stream");
    _test_case.assert(callback_insert_rejected, __FUNCTION__, "bound insert output before inserted data grows the pending buffer");
    _test_case.assert(callback_fill_rejected, __FUNCTION__, "bound fill output before it grows the pending buffer");
    _test_case.assert(callback_resize_rejected, __FUNCTION__, "reject callback resize before it grows the pending buffer");
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject callback mutation APIs that exceed the pending ciphertext limit");

    tls_session callback_encoder_server;
    prepare_server(callback_encoder_server, true);
    auto callback_encoder_prosumer = callback_encoder_server.get_secure_prosumer();
    callback_encoder_prosumer->set_pending_early_data_buffer_limit(1);
    return_t callback_encoder_ret = errorcode_t::success;
    ret = callback_encoder_prosumer->produce(&callback_encoder_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        callback_encoder_ret = base64_encode(binary_t{0x01, 0x02, 0x03}, stream);
    });
    _test_case.assert(errorcode_t::overflow == callback_encoder_ret, __FUNCTION__, "reject a Base64 encoder reservation before writing through its raw output pointer");
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "propagate an over-limit Base64 reservation to pending ciphertext handling");

    tls_session callback_base16_server;
    prepare_server(callback_base16_server, true);
    auto callback_base16_prosumer = callback_base16_server.get_secure_prosumer();
    callback_base16_prosumer->set_pending_early_data_buffer_limit(1);
    return_t callback_base16_ret = errorcode_t::success;
    ret = callback_base16_prosumer->produce(&callback_base16_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        callback_base16_ret = base16_encode(binary_t{0x01, 0x02, 0x03}, stream);
    });
    _test_case.assert(errorcode_t::overflow == callback_base16_ret, __FUNCTION__, "reject a Base16 encoder reservation before writing through its raw output pointer");
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "propagate an over-limit Base16 reservation to pending ciphertext handling");

    tls_session callback_integer_server;
    prepare_server(callback_integer_server, true);
    auto callback_integer_prosumer = callback_integer_server.get_secure_prosumer();
    callback_integer_prosumer->set_pending_early_data_buffer_limit(1);
    ret = callback_integer_prosumer->produce(&callback_integer_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void { stream << 123456; });
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound integral stream insertion through the formatted output hook");

    tls_session callback_assignment_server;
    prepare_server(callback_assignment_server, true);
    auto callback_assignment_prosumer = callback_assignment_server.get_secure_prosumer();
    callback_assignment_prosumer->set_pending_early_data_buffer_limit(1);
    ret = callback_assignment_prosumer->produce(&callback_assignment_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        basic_stream oversized;
        oversized.write("oversized", 9);
        stream = oversized;
    });
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound callback stream copy assignment before replacing the pending buffer");

    tls_session callback_move_assignment_server;
    prepare_server(callback_move_assignment_server, true);
    auto callback_move_assignment_prosumer = callback_move_assignment_server.get_secure_prosumer();
    callback_move_assignment_prosumer->set_pending_early_data_buffer_limit(1);
    ret = callback_move_assignment_prosumer->produce(&callback_move_assignment_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
        basic_stream oversized;
        oversized.write("oversized", 9);
        stream = std::move(oversized);
    });
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound callback stream move assignment before replacing the pending buffer");

    tls_session rejected_server;
    prepare_server(rejected_server, false);
    // PSK rejection may select one_rtt during ClientHello processing, but
    // in-flight early data must remain pending until EncryptedExtensions.
    rejected_server.get_tls_protection().set_flow(tls_flow_t::one_rtt);
    auto rejected_prosumer = rejected_server.get_secure_prosumer();
    ret = rejected_prosumer->produce(&rejected_server, from_client, early_record_wire.data(), early_record_wire.size());
    _test_case.test(ret, __FUNCTION__, "buffer in-flight early data after PSK rejection has selected one_rtt but before EncryptedExtensions");
    if (errorcode_t::success != ret) {
        return;
    }
    char rejected_output[8] = {};
    size_t rejected_read = 0;
    rejected_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &rejected_read);
    _test_case.assert(0 == rejected_read, __FUNCTION__, "do not deliver data before a rejection decision");

    tls_handshake_encrypted_extensions rejected_ee(&rejected_server);
    binary_t rejected_ee_wire;
    ret = rejected_ee.write(from_server, rejected_ee_wire);
    _test_case.test(ret, __FUNCTION__, "omit early_data and discard the buffered rejected ciphertext under handshake keys");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == rejected_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "retain rejection state when EncryptedExtensions omits early_data");
    _test_case.assert(tls_flow_t::one_rtt == rejected_server.get_tls_protection().get_flow(), __FUNCTION__, "retain handshake-key flow while resuming rejected records");
    _test_case.assert(early_record_wire.size() - 5 == rejected_server.get_session_info(from_server).get_keyvalue().get(session_early_data_discarded), __FUNCTION__,
                      "discard the buffered ciphertext within the configured skip bound");
    size_t rejected_after_ee = 0;
    ret = rejected_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &rejected_after_ee);
    _test_case.assert(0 == rejected_after_ee, __FUNCTION__, "never deliver rejected early-data plaintext");
}

static void test_tls13_hrr_drains_buffered_early_data() {
    _test_case.begin("TLS 1.3 HelloRetryRequest drains already-buffered rejected early data");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);
    // The probe bypasses ServerHello serialization; provide the RFC-defined
    // HRR random so postprocess recognizes HRR before key-schedule processing.
    const binary_t hrr_random{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                              0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    protection.get_secrets().assign(tls_secret_t::server_hello_random, hrr_random);
    protection.get_protection_context().add_supported_version(tls_13);
    session.update_session_status(session_status_client_hello);
    // HRR does not select a PSK identity. Keep the synthetic ServerHello
    // state explicit so calc() derives the zero-PSK early secret.
    session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_discard_limit, 4096);

    // Simulate a complete 0-RTT record coalesced after ClientHello1 while the
    // server has not yet committed its response.
    binary_t in_flight_record{0x17, 0x03, 0x03, 0x00, 0x10};
    in_flight_record.insert(in_flight_record.end(), 16, 0xaa);
    auto prosumer = session.get_secure_prosumer();
    return_t ret = prosumer->produce(&session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.test(ret, __FUNCTION__, "buffer in-flight 0-RTT while the early-data decision is pending");
    _test_case.assert(0 == early_state.get(session_early_data_discarded), __FUNCTION__, "do not discard the record before the server chooses its HRR response");

    test_tls13_server_hello_postprocess_probe hrr(&session);
    hrr.set_version(tls_13);
    ret = hrr.postprocess_write();
    _test_case.test(ret, __FUNCTION__, "commit HelloRetryRequest and drain pending first-flight records");
    _test_case.assert(tls_flow_t::hello_retry_request == protection.get_flow(), __FUNCTION__, "enter HRR flow before processing buffered records");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__,
                      "account for the buffered ciphertext as rejected early data immediately after HRR");
    _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                      "count the drained HRR early-data record against the independent record ceiling");

    // ClientHello2 still carries pre_shared_key, but it must not reset the
    // rejected-record ceiling accumulated for ClientHello1's 0-RTT flight.
    tls_handshake_client_hello client_hello2(&session);
    tls_extension_client_psk client_hello2_psk(&client_hello2);
    binary_t client_hello2_psk_wire{0x00, 0x29, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20};
    client_hello2_psk_wire.insert(client_hello2_psk_wire.end(), 32, 0x00);
    size_t client_hello2_psk_pos = 0;
    ret = client_hello2_psk.read(from_client, client_hello2_psk_wire.data(), client_hello2_psk_wire.size(), client_hello2_psk_pos);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello2 pre_shared_key without resetting the HRR discard counter");
    _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "preserve the rejected-record count across ClientHello2 PSK parsing");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__, "preserve the rejected-ciphertext byte count across ClientHello2 PSK parsing");

    binary_t remaining_hrr_records;
    for (size_t i = 0; i < 63; ++i) {
        remaining_hrr_records.insert(remaining_hrr_records.end(), in_flight_record.begin(), in_flight_record.end());
    }
    ret = prosumer->produce(&session, from_client, remaining_hrr_records.data(), remaining_hrr_records.size());
    _test_case.test(ret, __FUNCTION__, "accept the remaining rejected records up to the connection-wide 64-record ceiling");
    _test_case.assert(64 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "retain one cumulative 64-record ceiling across HRR and ClientHello2");

    ret = prosumer->produce(&session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject the 65th rejected early-data record after ClientHello2");
    _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "abort after the cumulative rejected-record ceiling is exceeded");
    size_t hrr_overflow_alert_count = 0;
    session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++hrr_overflow_alert_count;
        }
    });
    _test_case.assert(1 == hrr_overflow_alert_count, __FUNCTION__, "queue one fatal alert when the post-ClientHello2 record ceiling is exceeded");

    char output[32] = {};
    size_t consumed = 0;
    ret = prosumer->consume(0, 0, output, sizeof(output), &consumed);
    _test_case.assert(0 == consumed, __FUNCTION__, "never deliver HRR-rejected early-data plaintext to the application");

    tls_session over_limit_session;
    over_limit_session.set_type(session_type_t::tls);
    auto& over_limit_protection = over_limit_session.get_tls_protection();
    over_limit_protection.set_tls_version(tls_13);
    over_limit_protection.set_cipher_suite(0x1301);
    over_limit_protection.set_flow(tls_flow_t::zero_rtt);
    over_limit_protection.get_secrets().assign(tls_secret_t::server_hello_random, hrr_random);
    over_limit_protection.get_protection_context().add_supported_version(tls_13);
    over_limit_session.update_session_status(session_status_client_hello);
    over_limit_session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
    auto& over_limit_state = over_limit_session.get_session_info(from_server).get_keyvalue();
    over_limit_state.set(session_early_data_offered, 1);
    over_limit_state.set(session_early_data_offered_initial, 1);
    over_limit_state.set(session_early_data_discard_limit, 8);
    auto over_limit_prosumer = over_limit_session.get_secure_prosumer();
    ret = over_limit_prosumer->produce(&over_limit_session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.test(ret, __FUNCTION__, "buffer the over-budget record before the HRR decision");

    test_tls13_server_hello_postprocess_probe over_limit_hrr(&over_limit_session);
    over_limit_hrr.set_version(tls_13);
    ret = over_limit_hrr.postprocess_write();
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the rejected-ciphertext budget while committing HRR");
    _test_case.assert(0 == over_limit_session.get_session_status(), __FUNCTION__, "abort the handshake when buffered HRR data exceeds the discard budget");
    size_t fatal_unexpected_message_count = 0;
    over_limit_session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++fatal_unexpected_message_count;
        }
    });
    _test_case.assert(1 == fatal_unexpected_message_count, __FUNCTION__, "queue one fatal unexpected_message for over-budget HRR data");
}

static void test_tls13_server_discards_rejected_early_data_records() {
    _test_case.begin("TLS 1.3 server discards rejected early-data records before Server Finished");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::one_rtt);
    session.update_session_status(session_status_client_hello);
    session.update_session_status(session_status_server_hello);
    session.get_session_info(from_client).begin_protection();
    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 4096);
    early_state.set(session_early_data_discarded, 0);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

    binary_t rejected_record{0x17, 0x03, 0x03, 0x00, 0x10};
    rejected_record.insert(rejected_record.end(), 16, 0xaa);
    tls_records records;
    return_t ret = records.read(&session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "trial-decrypt rejected 0-RTT with handshake keys and discard failed records");
    _test_case.assert(1 == records.size(), __FUNCTION__, "consume the rejected early-data record");
    if (records.size()) {
        auto decoded = static_cast<tls_record_application_data*>(records.getat(0));
        _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "do not deliver rejected early-data plaintext");
    }
    _test_case.assert(false == session.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__,
                      "do not raise bad_record_mac for intentionally rejected 0-RTT data");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__, "count discarded ciphertext against the configured early-data skip bound");
    _test_case.assert(0 == session.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                      "restore the handshake record sequence after failed trial decryption");

    tls_session pre_server_hello_session;
    pre_server_hello_session.set_type(session_type_t::tls);
    auto& pre_server_hello_protection = pre_server_hello_session.get_tls_protection();
    pre_server_hello_protection.set_tls_version(tls_13);
    pre_server_hello_protection.set_cipher_suite(0x1301);
    pre_server_hello_protection.set_flow(tls_flow_t::one_rtt);
    pre_server_hello_session.update_session_status(session_status_client_hello);
    pre_server_hello_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    pre_server_hello_session.get_session_info(from_client).begin_protection();
    auto& pre_server_hello_state = pre_server_hello_session.get_session_info(from_server).get_keyvalue();
    pre_server_hello_state.set(session_early_data_offered, 1);
    pre_server_hello_state.set(session_early_data_accepted, 0);
    pre_server_hello_state.set(session_early_data_discard_limit, 4096);
    tls_records pre_server_hello_records;
    ret = pre_server_hello_records.read(&pre_server_hello_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "discard rejected 0-RTT records that arrive before ServerHello");
    _test_case.assert(16 == pre_server_hello_state.get(session_early_data_discarded), __FUNCTION__,
                      "account for rejected data received before handshake traffic keys exist");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    auto& hrr_protection = hrr_session.get_tls_protection();
    hrr_protection.set_tls_version(tls_13);
    hrr_protection.set_cipher_suite(0x1301);
    hrr_protection.set_flow(tls_flow_t::hello_retry_request);
    hrr_session.update_session_status(session_status_client_hello);
    hrr_session.update_session_status(session_status_hello_retry_request);
    hrr_session.get_session_info(from_client).begin_protection();
    auto& hrr_early_state = hrr_session.get_session_info(from_server).get_keyvalue();
    hrr_early_state.set(session_early_data_offered, 1);
    hrr_early_state.set(session_early_data_accepted, 0);
    hrr_early_state.set(session_early_data_discard_limit, 4096);
    tls_records hrr_records;
    ret = hrr_records.read(&hrr_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "skip already-in-flight 0-RTT records after HelloRetryRequest");
    _test_case.assert(16 == hrr_early_state.get(session_early_data_discarded), __FUNCTION__, "bound HRR early-data skipping by the configured ciphertext discard limit");

    tls_session over_limit_session;
    over_limit_session.set_type(session_type_t::tls);
    auto& over_limit_protection = over_limit_session.get_tls_protection();
    over_limit_protection.set_tls_version(tls_13);
    over_limit_protection.set_cipher_suite(0x1301);
    over_limit_protection.set_flow(tls_flow_t::one_rtt);
    over_limit_session.update_session_status(session_status_client_hello);
    over_limit_session.update_session_status(session_status_server_hello);
    over_limit_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    over_limit_session.get_session_info(from_client).begin_protection();
    auto& over_limit_state = over_limit_session.get_session_info(from_server).get_keyvalue();
    over_limit_state.set(session_early_data_offered, 1);
    over_limit_state.set(session_early_data_accepted, 0);
    over_limit_state.set(session_early_data_discard_limit, 8);
    tls_records over_limit_records;
    ret = over_limit_records.read(&over_limit_session, from_client, rejected_record);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "abort when rejected early-data ciphertext exceeds the configured skip limit");
    _test_case.assert(over_limit_session.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__, "raise a fatal alert when the rejection skip bound is exceeded");

    tls_session default_limit_session;
    _test_case.assert(1024 * 1024 == default_limit_session.get_early_data_discard_limit(), __FUNCTION__,
                      "use an independent bounded ciphertext discard budget by default");

    default_limit_session.set_type(session_type_t::tls);
    auto& default_protection = default_limit_session.get_tls_protection();
    default_protection.set_tls_version(tls_13);
    default_protection.set_cipher_suite(0x1301);
    default_protection.set_flow(tls_flow_t::one_rtt);
    default_limit_session.update_session_status(session_status_client_hello);
    default_limit_session.update_session_status(session_status_server_hello);
    default_limit_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    default_limit_session.get_session_info(from_client).begin_protection();
    auto& default_state = default_limit_session.get_session_info(from_server).get_keyvalue();
    default_state.set(session_early_data_offered, 1);
    default_state.set(session_early_data_accepted, 0);
    default_state.set(session_early_data_discard_limit, default_limit_session.get_early_data_discard_limit());
    tls_records default_records;
    ret = default_records.read(&default_limit_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "discard rejected ciphertext using the independent default budget without a per-session override");
    _test_case.assert(16 == default_state.get(session_early_data_discarded), __FUNCTION__, "count the encrypted record body rather than the ticket plaintext allowance");
    _test_case.assert(1 == default_state.get(session_early_data_discarded_records), __FUNCTION__, "count rejected records independently from ciphertext bytes");

    tls_session record_count_session;
    record_count_session.set_type(session_type_t::tls);
    auto& count_protection = record_count_session.get_tls_protection();
    count_protection.set_tls_version(tls_13);
    count_protection.set_cipher_suite(0x1301);
    count_protection.set_flow(tls_flow_t::one_rtt);
    record_count_session.update_session_status(session_status_client_hello);
    record_count_session.update_session_status(session_status_server_hello);
    record_count_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    record_count_session.get_session_info(from_client).begin_protection();
    auto& count_state = record_count_session.get_session_info(from_server).get_keyvalue();
    count_state.set(session_early_data_offered, 1);
    count_state.set(session_early_data_accepted, 0);
    count_state.set(session_early_data_discard_limit, record_count_session.get_early_data_discard_limit());
    bool discarded_64_records = true;
    for (size_t i = 0; i < 64; ++i) {
        tls_records one_record;
        ret = one_record.read(&record_count_session, from_client, rejected_record);
        if (errorcode_t::success != ret) {
            discarded_64_records = false;
            break;
        }
    }
    _test_case.assert(discarded_64_records, __FUNCTION__, "allow at most 64 rejected TLS records within the discard budget");
    _test_case.assert(64 == count_state.get(session_early_data_discarded_records), __FUNCTION__, "account for all discarded records");
    tls_records sixty_fifth_record;
    ret = sixty_fifth_record.read(&record_count_session, from_client, rejected_record);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject the 65th discarded early-data record");

    tls_session empty_record_session;
    empty_record_session.set_type(session_type_t::tls);
    auto& empty_protection = empty_record_session.get_tls_protection();
    empty_protection.set_tls_version(tls_13);
    empty_protection.set_cipher_suite(0x1301);
    empty_protection.set_flow(tls_flow_t::zero_rtt);
    empty_record_session.update_session_status(session_status_client_hello);
    auto& empty_state = empty_record_session.get_session_info(from_server).get_keyvalue();
    empty_state.set(session_early_data_offered, 1);
    empty_state.set(session_early_data_accepted, 0);
    empty_state.set(session_early_data_discard_limit, empty_record_session.get_early_data_discard_limit());
    const binary_t empty_record_wire{0x17, 0x03, 0x03, 0x00, 0x00};
    tls_records empty_record;
    ret = empty_record.read(&empty_record_session, from_client, empty_record_wire);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject an empty ciphertext fragment instead of counting it as discarded early data");
}

static void test_tls13_server_requires_consistent_early_data_acceptance_signal() {
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

void testcase_gpt_early_data() {
    test_tls13_server_requires_consistent_early_data_acceptance_signal();
    test_tls13_server_rejects_early_data_for_nonzero_selected_identity();
    test_tls13_server_requires_early_data_ticket_permission();
    test_tls13_client_requires_psk_for_early_data_offer();
    test_tls13_server_records_early_data_offer_during_extension_parse();
    test_tls13_client_validates_early_data_acceptance_parameters();
    test_tls13_client_sends_bounded_early_data();
    test_tls13_server_discards_rejected_early_data_records();
    test_tls13_hrr_drains_buffered_early_data();
    test_tls13_server_defers_inflight_early_data_until_encrypted_extensions();
    test_tls13_end_of_early_data_usage_reset();
    test_tls13_end_of_early_data_requires_server_finished();
    test_tls13_application_data_finished_direction_policy();
    test_tls13_handshake_protection_transition();
    test_tls13_early_data_and_compatibility_ccs();
}
