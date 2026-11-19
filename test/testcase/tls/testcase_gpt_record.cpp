/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_record.cpp
 * @author GPT
 * @desc   TLS and DTLS record framing, protection, size-limit, and AEAD boundary tests.
 */

#include "testcase_gpt_common.hpp"

static void test_tls13_key_usage_limits() {
    constexpr uint64 aes_max_records = 23726566ULL;
    constexpr uint64 aes_max_plaintext = 388736063996ULL;
    constexpr uint64 ccm_max_records = (1ULL << 21);
    constexpr uint64 ccm_max_plaintext = (1ULL << 35);
    const binary_t plaintext{'x', (byte_t)tls_content_type_t::application_data};

    // Scenario under test: TLS 1.3 per-key AEAD usage limits.
    // Action: allow the final AES-GCM application record while reserving one alert slot.
    // Expected: leave an alert record and one additional safety record unused.
    _test_case.begin("TLS 1.3 per-key AEAD usage limits");

    {
        tls_session writer;
        tls_session reader;
        test_configure_tls13_inner_plaintext_session(writer);
        test_configure_tls13_inner_plaintext_session(reader);
        writer.set_recordno(from_client, aes_max_records - 3);
        reader.set_recordno(from_client, aes_max_records - 3);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, __FUNCTION__, "allow the final AES-GCM application record while reserving one alert slot");
        if (errorcode_t::success == ret) {
            uint64 writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == writer_recordno, __FUNCTION__, "leave an alert record and one additional safety record unused");
            auto& writer_usage = writer.get_session_info(from_client).get_keyvalue();
            uint64 writer_usage_bytes = writer_usage.get(session_tls13_key_usage_bytes);
            _test_case.assert(plaintext.size() == writer_usage_bytes, __FUNCTION__, "account the complete TLSInnerPlaintext bytes encrypted under the key");

            tls_records records;
            ret = records.read(&reader, from_client, wire);
            _test_case.test(ret, __FUNCTION__, "receiver accepts a valid record at the sender's usage boundary");
            uint64 reader_recordno = reader.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == reader_recordno, __FUNCTION__, "receiver advances its sequence without enforcing sender usage limits");

            test_tls13_inner_plaintext_writer blocked(&writer);
            binary_t blocked_wire;
            ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), __FUNCTION__, "do not emit a record beyond the AES-GCM usage limit");
            writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == writer_recordno, __FUNCTION__, "do not advance the record number after limit rejection");

            test_tls13_inner_plaintext_writer blocked_again(&writer);
            binary_t blocked_again_wire;
            ret = blocked_again.write_inner_plaintext(from_client, plaintext, blocked_again_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_again_wire.empty(), __FUNCTION__, "keep the exhausted key from encrypting additional data");

            size_t fatal_count = 0;
            writer.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
                    ++fatal_count;
                }
            });
            _test_case.assert(1 == fatal_count, __FUNCTION__, "queue one fatal internal_error when the key usage limit is reached");
            uint32 writer_status = writer.get_session_status();
            _test_case.assert((session_status_server_hello & writer_status) != 0, __FUNCTION__, "preserve handshake state so the queued fatal alert can be sent");

            const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
            test_tls13_inner_plaintext_writer alert_record(&writer);
            binary_t alert_wire;
            ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
            _test_case.test(ret, __FUNCTION__, "allow the reserved fatal Alert record while staying below the ceiling");
            writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 1) == writer_recordno, __FUNCTION__, "send the fatal Alert while remaining strictly below the record ceiling");
        }
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        auto& usage = writer.get_session_info(from_client).get_keyvalue();
        usage.set(session_tls13_key_usage_bytes, aes_max_plaintext - 6 - plaintext.size());

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, __FUNCTION__, "allow plaintext usage up to the reserved fatal-alert boundary");
        uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, __FUNCTION__, "leave the fatal-alert reserve and a further safety margin");

        test_tls13_inner_plaintext_writer blocked(&writer);
        binary_t blocked_wire;
        ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), __FUNCTION__, "reject the byte-limit crossing before encryption");
        usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, __FUNCTION__, "do not account plaintext from a rejected encryption attempt");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.test(ret, __FUNCTION__, "allow the fatal Alert to consume the reserved plaintext bytes");
        usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 3) == usage_bytes, __FUNCTION__, "send the fatal Alert while remaining below the plaintext ceiling");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1302);
        writer.set_recordno(from_client, aes_max_records - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), __FUNCTION__, "refuse AES-256-GCM encryption at its per-key record boundary");
    }

    {
        const uint16 ccm_suites[] = {0x1304, 0x1305};
        for (size_t i = 0; i < 2; ++i) {
            tls_session writer;
            test_configure_tls13_inner_plaintext_session(writer);
            writer.get_tls_protection().set_cipher_suite(ccm_suites[i]);
            writer.set_recordno(from_client, ccm_max_records - 2);

            test_tls13_inner_plaintext_writer record(&writer);
            binary_t wire;
            return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
            _test_case.assert(errorcode_t::exceed == ret && wire.empty(), __FUNCTION__, "refuse AES-CCM encryption at its per-key record boundary");
        }
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1302);
        auto& usage = writer.get_session_info(from_client).get_keyvalue();
        usage.set(session_tls13_key_usage_bytes, aes_max_plaintext - 6 - plaintext.size());

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, __FUNCTION__, "allow AES-256-GCM plaintext usage up to its reserved-alert boundary");
        uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, __FUNCTION__, "apply the AES-256-GCM per-key plaintext-byte ceiling");

        test_tls13_inner_plaintext_writer blocked(&writer);
        binary_t blocked_wire;
        ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), __FUNCTION__, "do not encrypt beyond the AES-256-GCM byte limit");
    }

    {
        const uint16 ccm_suites[] = {0x1304, 0x1305};
        for (size_t i = 0; i < 2; ++i) {
            tls_session writer;
            test_configure_tls13_inner_plaintext_session(writer);
            writer.get_tls_protection().set_cipher_suite(ccm_suites[i]);
            auto& usage = writer.get_session_info(from_client).get_keyvalue();
            usage.set(session_tls13_key_usage_bytes, ccm_max_plaintext - 6 - plaintext.size());

            test_tls13_inner_plaintext_writer record(&writer);
            binary_t wire;
            return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
            _test_case.test(ret, __FUNCTION__, "allow AES-CCM plaintext usage up to its reserved-alert boundary");
            uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
            _test_case.assert((ccm_max_plaintext - 6) == usage_bytes, __FUNCTION__, "apply the AES-CCM per-key plaintext-byte ceiling");

            test_tls13_inner_plaintext_writer blocked(&writer);
            binary_t blocked_wire;
            ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), __FUNCTION__, "do not encrypt beyond the AES-CCM byte limit");
        }
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1303);
        writer.set_recordno(from_client, (~static_cast<uint64>(0)) - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), __FUNCTION__, "refuse application encryption before the 64-bit record sequence wraps");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.test(ret, __FUNCTION__, "allow the reserved ChaCha20-Poly1305 Alert sequence without approaching wrap");
        uint64 writer_recordno = writer.get_recordno(from_client);
        _test_case.assert((~static_cast<uint64>(0)) - 1 == writer_recordno, __FUNCTION__, "stop before the ChaCha20 sequence reaches its terminal value");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        auto& protection = writer.get_tls_protection();
        protection.set_flow(tls_flow_t::zero_rtt);
        const binary_t key(16, 0x31);
        const binary_t iv(12, 0x42);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, key);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, iv);
        writer.reset_session_status();
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        writer.get_session_info(from_client).begin_protection();
        writer.set_recordno(from_client, aes_max_records - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), __FUNCTION__, "do not rely on KeyUpdate for non-updatable early data");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.assert(errorcode_t::exceed == ret && alert_wire.empty(), __FUNCTION__, "require transport closure when early-data key usage is exhausted");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        auto& client_usage = session.get_session_info(from_client).get_keyvalue();
        auto& server_usage = session.get_session_info(from_server).get_keyvalue();
        client_usage.set(session_tls13_key_usage_bytes, 99);
        server_usage.set(session_tls13_key_usage_bytes, 77);
        session.reset_recordno(from_client);
        uint64 reset_client_usage_bytes = client_usage.get(session_tls13_key_usage_bytes);
        uint64 unchanged_server_usage_bytes = server_usage.get(session_tls13_key_usage_bytes);
        _test_case.assert(0 == reset_client_usage_bytes, __FUNCTION__, "reset byte accounting for the direction whose traffic key changed");
        _test_case.assert(77 == unchanged_server_usage_bytes, __FUNCTION__, "preserve the opposite direction's independent key usage counter");
        session.reset_recordno(from_server);
        uint64 reset_server_usage_bytes = server_usage.get(session_tls13_key_usage_bytes);
        _test_case.assert(0 == reset_server_usage_bytes, __FUNCTION__, "reset byte accounting when the opposite directional key changes");
    }
}

static void test_tls13_inner_plaintext_padding_and_content_type() {
    // Scenario under test: TLS 1.3 TLSInnerPlaintext padding and content type.
    // Action: accept Application Data with multiple zero padding octets.
    // Expected: remove all padding and the inner content type.
    _test_case.begin("TLS 1.3 TLSInnerPlaintext padding and content type");

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{'p', 'i', 'n', 'g', 0x00, 0x00, (byte_t)tls_content_type_t::application_data, 0x00, 0x00, 0x00};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept Application Data with multiple zero padding octets");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            const binary_t expected{'p', 'i', 'n', 'g', 0x00, 0x00};
            _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "remove all padding and the inner content type");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{(byte_t)tls_content_type_t::application_data};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept zero-length Application Data content");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "deliver empty Application Data content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded empty Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        binary_t plaintext(16384, 0x41);
        plaintext.push_back((byte_t)tls_content_type_t::application_data);
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept maximum TLSInnerPlaintext application content at 2^14+1");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(16384 == decoded->get_binary().size(), __FUNCTION__, "deliver maximum application content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded maximum Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        binary_t plaintext{(byte_t)tls_content_type_t::application_data};
        plaintext.insert(plaintext.end(), 16384, 0x00);
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept maximum TLSInnerPlaintext padding at 2^14+1");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "strip maximum zero padding after empty content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded maximum-padding Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_content_type_t::alert, 0x00, 0x00};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept one Alert message followed by zero padding");
        _test_case.assert(0 != (reader.get_session_status() & session_status_client_close_notified), __FUNCTION__, "dispatch only the two-byte Alert content");
    }

    {
        tls_session handshake_writer;
        handshake_writer.get_tls_protection().set_tls_version(tls_13);
        tls_handshake_certificate_request request(&handshake_writer);
        auto algorithms = new tls_extension_signature_algorithms(&request);
        algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        request.get_extensions().add(algorithms);

        binary_t handshake_message;
        return_t ret = request.write(from_server, handshake_message);
        _test_case.test(ret, __FUNCTION__, "construct a valid CertificateRequest Handshake message");
        if (errorcode_t::success != ret) {
            return;
        }

        binary_t plaintext = handshake_message;
        plaintext.push_back((byte_t)tls_content_type_t::handshake);
        plaintext.push_back(0x00);
        plaintext.push_back(0x00);

        tls_session reader;
        tls_records records;
        ret = test_read_tls13_inner_plaintext(plaintext, from_server, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept a Handshake message followed by zero padding");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(1 == decoded->get_handshakes().size(), __FUNCTION__, "remove padding before Handshake parser dispatch");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded Handshake record is available");
        }
    }

    const auto reject = [](const char* label, const binary_t& plaintext, tls_alertdesc_t expected_alert = tls_alertdesc_t::unexpected_message) {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "%s: reject malformed TLSInnerPlaintext", label);
        _test_case.assert(1 == reader.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                          "%s: authenticate the record before rejecting its empty or malformed TLSInnerPlaintext", label);

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_alert_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{expected_alert}, __FUNCTION__, "%s: queue exactly one expected fatal alert",
                          label);
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "%s: reset session state", label);
    };

    reject("empty decrypted plaintext", binary_t());
    reject("all-zero decrypted plaintext", binary_t{0x00, 0x00, 0x00, 0x00});
    reject("unknown inner content type", binary_t{0x99}, tls_alertdesc_t::illegal_parameter);
    reject("protected ChangeCipherSpec content type", binary_t{0x14});
    reject("empty Alert content", binary_t{(byte_t)tls_content_type_t::alert});
    reject("truncated Alert content", binary_t{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_content_type_t::alert});
    reject("coalesced Alert messages", binary_t{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_alertlevel_t::warning,
                                                (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_content_type_t::alert});
    reject("empty Handshake content", binary_t{(byte_t)tls_content_type_t::handshake});
}

static void test_tls_record_size_limits() {
    // Scenario under test: TLS record plaintext and ciphertext size limits.
    // Expected: allow TLS 1.3 plaintext header length at 2^14.
    _test_case.begin("TLS record plaintext and ciphertext size limits");

    // Inbound TLS 1.3: plaintext records are limited to 2^14; protected records to 2^14+256.
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls_13, false, 16384, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.3 plaintext header length at 2^14");
        ret = test_read_tls_record_header_size(tls_13, false, 16385, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.3 plaintext fragment above 2^14");
    }
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls_13, true, 16640, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.3 ciphertext header length at 2^14+256");
        ret = test_read_tls_record_header_size(tls_13, true, 16641, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.3 ciphertext fragment above 2^14+256");
        size_t fatal_alert_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::record_overflow == desc) {
                ++fatal_alert_count;
            }
        });
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal record_overflow alert");
    }

    // Exercise the complete tls_records receive entry point. The oversized
    // TLSCiphertext length must be rejected from its header before body parsing.
    {
        tls_session session;
        tls_records records;
        return_t ret = test_read_tls_record_fragment_size(tls_13, true, 16641, session, records);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject oversized TLS 1.3 ciphertext through tls_records::read");
        _test_case.assert(0 == records.size(), __FUNCTION__, "do not publish a record rejected by the receive path");

        size_t fatal_alert_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::record_overflow == desc) {
                ++fatal_alert_count;
            }
        });
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal record_overflow alert through the receive path");
    }

    // Inbound TLS 1.2 retains its 2^14 plaintext and 2^14+2048 ciphertext limits.
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls_12, false, 16384, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.2 plaintext header length at 2^14");
        ret = test_read_tls_record_header_size(tls_12, false, 16385, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.2 plaintext fragment above 2^14");
    }
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls_12, true, 18432, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.2 ciphertext header length at 2^14+2048");
        ret = test_read_tls_record_header_size(tls_12, true, 18433, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.2 ciphertext fragment above 2^14+2048");
    }

    // Exercise the normal do_write_header() path as well as the raw header helper.
    // A size-validation error must be returned to the caller, not silently discarded.
    _test_case.assert(errorcode_t::success == test_write_tls_record_header_path(tls_13, 16384), __FUNCTION__,
                      "propagate TLS 1.3 plaintext boundary through record writer");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_header_path(tls_13, 16385), __FUNCTION__,
                      "propagate TLS 1.3 plaintext size rejection through record writer");
    _test_case.assert(errorcode_t::success == test_write_tls_record_header_path(tls_12, 16384), __FUNCTION__,
                      "propagate TLS 1.2 plaintext boundary through record writer");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_header_path(tls_12, 16385), __FUNCTION__,
                      "propagate TLS 1.2 plaintext size rejection through record writer");

    // Outbound record serialization uses the matching negotiated-version and protection-state limit.
    _test_case.assert(errorcode_t::success == test_write_tls_record_fragment_size(tls_13, false, 16384), __FUNCTION__, "write TLS 1.3 plaintext fragment at 2^14");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_fragment_size(tls_13, false, 16385), __FUNCTION__, "reject TLS 1.3 plaintext fragment above 2^14");
    _test_case.assert(errorcode_t::success == test_write_tls_record_fragment_size(tls_13, true, 16640), __FUNCTION__, "write TLS 1.3 ciphertext fragment at 2^14+256");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_fragment_size(tls_13, true, 16641), __FUNCTION__, "reject TLS 1.3 ciphertext fragment above 2^14+256");

    _test_case.assert(errorcode_t::success == test_write_tls_record_fragment_size(tls_12, false, 16384), __FUNCTION__, "write TLS 1.2 plaintext fragment at 2^14");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_fragment_size(tls_12, false, 16385), __FUNCTION__, "reject TLS 1.2 plaintext fragment above 2^14");
    _test_case.assert(errorcode_t::success == test_write_tls_record_fragment_size(tls_12, true, 18432), __FUNCTION__, "write TLS 1.2 ciphertext fragment at 2^14+2048");
    _test_case.assert(errorcode_t::exceed == test_write_tls_record_fragment_size(tls_12, true, 18433), __FUNCTION__,
                      "reject TLS 1.2 ciphertext fragment above 2^14+2048");

    // DTLS 1.2 uses the same negotiated plaintext limit; oversized inbound records may be rejected with record_overflow.
    {
        tls_session session(session_type_t::dtls);
        session.get_tls_protection().set_tls_version(tls_version_t::dtls_12);
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls_record_size_probe record(&session);
        return_t ret = record.validate_plaintext_size(from_client, 64);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept DTLS 1.2 plaintext at negotiated receive limit");
        ret = record.validate_plaintext_size(from_client, 65);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject DTLS 1.2 plaintext above negotiated receive limit");
        size_t overflow_alert_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::record_overflow == desc)) ++overflow_alert_count;
        });
        _test_case.assert(1 == overflow_alert_count, __FUNCTION__, "queue fatal record_overflow for oversized DTLS 1.2 plaintext");
    }

    // DTLS 1.3 carries TLSInnerPlaintext, including the inner content type, through dtls13_ciphertext.
    {
        class dtls13_size_probe : public dtls13_ciphertext {
           public:
            explicit dtls13_size_probe(tls_session* session) : dtls13_ciphertext(tls_content_type_t::application_data, session) {}
            return_t write_inner(tls_direction_t dir, const binary_t& plaintext, binary_t& record) { return do_write_header(dir, record, plaintext); }
        };
        tls_session session(session_type_t::dtls);
        session.get_tls_protection().set_tls_version(tls_version_t::dtls_13);
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        dtls13_size_probe record(&session);
        binary_t wire;
        return_t ret = record.write_inner(from_client, binary_t(65, 0x5a), wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject DTLS 1.3 TLSInnerPlaintext above peer receive limit before encryption");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no DTLS 1.3 bytes when record_size_limit is exceeded");
    }

    // TLS 1.2 has no record compression path in this implementation, so its encryption input is TLSPlaintext.
    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls_12);
        binary_t plaintext(16385, 0x01);
        binary_t ciphertext;
        binary_t additional;
        binary_t tag;
        return_t ret = session.get_tls_protection().encrypt(&session, from_client, plaintext, ciphertext, additional, tag);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject TLS 1.2 plaintext above 2^14 before encryption");
    }

    // The encryption input is TLSInnerPlaintext in TLS 1.3, including type and padding.
    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        test_tls_record_size_probe record(&session);
        binary_t wire;
        binary_t inner_plaintext(16385, 0x01);
        return_t ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "encrypt TLSInnerPlaintext at 2^14+1");
        inner_plaintext.push_back(0x01);
        wire.clear();
        ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject TLSInnerPlaintext above 2^14+1");
    }
}

static void test_dtls_record_publisher_segment_boundary() {
    // Scenario under test: DTLS record publisher segment boundary.
    // Expected: reject a record larger than the datagram segment target.
    _test_case.begin("DTLS record publisher segment boundary");

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(1);

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        return_t ret = records.write(&session, from_client, [&](tls_session*, binary_t&) { ++callback_count; });
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject a record larger than the datagram segment target");
        _test_case.assert(0 == callback_count, __FUNCTION__, "do not publish an empty or oversized datagram");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(1);

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        return_t ret = publisher.publish(records.getat(0), from_client, [&](tls_session*, binary_t&) { ++callback_count; });
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject an oversized record on the single-record callback path");
        _test_case.assert(0 == callback_count, __FUNCTION__, "do not publish an oversized single-record datagram");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(14);  // DTLS 1.2 header (13) + ChangeCipherSpec (1)

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        size_t datagram_size = 0;
        return_t ret = records.write(&session, from_client, [&](tls_session*, binary_t& bin) {
            ++callback_count;
            datagram_size = bin.size();
        });
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow a datagram exactly at the segment target");
        _test_case.assert(1 == callback_count && 14 == datagram_size, __FUNCTION__, "publish one exact-boundary DTLS datagram");
    }
}

static void test_dtls_record_publisher_pmtu_api() {
    // Scenario under test: DTLS record publisher PMTU API.
    // Expected: report legacy DTLS record header expansion before protection.
    _test_case.begin("DTLS record publisher PMTU API");

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        size_t expansion = 0;
        return_t ret = publisher.get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && sizeof(dtls_header) == expansion, __FUNCTION__, "report legacy DTLS record header expansion before protection");
        _test_case.assert(0 == publisher.get_pmtu_estimate(), __FUNCTION__, "report unknown PMTU estimate as zero");
        auto fragment_size = publisher.get_fragment_size();
        auto segment_size = publisher.get_max_size();
        publisher.set_pmtu_estimate(1500);
        _test_case.assert(1500 == publisher.get_pmtu_estimate(), __FUNCTION__, "expose the transport-provided PMTU estimate");
        _test_case.assert(fragment_size == publisher.get_fragment_size() && segment_size == publisher.get_max_size(), __FUNCTION__,
                          "do not change fragment or segment targets when PMTU estimate changes");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls_12);
        protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 37 == expansion, __FUNCTION__, "include DTLS 1.2 GCM explicit nonce, tag and record header");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls_12);
        protection.set_cipher_suite(0xcca8);  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 29 == expansion, __FUNCTION__, "include DTLS 1.2 ChaCha20-Poly1305 tag without an explicit nonce");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls_13);
        protection.set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 22 == expansion, __FUNCTION__, "include DTLS 1.3 inner content type, conservative unified header and tag");
    }
    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls_13);
        protection.set_cipher_suite(0x1305);  // TLS_AES_128_CCM_8_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 2, expansion);
        _test_case.assert(errorcode_t::success == ret && 19 == expansion, __FUNCTION__, "include DTLS 1.3 padding needed for a short CCM_8 ciphertext sample");
        ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 7, expansion);
        _test_case.assert(errorcode_t::success == ret && 14 == expansion, __FUNCTION__, "do not add DTLS 1.3 padding when the CCM_8 sample is exactly 16 bytes");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls_12);
        protection.set_cipher_suite(0xc013);  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 32, expansion);
        _test_case.assert(errorcode_t::success == ret && 61 == expansion, __FUNCTION__, "calculate DTLS 1.2 CBC MAC-then-encrypt padding expansion");

        session.get_keyvalue().set(session_encrypt_then_mac, 1);
        ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 32, expansion);
        _test_case.assert(errorcode_t::success == ret && 65 == expansion, __FUNCTION__, "calculate DTLS 1.2 CBC encrypt-then-MAC padding expansion");
    }
}

static void test_dtls13_plaintext_content_type_demux() {
    // Scenario under test: DTLS 1.3 plaintext content-type demultiplexing.
    // Expected: allow plaintext alert, handshake, and ACK record builders.
    _test_case.begin("DTLS 1.3 plaintext content-type demultiplexing");

    const tls_content_type_t allowed[] = {
        tls_content_type_t::alert,
        tls_content_type_t::handshake,
        tls_content_type_t::ack,
    };
    tls_session session(session_type_t::dtls);
    session.get_tls_protection().set_tls_version(tls_version_t::dtls_13);

    for (auto type : allowed) {
        tls_record_builder builder;
        auto record = builder.set(&session).set(type).build();
        _test_case.assert(nullptr != record, __FUNCTION__, "allow plaintext alert, handshake, and ACK record builders");
        if (record) {
            record->release();
        }
    }

    {
        tls_record_builder builder;
        auto record = builder.set(&session).set(static_cast<tls_content_type_t>(0x20)).build();
        _test_case.assert((nullptr != record) && (nullptr != dynamic_cast<dtls13_ciphertext*>(record)), __FUNCTION__,
                          "dispatch DTLS 1.3 unified-header values to the protected record parser");
        if (record) {
            record->release();
        }
    }

    {
        binary_t truncated_header{0x20};
        tls_records records;
        return_t ret = records.read(&session, from_server, truncated_header);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a truncated DTLS 1.3 unified header");
    }

    {
        tls_session legacy_session(session_type_t::dtls);
        legacy_session.get_tls_protection().set_tls_version(tls_version_t::dtls_12);
        tls_record_builder builder;
        auto record = builder.set(&legacy_session).set(static_cast<tls_content_type_t>(0x20)).build();
        _test_case.assert((nullptr != record) && (nullptr == dynamic_cast<dtls13_ciphertext*>(record)), __FUNCTION__,
                          "do not dispatch reserved high-bit values to the DTLS 1.3 parser for DTLS 1.2");
        if (record) {
            record->release();
        }

        binary_t reserved_datagram{0x20, 0xfe, 0xfd,  // reserved unified-header range is not a DTLS 1.2 content type
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
        tls_records records;
        return_t ret = records.read(&legacy_session, from_server, reserved_datagram);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject the DTLS 1.3 reserved unified-header range in DTLS 1.2");
    }

    // RFC 9147 §4.1: non-plaintext values must use the 001 unified-header prefix; RFC 9853 requires RRC to be protected.
    const uint8 forbidden[] = {
        static_cast<uint8>(tls_content_type_t::change_cipher_spec),
        static_cast<uint8>(tls_content_type_t::application_data),
        static_cast<uint8>(tls_content_type_t::heartbeat),
        static_cast<uint8>(tls_content_type_t::tls12_cid),
        static_cast<uint8>(tls_content_type_t::return_routability_check),
        0x1f,
        0x40,
        0xff,
    };
    for (auto type : forbidden) {
        binary_t datagram{
            type, 0xfe, 0xfc,                    // legacy record header: content type, version
            0x00, 0x00,                          // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // sequence number
            0x00, 0x01,                          // fragment length
            0x00                                 // one-byte body
        };
        tls_records records;
        return_t ret = records.read(&session, from_server, datagram);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject plaintext content types other than alert, handshake, and ACK in DTLS 1.3");
    }
}

static void test_dtls13_minimum_ciphertext_sample() {
    // Scenario under test: DTLS 1.3 minimum ciphertext sample and padding.
    // Expected: write a short DTLS 1.3 CCM_8 record with required padding.
    _test_case.begin("DTLS 1.3 minimum ciphertext sample and padding");

    class dtls13_padding_probe : public dtls13_ciphertext {
       public:
        explicit dtls13_padding_probe(tls_session* session) : dtls13_ciphertext(tls_content_type_t::alert, session) {}

        return_t write_inner(tls_direction_t dir, const binary_t& inner, binary_t& wire) { return do_write_header(dir, wire, inner); }

        return_t read_inner(tls_direction_t dir, const binary_t& wire, size_t start = 0) {
            size_t pos = start;
            return_t ret = do_read_header(dir, wire.data(), wire.size(), pos);
            if (errorcode_t::success == ret) {
                ret = do_read_body(dir, wire.data(), wire.size(), pos);
            }
            return ret;
        }
    };

    tls_session writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(writer);
    dtls13_padding_probe outgoing(&writer);

    binary_t inner;
    inner.push_back(static_cast<byte_t>(tls_alertlevel_t::fatal));
    inner.push_back(static_cast<byte_t>(tls_alertdesc_t::internal_error));
    inner.push_back(static_cast<byte_t>(tls_content_type_t::alert));

    binary_t wire;
    return_t ret = outgoing.write_inner(from_client, inner, wire);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "write a short DTLS 1.3 CCM_8 record with required padding");
    _test_case.assert(20 == wire.size() && 16 == test_read_u16(wire, 2), __FUNCTION__, "pad ciphertext plus tag to a 16-byte header-protection sample");

    tls_session limited_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(limited_writer);
    limited_writer.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 3);
    dtls13_padding_probe limited_outgoing(&limited_writer);
    binary_t limited_wire;
    ret = limited_outgoing.write_inner(from_client, inner, limited_wire);
    _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "apply the peer record_size_limit after required DTLS 1.3 padding");

    for (size_t content_size = 0; content_size < 8; ++content_size) {
        tls_session loop_writer(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(loop_writer);
        dtls13_padding_probe loop_outgoing(&loop_writer);
        binary_t loop_inner(content_size + 1, 0x55);
        loop_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
        binary_t loop_wire;
        ret = loop_outgoing.write_inner(from_client, loop_inner, loop_wire);
        _test_case.assert(errorcode_t::success == ret && 16 == test_read_u16(loop_wire, 2), __FUNCTION__,
                          "pad every CCM_8 inner plaintext that would produce a sample shorter than 16 bytes");
    }

    tls_session exact_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(exact_writer);
    dtls13_padding_probe exact_outgoing(&exact_writer);
    binary_t exact_inner(8, 0x55);
    exact_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
    binary_t exact_wire;
    ret = exact_outgoing.write_inner(from_client, exact_inner, exact_wire);
    _test_case.assert(errorcode_t::success == ret && 20 == exact_wire.size() && 16 == test_read_u16(exact_wire, 2), __FUNCTION__,
                      "leave an exact 16-byte ciphertext sample unpadded");

    tls_session above_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(above_writer);
    dtls13_padding_probe above_outgoing(&above_writer);
    binary_t above_inner(9, 0x55);
    above_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
    binary_t above_wire;
    ret = above_outgoing.write_inner(from_client, above_inner, above_wire);
    _test_case.assert(errorcode_t::success == ret && 21 == above_wire.size() && 17 == test_read_u16(above_wire, 2), __FUNCTION__,
                      "leave a ciphertext sample larger than 16 bytes unpadded");

    binary_t with_trailing{0xa1, 0xb2, 0xc3};
    binary_append(with_trailing, wire);
    binary_append(with_trailing, binary_t(16, 0x5a));

    tls_session reader(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(reader);
    dtls13_padding_probe incoming(&reader);
    ret = incoming.read_inner(from_client, with_trailing, 3);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "decrypt only the current record when trailing datagram bytes exist");

    size_t alert_count = 0;
    reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
            ++alert_count;
        }
    });
    _test_case.assert(1 == alert_count, __FUNCTION__, "strip zero padding and recover the inner alert content type");

    binary_t invalid_fixed_bits = wire;
    invalid_fixed_bits[0] = 0xff;
    ret = incoming.read_inner(from_client, invalid_fixed_bits);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject a DTLS 1.3 unified header whose leading three bits are not 001");

    binary_t truncated_record = wire;
    truncated_record[2] = 0;
    truncated_record[3] = 17;
    ret = incoming.read_inner(from_client, truncated_record);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a declared DTLS 1.3 ciphertext length that extends beyond the datagram");

    // Heartbeat and RRC are optional and are not negotiated by this test profile.
    const uint8 unsupported_inner_types[] = {
        static_cast<uint8>(tls_content_type_t::change_cipher_spec),
        static_cast<uint8>(tls_content_type_t::heartbeat),
        static_cast<uint8>(tls_content_type_t::tls12_cid),
        static_cast<uint8>(tls_content_type_t::return_routability_check),
    };
    for (auto type : unsupported_inner_types) {
        tls_session invalid_writer(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(invalid_writer);
        dtls13_padding_probe invalid_outgoing(&invalid_writer);
        binary_t invalid_inner{type};
        binary_t invalid_wire;
        ret = invalid_outgoing.write_inner(from_client, invalid_inner, invalid_wire);

        tls_session invalid_reader(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(invalid_reader);
        dtls13_padding_probe invalid_incoming(&invalid_reader);
        if (errorcode_t::success == ret) {
            ret = invalid_incoming.read_inner(from_client, invalid_wire);
        }
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject unsupported authenticated DTLS 1.3 inner content types");
    }

    for (size_t sample_size = 0; sample_size < 16; ++sample_size) {
        binary_t malformed{0xa1, 0xb2, 0xc3};
        binary_append(malformed, binary_t(wire.begin(), wire.begin() + 4));
        malformed.resize(3 + 4 + sample_size, 0x5a);
        malformed[5] = static_cast<byte_t>((sample_size >> 8) & 0xff);
        malformed[6] = static_cast<byte_t>(sample_size & 0xff);
        binary_append(malformed, binary_t(16, 0x5a));

        tls_session short_reader(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(short_reader);
        dtls13_padding_probe short_incoming(&short_reader);
        ret = short_incoming.read_inner(from_client, malformed, 3);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject every ciphertext sample shorter than 16 bytes even when trailing datagram bytes exist");
    }
}

static void test_tls_record_size_limit_extension() {
    // Scenario under test: TLS record_size_limit extension negotiation and enforcement.
    // Action: serialize record_size_limit in ClientHello.
    // Expected: encode extension type and uint16 limit.
    _test_case.begin("TLS record_size_limit extension negotiation and enforcement");

    {
        tls_session session;
        tls_handshake_client_hello handshake(&session);
        tls_extension_record_size_limit extension(&handshake);
        extension.set_record_size_limit(1024);
        binary_t wire;
        return_t ret = extension.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "serialize record_size_limit in ClientHello");
        _test_case.assert(binary_t({0x00, 0x1c, 0x00, 0x02, 0x04, 0x00}) == wire, __FUNCTION__, "encode extension type and uint16 limit");
        _test_case.assert(1024 == session.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the local receive limit for the advertised direction");

        tls_session peer_session;
        tls_handshake_client_hello peer_handshake(&peer_session);
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&peer_handshake, from_client, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "parse record_size_limit extension");
        if (parsed) {
            auto typed = (tls_extension_record_size_limit*)parsed;
            _test_case.assert(1024 == typed->get_record_size_limit(), __FUNCTION__, "recover advertised record size limit");
            parsed->release();
        }
        _test_case.assert(1024 == peer_session.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the peer receive limit for the advertised direction");
    }

    {
        tls_session session;
        tls_handshake_client_hello handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_client, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject record_size_limit below 64");
        size_t illegal_parameter_count = 0;
        session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for limit below 64");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject unsolicited server record_size_limit response");
        size_t unsupported_extension_count = 0;
        session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unsupported_extension == desc)) {
                ++unsupported_extension_count;
            }
        });
        _test_case.assert(1 == unsupported_extension_count, __FUNCTION__, "queue fatal unsupported_extension when client did not offer record_size_limit");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls_12);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject record_size_limit in TLS 1.2 EncryptedExtensions context");
        size_t illegal_parameter_count = 0;
        session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for invalid EncryptedExtensions context");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls_12);
        session.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1024);
        tls_handshake_server_hello handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "accept TLS 1.2 ServerHello response after client offer");
        if (parsed) {
            parsed->release();
        }
        _test_case.assert(1024 == session.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain server receive limit from TLS 1.2 ServerHello");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        session.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1024);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "accept EncryptedExtensions record_size_limit after client offer");
        if (parsed) {
            parsed->release();
        }
        _test_case.assert(1024 == session.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain server receive limit from EncryptedExtensions");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        tls_handshake_encrypted_extensions handshake(&session);
        tls_extension_record_size_limit extension(&handshake);
        extension.set_record_size_limit(1024);
        binary_t wire;
        return_t ret = extension.write(from_server, wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "do not emit unsolicited server record_size_limit response");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        binary_t boundary_plaintext(64, 0x01);
        return_t ret = record.write_inner_plaintext(from_client, boundary_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound TLSInnerPlaintext at negotiated receive limit");
        wire.clear();
        binary_t inner_plaintext(65, 0x01);
        ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject outbound TLSInnerPlaintext above peer receive limit");
    }

    {
        tls_session writer;
        tls_session reader;
        test_configure_tls13_inner_plaintext_session(writer);
        test_configure_tls13_inner_plaintext_session(reader);
        reader.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        binary_t boundary_plaintext(64, 0x5a);
        boundary_plaintext.back() = (byte_t)tls_content_type_t::application_data;
        return_t ret = record.write_inner_plaintext(from_client, boundary_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "construct inbound TLSInnerPlaintext at local receive limit");
        tls_records boundary_records;
        if (errorcode_t::success == ret) {
            ret = boundary_records.read(&reader, from_client, wire);
        }
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept inbound TLSInnerPlaintext at local receive limit");

        tls_session oversized_writer;
        tls_session oversized_reader;
        test_configure_tls13_inner_plaintext_session(oversized_writer);
        test_configure_tls13_inner_plaintext_session(oversized_reader);
        oversized_reader.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls13_inner_plaintext_writer oversized_record(&oversized_writer);
        wire.clear();
        binary_t inner_plaintext(65, 0x01);
        ret = oversized_record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "construct peer record above local receive limit");

        tls_records records;
        if (errorcode_t::success == ret) {
            ret = records.read(&oversized_reader, from_client, wire);
        }
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject inbound TLSInnerPlaintext above local receive limit");
        size_t record_overflow_count = 0;
        oversized_reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::record_overflow == desc)) {
                ++record_overflow_count;
            }
        });
        _test_case.assert(1 == record_overflow_count, __FUNCTION__, "queue fatal record_overflow for inbound negotiated-limit violation");
    }
}

static void test_tls13_rejects_truncated_aead_record_before_tag_extraction() {
    // Scenario under test: TLS 1.3 rejects truncated AEAD records before extracting the tag.
    // Expected: return bad_data when the record is shorter than its AEAD tag.
    _test_case.begin("TLS 1.3 rejects truncated AEAD records before extracting the tag");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::one_rtt);
    protection.get_secrets().assign(tls_secret_t::handshake_client_key, binary_t(16, 0x41));
    protection.get_secrets().assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x42));

    // The TLS header declares five body bytes; AES-GCM needs at least a
    // complete 16-byte authentication tag before decryption can be attempted.
    const binary_t truncated_record = {0x17, 0x03, 0x03, 0x00, 0x05, 0x70, 0x69, 0x6e, 0x67, 0x17};
    binary_t plaintext;
    return_t ret = protection.decrypt_aead(&session, from_client, truncated_record.data(), truncated_record.size(), 0, plaintext, protection_space_t::tls,
                                           decrypt_alert_policy_t::suppress);

    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "return bad_data when the record is shorter than its AEAD tag");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not produce plaintext from a truncated record");
    _test_case.assert(0 == session.get_session_info(from_client).get_recordno(false), __FUNCTION__, "do not consume a record number when tag extraction is impossible");
    size_t fatal_alert_count = 0;
    session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
        }
    });
    _test_case.assert(0 == fatal_alert_count, __FUNCTION__, "do not report an authentication failure before attempting AEAD");

    // An all-zero tag is not an authenticated empty TLSInnerPlaintext. The
    // record-layer integration test covers a valid tag over an empty plaintext;
    // this low-level trial-decrypt case remains an authentication failure.
    // Keep one encrypted byte so this case exercises an ordinary failed
    // AEAD authentication, independently of the empty-plaintext edge case.
    binary_t invalid_tag_record = {0x17, 0x03, 0x03, 0x00, 0x11, 0x70};
    invalid_tag_record.insert(invalid_tag_record.end(), 16, 0);
    ret = protection.decrypt_aead(&session, from_client, invalid_tag_record.data(), invalid_tag_record.size(), 0, plaintext, protection_space_t::tls,
                                  decrypt_alert_policy_t::suppress);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "propagate the AEAD authentication failure for an invalid TLS 1.3 tag");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext when trial authentication fails");

    // The overload that receives AAD separately must validate the trailing tag
    // before extracting it from the record buffer.
    binary_t aad = {0x17, 0x03, 0x03, 0x00, 0x05};
    auto recordno_before_truncated_aad = session.get_session_info(from_client).get_recordno(false);
    ret = protection.decrypt(&session, from_client, truncated_record.data(), truncated_record.size(), 0, plaintext, aad);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject a record too short for separately supplied AAD and tag");
    _test_case.assert(recordno_before_truncated_aad == session.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                      "do not consume a record number when separately supplied AAD leaves no room for the tag");

    // The explicit-AAD/tag overload must reject an inverted range before
    // forming stream + pos or computing size - pos.
    binary_t tag(16, 0);
    ret = protection.decrypt(&session, from_client, truncated_record.data(), 0, 1, plaintext, aad, tag);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject size smaller than pos in the explicit-tag overload");
}

static void test_tls12_rejects_truncated_aead_explicit_nonce() {
    // Scenario under test: TLS 1.2 rejects truncated AEAD explicit nonces before reading them.
    // Expected: reject ciphertext shorter than the TLS 1.2 explicit nonce.
    _test_case.begin("TLS 1.2 rejects truncated AEAD explicit nonces before reading them");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_12);
    protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (supported)

    // TLS 1.2 AES-GCM carries an 8-byte explicit nonce before the encrypted
    // fragment. The AEAD tag is supplied separately by this overload.
    binary_t truncated_ciphertext(7, 0x5a);
    binary_t aad(13, 0);
    binary_t tag(16, 0);
    binary_t plaintext;
    return_t ret = protection.decrypt(&session, from_client, truncated_ciphertext.data(), truncated_ciphertext.size(), 0, plaintext, aad, tag);

    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject ciphertext shorter than the TLS 1.2 explicit nonce");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not produce plaintext from a truncated explicit nonce");
    _test_case.assert(0 == session.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                      "do not consume a record number when the explicit nonce is truncated");
}

void testcase_gpt_record() {
    test_tls13_rejects_truncated_aead_record_before_tag_extraction();
    test_tls12_rejects_truncated_aead_explicit_nonce();
    test_tls13_key_usage_limits();
    test_tls13_inner_plaintext_padding_and_content_type();
    test_tls_record_size_limits();
    test_dtls_record_publisher_segment_boundary();
    test_dtls_record_publisher_pmtu_api();
    test_dtls13_plaintext_content_type_demux();
    test_dtls13_minimum_ciphertext_sample();
    test_tls_record_size_limit_extension();
}
