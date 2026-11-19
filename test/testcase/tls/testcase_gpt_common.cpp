/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_common.cpp
 * @author GPT
 * @desc   Shared helper implementations for testcase_gpt groups.
 */

#include "testcase_gpt_common.hpp"

testable_tls_handshake_certificate_verify::testable_tls_handshake_certificate_verify(tls_session* session) : tls_handshake_certificate_verify(session) {}

return_t testable_tls_handshake_certificate_verify::sign_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t& scheme, binary_t& signature) {
    return sign_certverify(pkey, dir, scheme, signature);
}

return_t testable_tls_handshake_certificate_verify::write_for_test(tls_direction_t dir, binary_t& body) { return do_write_body(dir, body); }

return_t testable_tls_handshake_certificate_verify::verify_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t scheme, const binary_t& signature) {
    return verify_certverify(pkey, dir, scheme, signature);
}

test_tls13_failing_client_hello::test_tls13_failing_client_hello(tls_session* session) : tls_handshake_client_hello(session), _preprocess_called(false) {}

bool test_tls13_failing_client_hello::preprocess_called() const { return _preprocess_called; }

return_t test_tls13_failing_client_hello::do_preprocess(tls_direction_t) {
    _preprocess_called = true;
    return errorcode_t::unexpected;
}

test_tls13_server_hello_phase_probe::test_tls13_server_hello_phase_probe(tls_session* session) : tls_handshake_server_hello(session) {}

return_t test_tls13_server_hello_phase_probe::validate_phase(tls_direction_t dir) { return do_preprocess(dir); }

test_tls13_server_hello_postprocess_probe::test_tls13_server_hello_postprocess_probe(tls_session* session) : tls_handshake_server_hello(session) {}

return_t test_tls13_server_hello_postprocess_probe::postprocess_read() {
    // do_postprocess consumes the already-decoded ServerHello state. The
    // four-byte buffer is sufficient here because this probe deliberately
    // leaves the encoded ServerHello body empty.
    byte_t stream[4] = {0, 0, 0, 0};
    return do_postprocess(from_server, tls_io_operation_t::read, stream, sizeof(stream));
}

return_t test_tls13_server_hello_postprocess_probe::postprocess_write() {
    // The same minimal buffer is sufficient for the synthetic HRR postprocess probe.
    byte_t stream[4] = {0, 0, 0, 0};
    return do_postprocess(from_server, tls_io_operation_t::write, stream, sizeof(stream));
}

test_tls13_server_hello_writer_probe::test_tls13_server_hello_writer_probe(tls_session* session) : tls_handshake_server_hello(session), _postprocessed(false) {}

bool test_tls13_server_hello_writer_probe::postprocessed() const { return _postprocessed; }

bool test_tls13_server_hello_writer_probe::serialized_body_valid() const {
    // The captured stream includes the four-byte Handshake header.
    if ((_serialized.size() < 50) || (_serialized[0] != (byte_t)tls_handshake_type_t::server_hello)) {
        return false;
    }
    uint32 handshake_size = ((uint32)_serialized[1] << 16) | ((uint32)_serialized[2] << 8) | _serialized[3];
    if (handshake_size != _serialized.size() - 4) {
        return false;
    }

    size_t pos = 4;
    if ((_serialized[pos++] != 0x03) || (_serialized[pos++] != 0x03)) {
        return false;
    }
    pos += 32;
    if (pos >= _serialized.size()) {
        return false;
    }
    uint8 session_id_size = _serialized[pos++];
    if (session_id_size > 32 || (pos + session_id_size + 5 > _serialized.size())) {
        return false;
    }
    pos += session_id_size;

    uint16 cipher_suite = ((uint16)_serialized[pos] << 8) | _serialized[pos + 1];
    pos += 2;
    if ((cipher_suite != 0x1301) || (_serialized[pos++] != 0)) {
        return false;
    }

    uint16 extensions_size = ((uint16)_serialized[pos] << 8) | _serialized[pos + 1];
    pos += 2;
    if (pos + extensions_size != _serialized.size()) {
        return false;
    }

    bool supported_versions_found = false;
    size_t extensions_end = pos + extensions_size;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) {
            return false;
        }
        uint16 extension_type = ((uint16)_serialized[pos] << 8) | _serialized[pos + 1];
        uint16 extension_size = ((uint16)_serialized[pos + 2] << 8) | _serialized[pos + 3];
        pos += 4;
        if (extension_size > extensions_end - pos) {
            return false;
        }
        if (extension_type == 0x002b) {
            if ((extension_size != 2) || (_serialized[pos] != 0x03) || (_serialized[pos + 1] != 0x04)) {
                return false;
            }
            supported_versions_found = true;
        }
        pos += extension_size;
    }
    return supported_versions_found;
}

return_t test_tls13_server_hello_writer_probe::do_postprocess(tls_direction_t, tls_io_operation_t, const byte_t* stream, size_t size) {
    _postprocessed = true;
    if (stream && size) {
        _serialized.assign(stream, stream + size);
    }
    auto session = get_session();
    session->get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
    session->get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
    session->update_session_status(session_status_server_hello);
    return errorcode_t::success;
}

return_t test_tls13_inner_plaintext_writer::write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record) {
    return do_write_header(dir, record, plaintext);
}

return_t test_tls_record_size_probe::read_record_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return do_read_header(dir, stream, size, pos);
}

return_t test_tls_record_size_probe::write_record_fragment(tls_direction_t dir, binary_t& record, const binary_t& fragment) {
    return do_write_header_internal(dir, record, fragment);
}

return_t test_tls_record_size_probe::write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record) {
    return do_write_header(dir, record, plaintext);
}

return_t test_tls_record_size_probe::validate_plaintext_size(tls_direction_t dir, size_t size) { return validate_record_size_limit(dir, size); }

return_t test_client_supportedversion_clienthello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_record_handshake record(session);
    tls_handshake* handshake = nullptr;
    ret = tls_composer::construct_client_hello(&handshake, session, nullptr, minspec, maxspec);
    record << handshake;
    ret = record.write(from_client, bin);
    return ret;
}

return_t test_client_supportedversion_serverhello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, tls_version_t& server_version) {
    return_t ret = errorcode_t::success;
    uint16 server_cs = 0;

    auto& protection = session->get_tls_protection();
    ret = protection.negotiate(session, minspec, maxspec, server_cs, server_version);
    return ret;
}

uint16 test_read_u16(const binary_t& bin, size_t pos) { return (uint16)(((uint16)bin[pos] << 8) | bin[pos + 1]); }

uint32 test_read_u24(const binary_t& bin, size_t pos) { return ((uint32)bin[pos] << 16) | ((uint32)bin[pos + 1] << 8) | (uint32)bin[pos + 2]; }

void test_write_u16(binary_t& bin, size_t pos, uint16 value) {
    bin[pos] = (byte_t)(value >> 8);
    bin[pos + 1] = (byte_t)value;
}

void test_write_u24(binary_t& bin, size_t pos, uint32 value) {
    bin[pos] = (byte_t)(value >> 16);
    bin[pos + 1] = (byte_t)(value >> 8);
    bin[pos + 2] = (byte_t)value;
}

bool test_rewrite_client_hello_supported_versions(binary_t& bin, uint8 vector_len, const binary_t& versions) {
    // TLSPlaintext + ClientHello framing.
    if (bin.size() < 9 || bin[0] != 0x16 || bin[5] != 0x01) {
        return false;
    }

    uint16 record_len = test_read_u16(bin, 3);
    uint32 handshake_len = test_read_u24(bin, 6);
    size_t record_end = 5 + record_len;
    size_t handshake_end = 9 + handshake_len;
    if (record_end > bin.size() || handshake_end > record_end) {
        return false;
    }

    size_t pos = 9;
    if (pos + 2 + 32 + 1 > handshake_end) {
        return false;
    }
    pos += 2 + 32;

    uint8 session_id_len = bin[pos++];
    if (pos + session_id_len + 2 > handshake_end) {
        return false;
    }
    pos += session_id_len;

    uint16 cipher_suites_len = test_read_u16(bin, pos);
    pos += 2;
    if (pos + cipher_suites_len + 1 > handshake_end) {
        return false;
    }
    pos += cipher_suites_len;

    uint8 compression_methods_len = bin[pos++];
    if (pos + compression_methods_len + 2 > handshake_end) {
        return false;
    }
    pos += compression_methods_len;

    size_t extensions_len_pos = pos;
    uint16 extensions_len = test_read_u16(bin, pos);
    pos += 2;
    size_t extensions_end = pos + extensions_len;
    if (extensions_end != handshake_end) {
        return false;
    }

    while (pos + 4 <= extensions_end) {
        uint16 extension_type = test_read_u16(bin, pos);
        uint16 extension_len = test_read_u16(bin, pos + 2);
        size_t extension_len_pos = pos + 2;
        size_t extension_data_pos = pos + 4;
        pos = extension_data_pos + extension_len;
        if (pos > extensions_end) {
            return false;
        }

        if (0x002b == extension_type) {  // supported_versions
            binary_t replacement;
            replacement.push_back(vector_len);
            replacement.insert(replacement.end(), versions.begin(), versions.end());

            int delta = (int)replacement.size() - (int)extension_len;
            if ((int)extensions_len + delta < 0 || (int)handshake_len + delta < 0 || (int)record_len + delta < 0) {
                return false;
            }

            bin.erase(bin.begin() + extension_data_pos, bin.begin() + extension_data_pos + extension_len);
            bin.insert(bin.begin() + extension_data_pos, replacement.begin(), replacement.end());

            test_write_u16(bin, extension_len_pos, (uint16)replacement.size());
            test_write_u16(bin, extensions_len_pos, (uint16)((int)extensions_len + delta));
            test_write_u24(bin, 6, (uint32)((int)handshake_len + delta));
            test_write_u16(bin, 3, (uint16)((int)record_len + delta));
            return true;
        }
    }
    return false;
}

bool test_remove_client_hello_supported_versions(binary_t& bin) {
    // TLSPlaintext + ClientHello framing.
    if (bin.size() < 9 || bin[0] != 0x16 || bin[5] != 0x01) {
        return false;
    }

    uint16 record_len = test_read_u16(bin, 3);
    uint32 handshake_len = test_read_u24(bin, 6);
    size_t record_end = 5 + record_len;
    size_t handshake_end = 9 + handshake_len;
    if (record_end > bin.size() || handshake_end > record_end) {
        return false;
    }

    size_t pos = 9 + 2 + 32;
    if (pos + 1 > handshake_end) {
        return false;
    }
    uint8 session_id_len = bin[pos++];
    if (pos + session_id_len + 2 > handshake_end) {
        return false;
    }
    pos += session_id_len;

    uint16 cipher_suites_len = test_read_u16(bin, pos);
    pos += 2;
    if (pos + cipher_suites_len + 1 > handshake_end) {
        return false;
    }
    pos += cipher_suites_len;

    uint8 compression_methods_len = bin[pos++];
    if (pos + compression_methods_len + 2 > handshake_end) {
        return false;
    }
    pos += compression_methods_len;

    size_t extensions_len_pos = pos;
    uint16 extensions_len = test_read_u16(bin, pos);
    pos += 2;
    size_t extensions_end = pos + extensions_len;
    if (extensions_end != handshake_end) {
        return false;
    }

    while (pos + 4 <= extensions_end) {
        uint16 extension_type = test_read_u16(bin, pos);
        uint16 extension_len = test_read_u16(bin, pos + 2);
        size_t extension_end = pos + 4 + extension_len;
        if (extension_end > extensions_end) {
            return false;
        }

        if (0x002b == extension_type) {  // supported_versions
            size_t removed = 4 + extension_len;
            bin.erase(bin.begin() + pos, bin.begin() + extension_end);
            test_write_u16(bin, extensions_len_pos, (uint16)(extensions_len - removed));
            test_write_u24(bin, 6, handshake_len - (uint32)removed);
            test_write_u16(bin, 3, (uint16)(record_len - removed));
            return true;
        }
        pos = extension_end;
    }
    return false;
}

void test_client_supported_versions_vector(const char* name, uint8 vector_len, const binary_t& versions, bool expect_success) {
    // Scenario under test: the named test-case variant.
    // Action: construct ClientHello.
    // Expected: rewrite supported_versions vector.
    _test_case.begin(name);

    tls_session client_session;
    tls_session server_session;
    binary_t client_hello;

    return_t ret = test_client_supportedversion_clienthello(&client_session, tls_12, tls_13, client_hello);
    _test_case.test(ret, __FUNCTION__, "construct ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    bool rewritten = test_rewrite_client_hello_supported_versions(client_hello, vector_len, versions);
    _test_case.assert(rewritten, __FUNCTION__, "rewrite supported_versions vector");
    if (false == rewritten) {
        return;
    }

    tls_records records;
    ret = records.read(&server_session, from_client, client_hello);
    if (expect_success) {
        _test_case.test(ret, __FUNCTION__, "accept supported_versions vector");
    } else {
        _test_case.assert(errorcode_t::bad_format == ret, __FUNCTION__, "reject malformed supported_versions vector");

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        server_session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_alert_count;
                fatal_alerts.insert(desc);
            }
        });
        _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::decode_error}, __FUNCTION__,
                          "exactly one fatal decode_error alert");
        _test_case.assert(0 == server_session.get_session_status(), __FUNCTION__, "terminate malformed ClientHello handshake state");
    }
}

void test_serverhello_unoffered_supported_version() {
    // Scenario under test: ServerHello selects an unoffered supported_version.
    // Action: construct TLS 1.2-only ClientHello.
    // Expected: ClientHello cipher suite list.
    _test_case.begin("ServerHello selects an unoffered supported_version");

    tls_session client_session;
    binary_t client_hello;
    return_t ret = test_client_supportedversion_clienthello(&client_session, tls_12, tls_12, client_hello);
    _test_case.test(ret, __FUNCTION__, "construct TLS 1.2-only ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Echo the ClientHello session ID and an actually offered cipher suite.
    size_t client_hello_pos = 9 + 2 + 32;
    uint8 session_id_len = client_hello[client_hello_pos++];
    binary_t session_id(client_hello.begin() + client_hello_pos, client_hello.begin() + client_hello_pos + session_id_len);
    client_hello_pos += session_id_len;
    uint16 cipher_suites_len = test_read_u16(client_hello, client_hello_pos);
    client_hello_pos += 2;
    if (cipher_suites_len < 2) {
        _test_case.assert(false, __FUNCTION__, "ClientHello cipher suite list");
        return;
    }
    uint16 cipher_suite = test_read_u16(client_hello, client_hello_pos);

    // Minimal ServerHello selecting TLS 1.3 although the ClientHello offered TLS 1.2 only.
    binary_t body;
    body.push_back(0x03);
    body.push_back(0x03);              // legacy_version
    body.resize(body.size() + 32, 0);  // random
    body.push_back(session_id_len);
    body.insert(body.end(), session_id.begin(), session_id.end());
    body.push_back((byte_t)(cipher_suite >> 8));
    body.push_back((byte_t)cipher_suite);
    body.push_back(0);  // legacy_compression_method
    body.push_back(0);
    body.push_back(6);  // extensions length
    body.push_back(0);
    body.push_back(0x2b);  // supported_versions
    body.push_back(0);
    body.push_back(2);
    body.push_back(0x03);
    body.push_back(0x04);  // TLS 1.3

    binary_t handshake;
    handshake.push_back(0x02);  // server_hello
    handshake.push_back((byte_t)(body.size() >> 16));
    handshake.push_back((byte_t)(body.size() >> 8));
    handshake.push_back((byte_t)body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());

    binary_t server_hello;
    server_hello.push_back(0x16);  // handshake record
    server_hello.push_back(0x03);
    server_hello.push_back(0x03);
    server_hello.push_back((byte_t)(handshake.size() >> 8));
    server_hello.push_back((byte_t)handshake.size());
    server_hello.insert(server_hello.end(), handshake.begin(), handshake.end());

    tls_records records;
    ret = records.read(&client_session, from_server, server_hello);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject unoffered TLS 1.3 selection");

    size_t fatal_alert_count = 0;
    std::set<tls_alertdesc_t> fatal_alerts;
    client_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
            fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                      "exactly one fatal illegal_parameter alert");
    _test_case.assert(0 == client_session.get_session_status(), __FUNCTION__, "terminate handshake after unoffered version selection");
}

return_t test_build_tls12_serverhello(tls_session& client, tls_session& server, tls_version_t client_min, tls_version_t client_max, binary_t& wire,
                                      bool tls12_only_supported_versions) {
    return_t ret = errorcode_t::success;
    client.set_type(session_type_t::tls);
    binary_t client_hello;
    ret = test_client_supportedversion_clienthello(&client, client_min, client_max, client_hello);
    if (errorcode_t::success != ret) {
        return ret;
    }
    if (tls12_only_supported_versions) {
        bool rewritten = test_rewrite_client_hello_supported_versions(client_hello, 2, binary_t{0x03, 0x03});
        if (false == rewritten) {
            return errorcode_t::bad_format;
        }
    }

    server.set_type(session_type_t::tls);
    tls_records client_records;
    ret = client_records.read(&server, from_client, client_hello);
    if (errorcode_t::success != ret) {
        return ret;
    }

    size_t pos = 9 + 2 + 32;
    if (pos >= client_hello.size()) {
        return errorcode_t::bad_format;
    }
    uint8 session_id_size = client_hello[pos++];
    if (pos + session_id_size + 2 > client_hello.size()) {
        return errorcode_t::bad_format;
    }
    binary_t session_id(client_hello.begin() + pos, client_hello.begin() + pos + session_id_size);
    pos += session_id_size;

    uint16 cipher_suites_size = test_read_u16(client_hello, pos);
    pos += 2;
    if ((0 != (cipher_suites_size & 1)) || (pos + cipher_suites_size > client_hello.size())) {
        return errorcode_t::bad_format;
    }

    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    uint16 cipher_suite = 0;
    for (size_t i = 0; i < cipher_suites_size; i += 2) {
        uint16 candidate = test_read_u16(client_hello, pos + i);
        auto hint = tlsadvisor->hintof_cipher_suite(candidate);
        if (hint && (tls_12 == hint->spec) && (tls_flag_support & hint->flags)) {
            cipher_suite = candidate;
            break;
        }
    }
    if (0 == cipher_suite) {
        return errorcode_t::handshake_failure;
    }

    auto& protection = server.get_tls_protection();
    protection.set_tls_version(tls_12);
    server.get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);

    auto hello = new tls_handshake_server_hello(&server);
    hello->set_version(tls_12);
    ret = hello->set_cipher_suite(cipher_suite);
    if (errorcode_t::success != ret) {
        delete hello;
        return ret;
    }
    hello->set_random(binary_t(32, 0x5a));
    hello->set_session_id(session_id);

    tls_record_handshake record(&server);
    record << hello;
    return record.write(from_server, wire);
}

bool test_set_tls_serverhello_random_suffix(binary_t& wire, const byte_t suffix[8]) {
    // TLS record header (5), Handshake header (4), legacy_version (2), Random (32).
    const size_t random_offset = 5 + 4 + 2;
    const size_t suffix_offset = random_offset + 24;
    if ((wire.size() < random_offset + 32) || (wire[0] != 0x16) || (wire[5] != (byte_t)tls_handshake_type_t::server_hello) || (suffix_offset + 8 > random_offset + 32)) {
        return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        wire[suffix_offset + i] = suffix[i];
    }
    return true;
}

void test_configure_tls13_inner_plaintext_session(tls_session& session, bool server_finished, bool client_finished) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
    protection.set_flow(tls_flow_t::one_rtt);

    const binary_t key(16, 0x11);
    const binary_t iv(12, 0x22);
    protection.get_secrets().assign(tls_secret_t::application_client_key, key);
    protection.get_secrets().assign(tls_secret_t::application_client_iv, iv);
    protection.get_secrets().assign(tls_secret_t::application_server_key, key);
    protection.get_secrets().assign(tls_secret_t::application_server_iv, iv);

    session.update_session_status(session_status_server_hello);
    if (server_finished) {
        session.update_session_status(session_status_server_finished);
    }
    if (client_finished) {
        session.update_session_status(session_status_client_finished);
    }
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).begin_protection();
}

return_t test_read_tls13_inner_plaintext(const binary_t& plaintext, tls_direction_t dir, tls_session& reader, tls_records& records) {
    tls_session writer;
    test_configure_tls13_inner_plaintext_session(writer);
    test_configure_tls13_inner_plaintext_session(reader);

    test_tls13_inner_plaintext_writer record(&writer);
    binary_t wire;
    return_t ret = record.write_inner_plaintext(dir, plaintext, wire);
    if (errorcode_t::success == ret) {
        ret = records.read(&reader, dir, wire);
    }
    return ret;
}

return_t test_read_tls13_application_data_with_finished_status(tls_direction_t dir, bool server_finished, bool client_finished, tls_session& reader,
                                                               tls_records& records) {
    tls_session writer;
    test_configure_tls13_inner_plaintext_session(writer, true, true);
    test_configure_tls13_inner_plaintext_session(reader, server_finished, client_finished);

    const binary_t plaintext{'a', 'p', 'p', (byte_t)tls_content_type_t::application_data};
    test_tls13_inner_plaintext_writer record(&writer);
    binary_t wire;
    return_t ret = record.write_inner_plaintext(dir, plaintext, wire);
    if (errorcode_t::success == ret) {
        ret = records.read(&reader, dir, wire);
    }
    return ret;
}

void test_configure_tls_record_size_session(tls_session& session, tls_version_t version, bool protected_record) {
    session.get_tls_protection().set_tls_version(version);
    if (protected_record) {
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).begin_protection();
    }
}

return_t test_read_tls_record_header_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session) {
    test_configure_tls_record_size_session(session, version, protected_record);
    test_tls_record_size_probe record(&session);
    binary_t header{(byte_t)tls_content_type_t::application_data, 0x03, 0x03, (byte_t)(length >> 8), (byte_t)length};
    size_t pos = 0;
    return record.read_record_header(from_client, header.data(), header.size(), pos);
}

return_t test_read_tls_record_fragment_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session, tls_records& records) {
    test_configure_tls_record_size_session(session, version, protected_record);
    session.update_session_status(session_status_server_hello);
    binary_t header{(byte_t)tls_content_type_t::application_data, 0x03, 0x03, (byte_t)(length >> 8), (byte_t)length};
    return records.read(&session, from_client, header);
}

return_t test_write_tls_record_fragment_size(tls_version_t version, bool protected_record, size_t length) {
    tls_session session;
    test_configure_tls_record_size_session(session, version, protected_record);
    test_tls_record_size_probe record(&session);
    binary_t fragment(length, 0x5a);
    binary_t wire;
    return record.write_record_fragment(from_client, wire, fragment);
}

return_t test_write_tls_record_header_path(tls_version_t version, size_t length) {
    tls_session session;
    test_configure_tls_record_size_session(session, version, false);
    test_tls_record_size_probe record(&session);
    binary_t fragment(length, 0x5a);
    binary_t wire;
    return record.write_inner_plaintext(from_client, fragment, wire);
}

void test_configure_dtls13_ccm8_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_version_t::dtls_13);
    protection.set_cipher_suite(0x1305);  // TLS_AES_128_CCM_8_SHA256
    protection.set_flow(tls_flow_t::one_rtt);

    const binary_t key(16, 0x11);
    const binary_t iv(12, 0x22);
    const binary_t sn_key(16, 0x33);
    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::application_client_key, key);
    secrets.assign(tls_secret_t::application_client_iv, iv);
    secrets.assign(tls_secret_t::application_client_sn_key, sn_key);
    secrets.assign(tls_secret_t::application_server_key, key);
    secrets.assign(tls_secret_t::application_server_iv, iv);
    secrets.assign(tls_secret_t::application_server_sn_key, sn_key);

    session.update_session_status(session_status_server_hello);
    session.update_session_status(session_status_server_finished);
    session.update_session_status(session_status_client_finished);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).begin_protection();
}
