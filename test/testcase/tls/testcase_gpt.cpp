/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt.cpp
 * @author GPT
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

static return_t test_client_supportedversion_clienthello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_record_handshake record(session);
    tls_handshake* handshake = nullptr;
    ret = tls_composer::construct_client_hello(&handshake, session, nullptr, minspec, maxspec);
    record << handshake;
    ret = record.write(from_client, bin);
    return ret;
}

static return_t test_client_supportedversion_serverhello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, tls_version_t& server_version) {
    return_t ret = errorcode_t::success;
    uint16 server_cs = 0;

    auto& protection = session->get_tls_protection();
    ret = protection.negotiate(session, minspec, maxspec, server_cs, server_version);
    return ret;
}

static uint16 test_read_u16(const binary_t& bin, size_t pos) { return (uint16)(((uint16)bin[pos] << 8) | bin[pos + 1]); }

static uint32 test_read_u24(const binary_t& bin, size_t pos) { return ((uint32)bin[pos] << 16) | ((uint32)bin[pos + 1] << 8) | (uint32)bin[pos + 2]; }

static void test_write_u16(binary_t& bin, size_t pos, uint16 value) {
    bin[pos] = (byte_t)(value >> 8);
    bin[pos + 1] = (byte_t)value;
}

static void test_write_u24(binary_t& bin, size_t pos, uint32 value) {
    bin[pos] = (byte_t)(value >> 16);
    bin[pos + 1] = (byte_t)(value >> 8);
    bin[pos + 2] = (byte_t)value;
}

static bool test_rewrite_client_hello_supported_versions(binary_t& bin, uint8 vector_len, const binary_t& versions) {
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

static bool test_remove_client_hello_supported_versions(binary_t& bin) {
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

static void test_client_supported_versions_vector(const char* name, uint8 vector_len, const binary_t& versions, bool expect_success) {
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

static void test_serverhello_unoffered_supported_version() {
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

static void test_supported_versions_negative_paths() {
    test_client_supported_versions_vector("supported_versions vector length 2 boundary", 2, binary_t{0x03, 0x04}, true);
    test_client_supported_versions_vector("supported_versions vector length 0", 0, binary_t(), false);
    test_client_supported_versions_vector("supported_versions vector length 1", 1, binary_t{0x03}, false);
    test_client_supported_versions_vector("supported_versions odd vector length 3", 3, binary_t{0x03, 0x04, 0x03}, false);

    binary_t versions_254;
    for (uint16 i = 0; i < 127; ++i) {
        uint16 version = (uint16)(0x7f00 + i);
        versions_254.push_back((byte_t)(version >> 8));
        versions_254.push_back((byte_t)version);
    }
    test_client_supported_versions_vector("supported_versions vector length 254 boundary", 254, versions_254, true);

    binary_t versions_255(255, (byte_t)0x7f);
    test_client_supported_versions_vector("supported_versions vector length 255", 255, versions_255, false);
    test_client_supported_versions_vector("supported_versions declared length exceeds available bytes", 4, binary_t{0x03, 0x04}, false);
    test_client_supported_versions_vector("supported_versions has trailing bytes beyond declared vector", 2, binary_t{0x03, 0x04, 0x03, 0x04}, false);

    test_serverhello_unoffered_supported_version();
}

static void test_tls13_certificate_verify_signature_policy() {
    _test_case.begin("TLS 1.3 CertificateVerify signature scheme policy");

    protection_context context;
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pkcs1_sha256);
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pss_rsae_sha256);
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pkcs1_sha384);
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pkcs1_sha512);
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pkcs1_sha1);
    context.add_signature_algorithm(tls_sigscheme_t::rsa_pss_pss_sha256);
    context.add_signature_algorithm(tls_sigscheme_t::ecdsa_secp256r1_sha256);
    context.add_signature_algorithm(tls_sigscheme_t::ecdsa_secp384r1_sha384);
    context.add_certificate_request_signature_algorithm(tls_sigscheme_t::ecdsa_secp256r1_sha256);

    _test_case.assert(context.is_signature_algorithm_offered(tls_sigscheme_t::rsa_pkcs1_sha256), __FUNCTION__, "recognize offered scheme");
    _test_case.assert(false == context.is_signature_algorithm_offered(tls_sigscheme_t::rsa_pss_rsae_sha384), __FUNCTION__, "reject unoffered scheme");

    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha256, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "TLS 1.3 rejects RSA-PKCS1 CertificateVerify");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha384, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "TLS 1.3 rejects RSA-PKCS1 SHA-384 CertificateVerify");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha512, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "TLS 1.3 rejects RSA-PKCS1 SHA-512 CertificateVerify");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha1, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "TLS 1.3 rejects SHA-1 CertificateVerify");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha1, kty_rsa, nid_rsa, false), __FUNCTION__,
                      "disabled SHA-1 remains unsupported outside TLS 1.3");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pkcs1_sha256, kty_rsa, nid_rsa, false), __FUNCTION__,
                      "retain legacy RSA-PKCS1 compatibility outside TLS 1.3");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pss_rsae_sha256, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "accept RSAE-PSS with RSA key");
    _test_case.assert(context.is_signature_algorithm_allowed(tls_sigscheme_t::rsa_pss_rsae_sha256, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "allow offered compatible RSAE-PSS scheme");
    _test_case.assert(false == context.is_signature_algorithm_allowed(tls_sigscheme_t::rsa_pss_rsae_sha384, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "reject unoffered RSAE-PSS scheme");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pss_rsae_sha384, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "retain locally valid server fallback scheme outside the peer offer");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pss_pss_sha256, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "reject PSS-key scheme with rsaEncryption key");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::rsa_pss_pss_sha256, kty_rsapss, NID_rsassaPss, true), __FUNCTION__,
                      "accept PSS-key scheme with RSASSA-PSS key");
    _test_case.assert(false == context.is_signature_algorithm_compatible(tls_sigscheme_t::ecdsa_secp384r1_sha384, kty_ec, NID_X9_62_prime256v1, true), __FUNCTION__,
                      "reject ECDSA curve mismatch");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::ecdsa_secp256r1_sha256, kty_ec, NID_X9_62_prime256v1, true), __FUNCTION__,
                      "accept matching ECDSA curve");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::ed25519, kty_eddsa, NID_ED25519, true), __FUNCTION__,
                      "accept Ed25519 key type and identifier");
    _test_case.assert(context.is_signature_algorithm_compatible(tls_sigscheme_t::ed448, kty_eddsa, NID_ED448, true), __FUNCTION__,
                      "accept Ed448 key type and identifier");
    _test_case.assert(tls_sigscheme_t::rsa_pss_rsae_sha256 == context.select_signature_algorithm(kty_rsa, nid_rsa, true), __FUNCTION__,
                      "select first TLS 1.3-compatible RSA scheme");
    _test_case.assert(context.has_certificate_request_signature_algorithms(), __FUNCTION__, "retain separate CertificateRequest offer");
    _test_case.assert(context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::ecdsa_secp256r1_sha256), __FUNCTION__,
                      "recognize CertificateRequest scheme");
    _test_case.assert(false == context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::rsa_pss_rsae_sha256), __FUNCTION__,
                      "do not mix ClientHello offer into CertificateRequest offer");
    _test_case.assert(context.is_certificate_request_signature_algorithm_allowed(tls_sigscheme_t::ecdsa_secp256r1_sha256, kty_ec, NID_X9_62_prime256v1, true),
                      __FUNCTION__, "allow offered compatible client CertificateVerify scheme");
    _test_case.assert(false == context.is_certificate_request_signature_algorithm_allowed(tls_sigscheme_t::rsa_pss_rsae_sha256, kty_rsa, nid_rsa, true), __FUNCTION__,
                      "reject unoffered client CertificateVerify scheme");
    _test_case.assert(tls_sigscheme_t::ecdsa_secp256r1_sha256 == context.select_certificate_request_signature_algorithm(kty_ec, NID_X9_62_prime256v1, true), __FUNCTION__,
                      "select client CertificateVerify scheme from CertificateRequest");
    protection_context no_offer;
    _test_case.assert(tls_sigscheme_t::unknown == no_offer.select_signature_algorithm(kty_rsa, nid_rsa, true), __FUNCTION__,
                      "do not select a server scheme when ClientHello has no offer");
    _test_case.assert(tls_sigscheme_t::unknown == no_offer.select_certificate_request_signature_algorithm(kty_rsa, nid_rsa, true), __FUNCTION__,
                      "do not select a client scheme when CertificateRequest has no offer");
}

static void test_tls13_certificate_request_signature_algorithms() {
    _test_case.begin("TLS 1.3 CertificateRequest signature_algorithms context");

    tls_session writer;
    writer.get_tls_protection().set_tls_version(tls_13);
    writer.get_tls_protection().get_protection_context().add_signature_algorithm(tls_sigscheme_t::ecdsa_secp256r1_sha256);
    tls_handshake_certificate_request request(&writer);
    auto algorithms = new tls_extension_signature_algorithms(&request);
    algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256).add(tls_sigscheme_t::rsa_pss_rsae_sha384);
    request.get_extensions().add(algorithms);

    binary_t encoded;
    return_t ret = request.write(from_server, encoded);
    _test_case.test(ret, __FUNCTION__, "serialize CertificateRequest with signature_algorithms");
    if (errorcode_t::success != ret) {
        return;
    }
    auto& writer_context = writer.get_tls_protection().get_protection_context();
    _test_case.assert(writer_context.is_signature_algorithm_offered(tls_sigscheme_t::ecdsa_secp256r1_sha256), __FUNCTION__,
                      "preserve ClientHello offer while writing CertificateRequest");
    _test_case.assert(writer_context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::rsa_pss_rsae_sha256), __FUNCTION__,
                      "record CertificateRequest offer on write");

    tls_session reader;
    reader.get_tls_protection().set_tls_version(tls_13);
    reader.get_tls_protection().get_protection_context().add_signature_algorithm(tls_sigscheme_t::ecdsa_secp256r1_sha256);
    size_t pos = 0;
    auto parsed = tls_handshake::read(&reader, from_server, encoded.data(), encoded.size(), pos);
    _test_case.assert(nullptr != parsed, __FUNCTION__, "parse CertificateRequest");
    if (nullptr == parsed) {
        return;
    }

    auto& context = reader.get_tls_protection().get_protection_context();
    _test_case.assert(context.has_signature_algorithms(), __FUNCTION__, "preserve original ClientHello algorithm list");
    _test_case.assert(context.is_signature_algorithm_offered(tls_sigscheme_t::ecdsa_secp256r1_sha256), __FUNCTION__,
                      "preserve ClientHello offer after CertificateRequest");
    _test_case.assert(context.has_certificate_request_signature_algorithms(), __FUNCTION__, "retain CertificateRequest algorithm list");
    _test_case.assert(context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::rsa_pss_rsae_sha256), __FUNCTION__,
                      "retain first CertificateRequest algorithm");
    _test_case.assert(context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::rsa_pss_rsae_sha384), __FUNCTION__,
                      "retain second CertificateRequest algorithm");
    _test_case.assert(false == context.is_certificate_request_signature_algorithm_offered(tls_sigscheme_t::rsa_pkcs1_sha256), __FUNCTION__,
                      "do not invent an unoffered algorithm");
    _test_case.assert(tls_sigscheme_t::ecdsa_secp256r1_sha256 == context.select_signature_algorithm(kty_ec, NID_X9_62_prime256v1, true), __FUNCTION__,
                      "server CertificateVerify still selects from ClientHello after CertificateRequest");
    _test_case.assert(tls_sigscheme_t::rsa_pss_rsae_sha256 == context.select_certificate_request_signature_algorithm(kty_rsa, nid_rsa, true), __FUNCTION__,
                      "client CertificateVerify selects from CertificateRequest");
    parsed->release();

    tls_session missing;
    missing.get_tls_protection().set_tls_version(tls_13);
    binary_t malformed{0x0d, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    pos = 0;
    parsed = tls_handshake::read(&missing, from_server, malformed.data(), malformed.size(), pos);
    _test_case.assert(nullptr == parsed, __FUNCTION__, "reject CertificateRequest without signature_algorithms");
    bool missing_extension = false;
    missing.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::missing_extension == desc) {
            missing_extension = true;
        }
    });
    _test_case.assert(missing_extension, __FUNCTION__, "queue missing_extension alert");

    const auto test_bad_vector = [&](const char* name, const binary_t& extension_body) -> void {
        _test_case.begin(name);
        binary_t body{0x00};  // empty certificate_request_context
        uint16 extensions_len = (uint16)(4 + extension_body.size());
        binary_append(body, extensions_len, hton16);
        binary_append(body, (uint16)tls_extension_type_t::signature_algorithms, hton16);
        binary_append(body, (uint16)extension_body.size(), hton16);
        binary_append(body, extension_body);

        binary_t message;
        message.push_back((byte_t)tls_handshake_type_t::certificate_request);
        message.push_back((byte_t)(body.size() >> 16));
        message.push_back((byte_t)(body.size() >> 8));
        message.push_back((byte_t)body.size());
        binary_append(message, body);

        tls_session malformed_session;
        malformed_session.get_tls_protection().set_tls_version(tls_13);
        size_t malformed_pos = 0;
        auto malformed_handshake = tls_handshake::read(&malformed_session, from_server, message.data(), message.size(), malformed_pos);
        _test_case.assert(nullptr == malformed_handshake, __FUNCTION__, "reject malformed SignatureSchemeList");
        bool decode_error = false;
        malformed_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::decode_error == desc) {
                decode_error = true;
            }
        });
        _test_case.assert(decode_error, __FUNCTION__, "queue decode_error alert");
    };

    test_bad_vector("CertificateRequest empty SignatureSchemeList", binary_t{0x00, 0x00});
    test_bad_vector("CertificateRequest odd SignatureSchemeList length", binary_t{0x00, 0x01, 0x08});
    test_bad_vector("CertificateRequest truncated SignatureSchemeList", binary_t{0x00, 0x04, 0x08, 0x04});
    test_bad_vector("CertificateRequest trailing SignatureSchemeList bytes", binary_t{0x00, 0x02, 0x08, 0x04, 0x00});

    _test_case.begin("CertificateRequest extension vector declared-length mismatch");
    binary_t bad_body{0x00};
    binary_append(bad_body, (uint16)8, hton16);  // declares 8 bytes; only 7 follow
    binary_append(bad_body, (uint16)tls_extension_type_t::signature_algorithms, hton16);
    binary_append(bad_body, (uint16)3, hton16);
    binary_append(bad_body, binary_t{0x00, 0x01, 0x08});
    binary_t bad_message{(byte_t)tls_handshake_type_t::certificate_request, 0x00, 0x00, (byte_t)bad_body.size()};
    binary_append(bad_message, bad_body);
    tls_session bad_length_session;
    bad_length_session.get_tls_protection().set_tls_version(tls_13);
    size_t bad_length_pos = 0;
    auto bad_length_handshake = tls_handshake::read(&bad_length_session, from_server, bad_message.data(), bad_message.size(), bad_length_pos);
    _test_case.assert(nullptr == bad_length_handshake, __FUNCTION__, "reject mismatched CertificateRequest extensions length");
    bool outer_decode_error = false;
    bad_length_session.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level && tls_alertdesc_t::decode_error == desc) {
            outer_decode_error = true;
        }
    });
    _test_case.assert(outer_decode_error, __FUNCTION__, "queue decode_error for outer extension length mismatch");

    tls_session no_extension_session;
    no_extension_session.get_tls_protection().set_tls_version(tls_13);
    tls_handshake_certificate_request no_extension_request(&no_extension_session);
    binary_t no_extension_wire;
    ret = no_extension_request.write(from_server, no_extension_wire);
    _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse to write CertificateRequest without signature_algorithms");
}

class testable_tls_handshake_certificate_verify : public tls_handshake_certificate_verify {
   public:
    explicit testable_tls_handshake_certificate_verify(tls_session* session) : tls_handshake_certificate_verify(session) {}
    return_t sign_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t& scheme, binary_t& signature) {
        return sign_certverify(pkey, dir, scheme, signature);
    }
    return_t verify_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t scheme, const binary_t& signature) {
        return verify_certverify(pkey, dir, scheme, signature);
    }
};

static void test_tls13_certificate_verify_signature_failure() {
    _test_case.begin("TLS 1.3 CertificateVerify invalid signature queues decrypt_error");

    EVP_PKEY_CTX* keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    bool key_generated =
        (nullptr != keygen) && (1 == EVP_PKEY_keygen_init(keygen)) && (1 == EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048)) && (1 == EVP_PKEY_keygen(keygen, &pkey));
    if (nullptr != keygen) {
        EVP_PKEY_CTX_free(keygen);
    }
    _test_case.assert(key_generated, __FUNCTION__, "generate RSA test key");
    if (false == key_generated) {
        if (nullptr != pkey) {
            EVP_PKEY_free(pkey);
        }
        return;
    }

    const tls_sigscheme_t expected_scheme = tls_sigscheme_t::rsa_pss_rsae_sha256;
    tls_session signer;
    signer.get_tls_protection().set_tls_version(tls_13);
    signer.get_tls_protection().get_protection_context().add_signature_algorithm(expected_scheme);

    testable_tls_handshake_certificate_verify signing_handshake(&signer);
    tls_sigscheme_t scheme = tls_sigscheme_t::unknown;
    binary_t signature;
    return_t ret = signing_handshake.sign_for_test(pkey, from_server, scheme, signature);
    _test_case.test(ret, __FUNCTION__, "create valid CertificateVerify signature");
    _test_case.assert(expected_scheme == scheme, __FUNCTION__, "select offered RSA-PSS scheme");
    if (errorcode_t::success != ret) {
        EVP_PKEY_free(pkey);
        return;
    }

    tls_session verifier;
    verifier.get_tls_protection().set_tls_version(tls_13);
    verifier.get_tls_protection().get_protection_context().add_signature_algorithm(expected_scheme);
    testable_tls_handshake_certificate_verify verifying_handshake(&verifier);

    ret = verifying_handshake.verify_for_test(pkey, from_server, scheme, signature);
    _test_case.test(ret, __FUNCTION__, "accept an intact CertificateVerify signature");
    std::set<tls_alertdesc_t> valid_alerts;
    verifier.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            valid_alerts.insert(desc);
        }
    });
    _test_case.assert(valid_alerts.empty(), __FUNCTION__, "do not queue a fatal alert for a valid signature");

    binary_t tampered_signature(signature);
    if (tampered_signature.empty()) {
        _test_case.assert(false, __FUNCTION__, "generated signature is non-empty");
        EVP_PKEY_free(pkey);
        return;
    }
    tampered_signature[0] ^= 0x01;

    tls_session tampered_verifier;
    tampered_verifier.get_tls_protection().set_tls_version(tls_13);
    tampered_verifier.get_tls_protection().get_protection_context().add_signature_algorithm(expected_scheme);
    testable_tls_handshake_certificate_verify tampered_handshake(&tampered_verifier);

    ret = tampered_handshake.verify_for_test(pkey, from_server, scheme, tampered_signature);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a modified CertificateVerify signature");

    std::set<tls_alertdesc_t> fatal_alerts;
    tampered_verifier.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::decrypt_error}, __FUNCTION__, "queue only fatal decrypt_error");

    // Exercise the actual CertificateVerify handshake reader, not only verify_certverify().
    const auto make_wire_message = [&](const binary_t& wire_signature) -> binary_t {
        binary_t message;
        message.push_back((byte_t)tls_handshake_type_t::certificate_verify);
        message.push_back(0);
        message.push_back(0);
        message.push_back(0);
        binary_append(message, (uint16)scheme, hton16);
        binary_append(message, (uint16)wire_signature.size(), hton16);
        binary_append(message, wire_signature);
        uint32 body_size = (uint32)(message.size() - 4);
        message[1] = (byte_t)(body_size >> 16);
        message[2] = (byte_t)(body_size >> 8);
        message[3] = (byte_t)body_size;
        return message;
    };

    tls_session wire_valid_verifier;
    wire_valid_verifier.get_tls_protection().set_tls_version(tls_13);
    wire_valid_verifier.get_tls_protection().get_protection_context().add_signature_algorithm(expected_scheme);
    wire_valid_verifier.update_session_status(session_status_server_cert);
    wire_valid_verifier.get_tls_protection().get_key().add(pkey, KID_TLS_SERVER_CERTIFICATE_PUBLIC, crypto_use_t::use_sig, true);
    binary_t valid_wire_message = make_wire_message(signature);
    size_t wire_pos = 0;
    auto parsed = tls_handshake::read(&wire_valid_verifier, from_server, valid_wire_message.data(), valid_wire_message.size(), wire_pos);
    _test_case.assert(nullptr != parsed, __FUNCTION__, "accept intact signature through CertificateVerify reader");
    if (nullptr != parsed) {
        parsed->release();
    }
    std::set<tls_alertdesc_t> wire_valid_alerts;
    wire_valid_verifier.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            wire_valid_alerts.insert(desc);
        }
    });
    _test_case.assert(wire_valid_alerts.empty(), __FUNCTION__, "valid CertificateVerify reader path queues no fatal alert");

    tls_session wire_verifier;
    wire_verifier.get_tls_protection().set_tls_version(tls_13);
    wire_verifier.get_tls_protection().get_protection_context().add_signature_algorithm(expected_scheme);
    wire_verifier.update_session_status(session_status_server_cert);
    wire_verifier.get_tls_protection().get_key().add(pkey, KID_TLS_SERVER_CERTIFICATE_PUBLIC, crypto_use_t::use_sig, true);
    binary_t tampered_wire_message = make_wire_message(tampered_signature);
    wire_pos = 0;
    parsed = tls_handshake::read(&wire_verifier, from_server, tampered_wire_message.data(), tampered_wire_message.size(), wire_pos);
    _test_case.assert(nullptr == parsed, __FUNCTION__, "reject modified signature through CertificateVerify reader");
    std::set<tls_alertdesc_t> wire_fatal_alerts;
    size_t wire_fatal_alert_count = 0;
    wire_verifier.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++wire_fatal_alert_count;
            wire_fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(wire_fatal_alert_count == 1 && wire_fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::decrypt_error}, __FUNCTION__,
                      "CertificateVerify reader queues exactly one fatal decrypt_error");

    EVP_PKEY_free(pkey);
}

static void test_tls13_empty_certificate_list_direction_policy() {
    _test_case.begin("TLS 1.3 empty Certificate list direction policy");

    const binary_t empty_certificate_message{(byte_t)tls_handshake_type_t::certificate, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};

    tls_session server_reader;
    server_reader.get_tls_protection().set_tls_version(tls_13);
    server_reader.update_session_status(session_status_client_hello);
    server_reader.update_session_status(session_status_server_hello);
    server_reader.update_session_status(session_status_encrypted_extensions);

    size_t pos = 0;
    auto parsed = tls_handshake::read(&server_reader, from_server, empty_certificate_message.data(), empty_certificate_message.size(), pos);
    _test_case.assert(nullptr == parsed, __FUNCTION__, "reject an empty server Certificate list");

    size_t fatal_alert_count = 0;
    bool decode_error = false;
    server_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
            decode_error = (tls_alertdesc_t::decode_error == desc);
        }
    });
    _test_case.assert(1 == fatal_alert_count && decode_error, __FUNCTION__, "queue exactly one fatal decode_error");
    _test_case.assert(0 == server_reader.get_session_status(), __FUNCTION__, "reset handshake state and do not mark server certificate state after rejection");

    tls_session request_writer;
    request_writer.get_tls_protection().set_tls_version(tls_13);
    tls_handshake_certificate_request request(&request_writer);
    auto algorithms = new tls_extension_signature_algorithms(&request);
    algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
    request.get_extensions().add(algorithms);
    binary_t request_message;
    return_t ret = request.write(from_server, request_message);
    _test_case.test(ret, __FUNCTION__, "construct CertificateRequest for client authentication");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session client_reader;
    client_reader.get_tls_protection().set_tls_version(tls_13);
    client_reader.update_session_status(session_status_client_hello);
    client_reader.update_session_status(session_status_server_hello);
    client_reader.update_session_status(session_status_encrypted_extensions);

    pos = 0;
    auto parsed_request = tls_handshake::read(&client_reader, from_server, request_message.data(), request_message.size(), pos);
    _test_case.assert(nullptr != parsed_request, __FUNCTION__, "receive CertificateRequest before client Certificate");
    if (nullptr == parsed_request) {
        return;
    }
    parsed_request->release();

    pos = 0;
    parsed = tls_handshake::read(&client_reader, from_client, empty_certificate_message.data(), empty_certificate_message.size(), pos);
    _test_case.assert(nullptr != parsed, __FUNCTION__, "allow an empty client Certificate list in response to CertificateRequest");
    if (nullptr != parsed) {
        parsed->release();
    }
    _test_case.assert(0 != (client_reader.get_session_status() & session_status_client_cert), __FUNCTION__, "complete the client Certificate message state transition");
    size_t client_fatal_alert_count = 0;
    client_reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++client_fatal_alert_count;
        }
    });
    _test_case.assert(0 == client_fatal_alert_count, __FUNCTION__, "do not queue a fatal alert for an empty client Certificate list");
}

static void test_supported_versions_unknown_and_legacy_fallback() {
    _test_case.begin("supported_versions ignores unknown values and preserves TLS 1.2 fallback");

    tls_session mixed_client;
    tls_session mixed_server;
    binary_t mixed_client_hello;
    return_t ret = test_client_supportedversion_clienthello(&mixed_client, tls_12, tls_13, mixed_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct mixed-version ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Unknown versions surrounding known TLS 1.3 and TLS 1.2 values must be ignored.
    const binary_t mixed_versions{0x7f, 0x1c, 0x03, 0x04, 0x7f, 0x1d, 0x03, 0x03};
    bool rewritten = test_rewrite_client_hello_supported_versions(mixed_client_hello, (uint8)mixed_versions.size(), mixed_versions);
    _test_case.assert(rewritten, __FUNCTION__, "write mixed known/unknown supported_versions");
    if (false == rewritten) {
        return;
    }

    tls_records records;
    ret = records.read(&mixed_server, from_client, mixed_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse mixed known/unknown supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_version_t selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&mixed_server, tls_12, tls_13, selected);
    _test_case.test(ret, __FUNCTION__, "negotiate from mixed known/unknown versions");
    _test_case.assert(tls_13 == selected, __FUNCTION__, "select highest locally supported version offered by peer");

    tls_session unknown_client;
    tls_session unknown_server;
    binary_t unknown_client_hello;
    ret = test_client_supportedversion_clienthello(&unknown_client, tls_12, tls_13, unknown_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct unknown-only ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Unknown values are ignored; with no mutually supported version, negotiation fails.
    const binary_t unknown_versions{0x7f, 0x1c, 0x7f, 0x1d};
    rewritten = test_rewrite_client_hello_supported_versions(unknown_client_hello, (uint8)unknown_versions.size(), unknown_versions);
    _test_case.assert(rewritten, __FUNCTION__, "write unknown-only supported_versions");
    if (false == rewritten) {
        return;
    }

    tls_records unknown_records;
    ret = unknown_records.read(&unknown_server, from_client, unknown_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse unknown-only supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&unknown_server, tls_12, tls_13, selected);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "fail when no mutually supported version remains");

    tls_session legacy_client;
    tls_session legacy_server;
    binary_t legacy_client_hello;
    ret = test_client_supportedversion_clienthello(&legacy_client, tls_12, tls_13, legacy_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct ClientHello for legacy fallback");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(0x0303 == test_read_u16(legacy_client_hello, 9), __FUNCTION__, "ClientHello legacy_version is TLS 1.2");
    bool removed = test_remove_client_hello_supported_versions(legacy_client_hello);
    _test_case.assert(removed, __FUNCTION__, "remove supported_versions extension");
    if (false == removed) {
        return;
    }

    tls_records legacy_records;
    ret = legacy_records.read(&legacy_server, from_client, legacy_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello without supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&legacy_server, tls_12, tls_13, selected);
    _test_case.test(ret, __FUNCTION__, "negotiate using legacy_version fallback");
    _test_case.assert(tls_12 == selected, __FUNCTION__, "fall back to TLS 1.2 when supported_versions is absent");
}

// TLS-IG-23: TLS 1.3 TLSInnerPlaintext content type and zero-padding handling.
class test_tls13_inner_plaintext_writer : public tls_record_application_data {
   public:
    using tls_record_application_data::tls_record_application_data;

    return_t write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record) { return do_write_header(dir, record, plaintext); }
};

static void test_configure_tls13_inner_plaintext_session(tls_session& session, bool server_finished = false, bool client_finished = true) {
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

static return_t test_read_tls13_inner_plaintext(const binary_t& plaintext, tls_direction_t dir, tls_session& reader, tls_records& records) {
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

static return_t test_read_tls13_application_data_with_finished_status(tls_direction_t dir, bool server_finished, bool client_finished, tls_session& reader,
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

static void test_tls13_inner_plaintext_padding_and_content_type() {
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

// TLS-IG-24: TLS record plaintext and ciphertext size limits.
class test_tls_record_size_probe : public tls_record_application_data {
   public:
    using tls_record_application_data::tls_record_application_data;

    return_t read_record_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return do_read_header(dir, stream, size, pos); }

    return_t write_record_fragment(tls_direction_t dir, binary_t& record, const binary_t& fragment) { return do_write_header_internal(dir, record, fragment); }

    return_t write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record) { return do_write_header(dir, record, plaintext); }
    return_t validate_plaintext_size(tls_direction_t dir, size_t size) { return validate_record_size_limit(dir, size); }
};

static void test_configure_tls_record_size_session(tls_session& session, tls_version_t version, bool protected_record) {
    session.get_tls_protection().set_tls_version(version);
    if (protected_record) {
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).begin_protection();
    }
}

static return_t test_read_tls_record_header_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session) {
    test_configure_tls_record_size_session(session, version, protected_record);
    test_tls_record_size_probe record(&session);
    binary_t header{(byte_t)tls_content_type_t::application_data, 0x03, 0x03, (byte_t)(length >> 8), (byte_t)length};
    size_t pos = 0;
    return record.read_record_header(from_client, header.data(), header.size(), pos);
}

static return_t test_read_tls_record_fragment_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session, tls_records& records) {
    test_configure_tls_record_size_session(session, version, protected_record);
    session.update_session_status(session_status_server_hello);
    binary_t header{(byte_t)tls_content_type_t::application_data, 0x03, 0x03, (byte_t)(length >> 8), (byte_t)length};
    return records.read(&session, from_client, header);
}

static return_t test_write_tls_record_fragment_size(tls_version_t version, bool protected_record, size_t length) {
    tls_session session;
    test_configure_tls_record_size_session(session, version, protected_record);
    test_tls_record_size_probe record(&session);
    binary_t fragment(length, 0x5a);
    binary_t wire;
    return record.write_record_fragment(from_client, wire, fragment);
}

static return_t test_write_tls_record_header_path(tls_version_t version, size_t length) {
    tls_session session;
    test_configure_tls_record_size_session(session, version, false);
    test_tls_record_size_probe record(&session);
    binary_t fragment(length, 0x5a);
    binary_t wire;
    return record.write_inner_plaintext(from_client, fragment, wire);
}

static void test_tls_record_size_limits() {
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

static void test_configure_dtls13_ccm8_session(tls_session& session) {
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

static void test_dtls13_plaintext_content_type_demux() {
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

class test_tls13_failing_client_hello : public tls_handshake_client_hello {
   public:
    explicit test_tls13_failing_client_hello(tls_session* session) : tls_handshake_client_hello(session), _preprocess_called(false) {}

    bool preprocess_called() const { return _preprocess_called; }

   protected:
    virtual return_t do_preprocess(tls_direction_t dir) {
        _preprocess_called = true;
        return errorcode_t::unexpected;
    }

   private:
    bool _preprocess_called;
};

class test_tls13_server_hello_phase_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_phase_probe(tls_session* session) : tls_handshake_server_hello(session) {}

    return_t validate_phase(tls_direction_t dir) { return do_preprocess(dir); }
};

class test_tls13_server_hello_postprocess_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_postprocess_probe(tls_session* session) : tls_handshake_server_hello(session) {}

    return_t postprocess_read() {
        // do_postprocess consumes the already-decoded ServerHello state. The
        // four-byte buffer is sufficient here because this probe deliberately
        // leaves the encoded ServerHello body empty.
        byte_t stream[4] = {0, 0, 0, 0};
        return do_postprocess(from_server, tls_io_operation_t::read, stream, sizeof(stream));
    }
};

class test_tls13_server_hello_writer_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_writer_probe(tls_session* session) : tls_handshake_server_hello(session), _postprocessed(false) {}

    bool postprocessed() const { return _postprocessed; }

    bool serialized_body_valid() const {
        // The captured stream includes the four-byte Handshake header.
        if ((_serialized.size() < 50) || (_serialized[0] != (byte_t)tls_handshake_type_t::server_hello)) {
            return false;
        }
        uint32 handshake_size = ((uint32)_serialized[1] << 16) | ((uint32)_serialized[2] << 8) | _serialized[3];
        if (handshake_size != _serialized.size() - 4) {
            return false;
        }

        size_t pos = 4;
        if ((_serialized[pos++] != 0x03) || (_serialized[pos++] != 0x03)) {  // legacy_version = TLS 1.2
            return false;
        }
        pos += 32;  // Random
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
        if ((cipher_suite != 0x1301) || (_serialized[pos++] != 0)) {  // TLS_AES_128_GCM_SHA256, null compression
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
            if (extension_type == 0x002b) {  // supported_versions
                if ((extension_size != 2) || (_serialized[pos] != 0x03) || (_serialized[pos + 1] != 0x04)) {
                    return false;
                }
                supported_versions_found = true;
            }
            pos += extension_size;
        }
        return supported_versions_found;
    }

   protected:
    // Keep the phase transition isolated from key-schedule setup, but use the
    // production ServerHello body serializer.
    virtual return_t do_postprocess(tls_direction_t, tls_io_operation_t, const byte_t* stream, size_t size) {
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

   private:
    bool _postprocessed;
    binary_t _serialized;
};

// TLS-IG-25: TLS 1.3 handshake protection starts after ServerHello, without relying on CCS.
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

// TLS-IG-25: TLS 1.3 early data is protected after ClientHello; compatibility CCS is ignored.
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

static void test_tls_record_size_limit_extension() {
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

void testcase_gpt() {
    test_supported_versions_negative_paths();
    test_tls13_certificate_verify_signature_policy();
    test_tls13_certificate_verify_signature_failure();
    test_tls13_certificate_request_signature_algorithms();
    test_tls13_empty_certificate_list_direction_policy();
    test_supported_versions_unknown_and_legacy_fallback();
    test_tls13_inner_plaintext_padding_and_content_type();
    test_tls13_application_data_finished_direction_policy();
    test_tls_record_size_limits();
    test_dtls_record_publisher_segment_boundary();
    test_dtls_record_publisher_pmtu_api();
    test_dtls13_plaintext_content_type_demux();
    test_dtls13_minimum_ciphertext_sample();
    test_tls_record_size_limit_extension();
    test_tls13_handshake_protection_transition();
    test_tls13_early_data_and_compatibility_ccs();
    test_finished_record_sequence_transition();
    test_tls13_finished_record_boundary();
    test_tls13_finished_application_epoch_integration();
    test_tls12_finished_record_sequence_integration();
}
