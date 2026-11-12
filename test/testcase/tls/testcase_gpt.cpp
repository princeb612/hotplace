/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_rfc.cpp
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

void testcase_gpt() {
    test_supported_versions_negative_paths();
    test_tls13_certificate_verify_signature_policy();
    test_tls13_certificate_verify_signature_failure();
    test_tls13_certificate_request_signature_algorithms();
    test_tls13_empty_certificate_list_direction_policy();
    test_supported_versions_unknown_and_legacy_fallback();
}
