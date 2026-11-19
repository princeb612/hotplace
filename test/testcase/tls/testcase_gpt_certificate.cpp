/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_certificate.cpp
 * @author GPT
 * @desc   TLS 1.3 CertificateRequest, CertificateVerify, and certificate-authentication policy tests.
 */

#include "testcase_gpt_common.hpp"

static void test_tls13_certificate_verify_signature_policy() {
    // Scenario under test: TLS 1.3 CertificateVerify signature scheme policy.
    // Expected: recognize offered scheme.
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

static void test_tls13_certificate_verify_signature_failure() {
    // Scenario under test: TLS 1.3 CertificateVerify invalid signature queues decrypt_error.
    // Action: create valid CertificateVerify signature.
    // Expected: generate RSA test key.
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

    // No peer signature_algorithms offer means the local endpoint cannot
    // select a CertificateVerify scheme. The fatal alert must be reflected
    // by a severe handshake_failure return code, not warning not_supported.
    tls_session unsupported_signer;
    unsupported_signer.get_tls_protection().set_tls_version(tls_13);
    unsupported_signer.get_tls_protection().get_key().add(pkey, KID_TLS_SERVER_CERTIFICATE_PRIVATE, crypto_use_t::use_sig, true);
    testable_tls_handshake_certificate_verify unsupported_handshake(&unsupported_signer);
    binary_t unsupported_body;
    return_t unsupported_ret = unsupported_handshake.write_for_test(from_server, unsupported_body);
    _test_case.assert(errorcode_t::handshake_failure == unsupported_ret, __FUNCTION__, "map unsupported CertificateVerify signing to severe handshake_failure");
    std::set<tls_alertdesc_t> unsupported_alerts;
    unsupported_signer.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            unsupported_alerts.insert(desc);
        }
    });
    _test_case.assert(unsupported_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::handshake_failure}, __FUNCTION__,
                      "queue exactly fatal handshake_failure when no signing scheme is selectable");

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

static void test_tls13_certificate_request_signature_algorithms() {
    // Scenario under test: TLS 1.3 CertificateRequest signature_algorithms context.
    // Action: serialize CertificateRequest with signature_algorithms.
    // Expected: preserve ClientHello offer while writing CertificateRequest.
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
        // Scenario under test: the named test-case variant.
        // Expected: reject malformed SignatureSchemeList.
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

    // Scenario under test: CertificateRequest extension vector declared-length mismatch.
    // Expected: reject mismatched CertificateRequest extensions length.
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

static void test_tls13_empty_certificate_list_direction_policy() {
    // Scenario under test: TLS 1.3 empty Certificate list direction policy.
    // Action: construct CertificateRequest for client authentication.
    // Expected: reject an empty server Certificate list.
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

static void test_tls13_post_handshake_certificate_request_gate() {
    // Scenario under test: TLS 1.3 post-handshake CertificateRequest offer gate.
    // Action: construct a valid main-handshake TLS 1.3 CertificateRequest.
    // Expected: refuse a post-handshake CertificateRequest when the client did not offer PHA.
    _test_case.begin("TLS 1.3 post-handshake CertificateRequest offer gate");

    tls_session request_writer;
    request_writer.set_type(session_type_t::tls);
    request_writer.get_tls_protection().set_tls_version(tls_13);
    tls_handshake_certificate_request request(&request_writer);
    auto algorithms = new tls_extension_signature_algorithms(&request);
    algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
    request.get_extensions().add(algorithms);

    binary_t request_message;
    return_t ret = request.write(from_server, request_message);
    _test_case.test(ret, __FUNCTION__, "construct a valid main-handshake TLS 1.3 CertificateRequest");
    if (errorcode_t::success != ret) {
        return;
    }

    // A post-handshake request is not allowed unless the client offered PHA.
    {
        tls_session no_offer_writer;
        no_offer_writer.set_type(session_type_t::tls);
        no_offer_writer.get_tls_protection().set_tls_version(tls_13);
        no_offer_writer.update_session_status(session_status_server_finished);
        no_offer_writer.update_session_status(session_status_client_finished);
        tls_handshake_certificate_request unoffered_request(&no_offer_writer);
        unoffered_request.set_request_context(binary_t{0x4e, 0x4f, 0x50, 0x48});
        auto unoffered_algorithms = new tls_extension_signature_algorithms(&unoffered_request);
        unoffered_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        unoffered_request.get_extensions().add(unoffered_algorithms);
        binary_t unoffered_message;
        ret = unoffered_request.write(from_server, unoffered_message);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse a post-handshake CertificateRequest when the client did not offer PHA");
        _test_case.assert(unoffered_message.empty(), __FUNCTION__, "do not emit an unoffered post-handshake CertificateRequest");
    }

    // A post-handshake request carries its own non-empty request context.
    request_writer.update_session_status(session_status_server_finished);
    request_writer.update_session_status(session_status_client_finished);
    request_writer.get_keyvalue().set(session_client_post_handshake_auth, 1);
    tls_handshake_certificate_request post_handshake_request(&request_writer);
    post_handshake_request.set_request_context(binary_t{0x50, 0x48, 0x41, 0x31});
    auto post_algorithms = new tls_extension_signature_algorithms(&post_handshake_request);
    post_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
    post_handshake_request.get_extensions().add(post_algorithms);
    binary_t post_handshake_request_message;
    ret = post_handshake_request.write(from_server, post_handshake_request_message);
    _test_case.test(ret, __FUNCTION__, "construct a TLS 1.3 post-handshake CertificateRequest with a request context");
    if (errorcode_t::success != ret) {
        return;
    }

    {
        tls_session premature_reader;
        premature_reader.set_type(session_type_t::tls);
        premature_reader.get_tls_protection().set_tls_version(tls_13);
        premature_reader.get_keyvalue().set(session_client_post_handshake_auth, 1);
        premature_reader.update_session_status(session_status_server_finished);
        size_t pos = 0;
        auto parsed = tls_handshake::read(&premature_reader, from_server, post_handshake_request_message.data(), post_handshake_request_message.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject post-handshake CertificateRequest before the client Finished");
        if (nullptr != parsed) {
            parsed->release();
        }
        size_t unexpected_message_count = 0;
        premature_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++unexpected_message_count;
            }
        });
        _test_case.assert(1 == unexpected_message_count, __FUNCTION__, "queue fatal unexpected_message before handshake completion");
    }

    {
        tls_session premature_writer;
        premature_writer.set_type(session_type_t::tls);
        premature_writer.get_tls_protection().set_tls_version(tls_13);
        premature_writer.get_keyvalue().set(session_client_post_handshake_auth, 1);
        premature_writer.update_session_status(session_status_server_finished);
        tls_handshake_certificate_request premature_request(&premature_writer);
        premature_request.set_request_context(binary_t{0x50, 0x52, 0x45, 0x31});
        auto algorithms = new tls_extension_signature_algorithms(&premature_request);
        algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        premature_request.get_extensions().add(algorithms);
        binary_t message;
        ret = premature_request.write(from_server, message);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse post-handshake CertificateRequest before client Finished");
        _test_case.assert(message.empty(), __FUNCTION__, "do not emit premature post-handshake CertificateRequest");
    }

    {
        tls_session main_handshake_reader;
        main_handshake_reader.set_type(session_type_t::tls);
        main_handshake_reader.get_tls_protection().set_tls_version(tls_13);
        main_handshake_reader.update_session_status(session_status_client_hello);
        main_handshake_reader.update_session_status(session_status_server_hello);
        main_handshake_reader.update_session_status(session_status_encrypted_extensions);

        size_t pos = 0;
        auto parsed = tls_handshake::read(&main_handshake_reader, from_server, request_message.data(), request_message.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "accept main-handshake CertificateRequest without post_handshake_auth");
        if (nullptr != parsed) {
            parsed->release();
        }

        size_t fatal_count = 0;
        main_handshake_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t) {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
            }
        });
        _test_case.assert(0 == fatal_count, __FUNCTION__, "do not apply the post-handshake offer gate before server Finished");
    }

    {
        tls_session post_handshake_reader;
        post_handshake_reader.set_type(session_type_t::tls);
        post_handshake_reader.get_tls_protection().set_tls_version(tls_13);
        post_handshake_reader.update_session_status(session_status_server_finished);
        post_handshake_reader.update_session_status(session_status_client_finished);

        size_t pos = 0;
        auto parsed = tls_handshake::read(&post_handshake_reader, from_server, post_handshake_request_message.data(), post_handshake_request_message.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject post-handshake CertificateRequest when the client did not offer post_handshake_auth");

        size_t fatal_count = 0;
        bool unexpected_message = false;
        post_handshake_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
                unexpected_message = (tls_alertdesc_t::unexpected_message == desc);
            }
        });
        _test_case.assert(1 == fatal_count && unexpected_message, __FUNCTION__, "queue exactly one fatal unexpected_message");
        _test_case.assert(0 == post_handshake_reader.get_session_status(), __FUNCTION__, "reset handshake state after rejecting the post-handshake request");
    }

    {
        const binary_t tls12_request{0x0d, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x02, 0x04, 0x01, 0x00, 0x00};
        tls_session tls12_reader;
        tls12_reader.set_type(session_type_t::tls);
        tls12_reader.get_tls_protection().set_tls_version(tls_12);
        tls12_reader.update_session_status(session_status_server_finished);

        size_t pos = 0;
        auto parsed = tls_handshake::read(&tls12_reader, from_server, tls12_request.data(), tls12_request.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "do not apply the TLS 1.3 post-handshake gate to TLS 1.2 CertificateRequest");
        if (nullptr != parsed) {
            parsed->release();
        }

        size_t fatal_count = 0;
        tls12_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t) {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
            }
        });
        _test_case.assert(0 == fatal_count, __FUNCTION__, "leave TLS 1.2 CertificateRequest handling unchanged");
    }

    {
        tls_session wrong_direction_reader;
        wrong_direction_reader.set_type(session_type_t::tls);
        wrong_direction_reader.get_tls_protection().set_tls_version(tls_13);
        size_t pos = 0;
        auto parsed = tls_handshake::read(&wrong_direction_reader, from_client, request_message.data(), request_message.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject a client-originated TLS 1.3 CertificateRequest");
        if (nullptr != parsed) {
            parsed->release();
        }
        size_t unexpected_message_count = 0;
        wrong_direction_reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++unexpected_message_count;
            }
        });
        _test_case.assert(1 == unexpected_message_count, __FUNCTION__, "queue fatal unexpected_message for a client-originated CertificateRequest");
    }

    {
        tls_session wrong_direction_writer;
        wrong_direction_writer.set_type(session_type_t::tls);
        wrong_direction_writer.get_tls_protection().set_tls_version(tls_13);
        tls_handshake_certificate_request request_from_client(&wrong_direction_writer);
        auto algorithms = new tls_extension_signature_algorithms(&request_from_client);
        algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        request_from_client.get_extensions().add(algorithms);
        binary_t message;
        ret = request_from_client.write(from_client, message);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse to serialize a client-originated TLS 1.3 CertificateRequest");
        _test_case.assert(message.empty(), __FUNCTION__, "do not emit a client-originated CertificateRequest");
    }

    {
        tls_session offered_reader;
        offered_reader.set_type(session_type_t::tls);
        offered_reader.get_tls_protection().set_tls_version(tls_13);
        offered_reader.get_keyvalue().set(session_client_post_handshake_auth, 1);
        offered_reader.update_session_status(session_status_server_finished);
        offered_reader.update_session_status(session_status_client_finished);

        size_t pos = 0;
        auto parsed = tls_handshake::read(&offered_reader, from_server, post_handshake_request_message.data(), post_handshake_request_message.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "do not trigger the no-offer gate when the client actually offered post_handshake_auth");
        if (nullptr != parsed) {
            parsed->release();
        }

        size_t fatal_count = 0;
        offered_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t) {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_count;
            }
        });
        _test_case.assert(0 == fatal_count, __FUNCTION__, "offered extension avoids the no-offer fatal alert");
    }

    binary_t empty_post_handshake_message;
    {
        tls_session empty_context_writer;
        empty_context_writer.set_type(session_type_t::tls);
        empty_context_writer.get_tls_protection().set_tls_version(tls_13);
        empty_context_writer.update_session_status(session_status_server_finished);
        empty_context_writer.update_session_status(session_status_client_finished);
        empty_context_writer.get_keyvalue().set(session_client_post_handshake_auth, 1);
        tls_handshake_certificate_request empty_post_handshake_request(&empty_context_writer);
        auto empty_post_algorithms = new tls_extension_signature_algorithms(&empty_post_handshake_request);
        empty_post_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        empty_post_handshake_request.get_extensions().add(empty_post_algorithms);
        ret = empty_post_handshake_request.write(from_server, empty_post_handshake_message);
        _test_case.test(ret, __FUNCTION__, "construct a post-handshake CertificateRequest with an empty request context");
        if (errorcode_t::success == ret) {
            tls_session reader;
            reader.set_type(session_type_t::tls);
            reader.get_tls_protection().set_tls_version(tls_13);
            reader.get_keyvalue().set(session_client_post_handshake_auth, 1);
            reader.update_session_status(session_status_server_finished);
            reader.update_session_status(session_status_client_finished);
            size_t pos = 0;
            auto parsed = tls_handshake::read(&reader, from_server, empty_post_handshake_message.data(), empty_post_handshake_message.size(), pos);
            _test_case.assert(nullptr != parsed, __FUNCTION__, "accept an empty request_context when it is unique within the connection");
            if (nullptr != parsed) {
                parsed->release();
            }
            size_t fatal_count = 0;
            reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t) {
                if (tls_alertlevel_t::fatal == level) {
                    ++fatal_count;
                }
            });
            _test_case.assert(0 == fatal_count, __FUNCTION__, "do not require a non-empty post-handshake request_context when unique");
        }
    }

    {
        tls_session duplicate_writer;
        duplicate_writer.set_type(session_type_t::tls);
        duplicate_writer.get_tls_protection().set_tls_version(tls_13);
        tls_handshake_certificate_request first(&duplicate_writer);
        auto first_algorithms = new tls_extension_signature_algorithms(&first);
        first_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        first.get_extensions().add(first_algorithms);
        binary_t first_message;
        ret = first.write(from_server, first_message);
        _test_case.test(ret, __FUNCTION__, "serialize the first empty CertificateRequest context");
        if (errorcode_t::success == ret) {
            tls_handshake_certificate_request duplicate(&duplicate_writer);
            auto duplicate_algorithms = new tls_extension_signature_algorithms(&duplicate);
            duplicate_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
            duplicate.get_extensions().add(duplicate_algorithms);
            binary_t duplicate_message;
            ret = duplicate.write(from_server, duplicate_message);
            _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse to serialize a duplicate CertificateRequest context");
            _test_case.assert(duplicate_message.empty(), __FUNCTION__, "do not emit bytes for a duplicate CertificateRequest context");
        }
    }

    {
        tls_session duplicate_reader;
        duplicate_reader.set_type(session_type_t::tls);
        duplicate_reader.get_tls_protection().set_tls_version(tls_13);
        duplicate_reader.update_session_status(session_status_client_hello);
        duplicate_reader.update_session_status(session_status_server_hello);
        duplicate_reader.update_session_status(session_status_encrypted_extensions);
        size_t pos = 0;
        auto first = tls_handshake::read(&duplicate_reader, from_server, request_message.data(), request_message.size(), pos);
        _test_case.assert(nullptr != first, __FUNCTION__, "accept the first empty CertificateRequest context");
        if (nullptr != first) {
            first->release();
        }
        duplicate_reader.get_keyvalue().set(session_client_post_handshake_auth, 1);
        duplicate_reader.update_session_status(session_status_server_finished);
        duplicate_reader.update_session_status(session_status_client_finished);
        pos = 0;
        auto duplicate = tls_handshake::read(&duplicate_reader, from_server, empty_post_handshake_message.data(), empty_post_handshake_message.size(), pos);
        _test_case.assert(nullptr == duplicate, __FUNCTION__, "reject a post-handshake CertificateRequest that reuses the main-handshake context");
        if (nullptr != duplicate) {
            duplicate->release();
        }
        size_t illegal_parameter_count = 0;
        duplicate_reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for a duplicate request_context");
    }

    {
        tls_session main_context_writer;
        main_context_writer.set_type(session_type_t::tls);
        main_context_writer.get_tls_protection().set_tls_version(tls_13);
        tls_handshake_certificate_request nonempty_main_request(&main_context_writer);
        nonempty_main_request.set_request_context(binary_t{0x4d, 0x41, 0x49, 0x4e});
        auto main_algorithms = new tls_extension_signature_algorithms(&nonempty_main_request);
        main_algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        nonempty_main_request.get_extensions().add(main_algorithms);
        binary_t rejected_main_message;
        ret = nonempty_main_request.write(from_server, rejected_main_message);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "refuse to serialize a non-empty main-handshake request_context");
        _test_case.assert(rejected_main_message.empty(), __FUNCTION__, "do not emit a malformed main-handshake CertificateRequest");

        binary_t nonempty_main_message = request_message;
        nonempty_main_message.insert(nonempty_main_message.begin() + 5, {0x4d, 0x41, 0x49, 0x4e});
        nonempty_main_message[4] = 4;
        uint32 main_body_size =
            (static_cast<uint32>(nonempty_main_message[1]) << 16) | (static_cast<uint32>(nonempty_main_message[2]) << 8) | static_cast<uint32>(nonempty_main_message[3]);
        main_body_size += 4;
        nonempty_main_message[1] = static_cast<byte_t>((main_body_size >> 16) & 0xff);
        nonempty_main_message[2] = static_cast<byte_t>((main_body_size >> 8) & 0xff);
        nonempty_main_message[3] = static_cast<byte_t>(main_body_size & 0xff);
        {
            tls_session reader;
            reader.set_type(session_type_t::tls);
            reader.get_tls_protection().set_tls_version(tls_13);
            reader.update_session_status(session_status_client_hello);
            reader.update_session_status(session_status_server_hello);
            reader.update_session_status(session_status_encrypted_extensions);
            size_t pos = 0;
            auto parsed = tls_handshake::read(&reader, from_server, nonempty_main_message.data(), nonempty_main_message.size(), pos);
            _test_case.assert(nullptr == parsed, __FUNCTION__, "reject a non-empty request_context in main-handshake CertificateRequest");
            if (nullptr != parsed) {
                parsed->release();
            }
            size_t decode_error_count = 0;
            reader.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
                    ++decode_error_count;
                }
            });
            _test_case.assert(1 == decode_error_count, __FUNCTION__, "queue fatal decode_error for a non-empty main-handshake request_context");
        }
    }

    {
        tls_session client;
        client.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls_13);

        tls_handshake_client_hello offered(&client);
        offered.add_ciphersuite(0x1301);
        auto offered_versions = new tls_extension_client_supported_versions(&offered);
        offered_versions->add(tls_13);
        offered.get_extensions().add(offered_versions);
        offered.get_extensions().add(new tls_extension_unknown(tls_extension_type_t::post_handshake_auth, &offered));
        binary_t offered_client_hello;
        ret = offered.write(from_client, offered_client_hello);
        _test_case.test(ret, __FUNCTION__, "serialize ClientHello with post_handshake_auth");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(1 == client.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__, "remember the extension actually offered by the client");

        tls_session server;
        server.set_type(session_type_t::tls);
        size_t server_pos = 0;
        auto server_parsed = tls_handshake::read(&server, from_client, offered_client_hello.data(), offered_client_hello.size(), server_pos);
        _test_case.assert(nullptr != server_parsed, __FUNCTION__, "parse ClientHello with post_handshake_auth on the server side");
        if (nullptr == server_parsed) {
            return;
        }
        server_parsed->release();
        _test_case.assert(1 == server.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                          "server records the client's actual post_handshake_auth offer");

        tls_handshake_client_hello not_offered(&client);
        not_offered.add_ciphersuite(0x1301);
        auto plain_versions = new tls_extension_client_supported_versions(&not_offered);
        plain_versions->add(tls_13);
        not_offered.get_extensions().add(plain_versions);
        binary_t plain_client_hello;
        ret = not_offered.write(from_client, plain_client_hello);
        _test_case.test(ret, __FUNCTION__, "serialize a subsequent ClientHello without post_handshake_auth");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0 == client.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                          "clear a previous offer when the new ClientHello omits the extension");

        tls_session server_without_offer;
        server_without_offer.set_type(session_type_t::tls);
        size_t plain_server_pos = 0;
        auto plain_server_parsed = tls_handshake::read(&server_without_offer, from_client, plain_client_hello.data(), plain_client_hello.size(), plain_server_pos);
        _test_case.assert(nullptr != plain_server_parsed, __FUNCTION__, "parse ClientHello without post_handshake_auth on the server side");
        if (nullptr == plain_server_parsed) {
            return;
        }
        plain_server_parsed->release();
        _test_case.assert(0 == server_without_offer.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                          "server records the absence of the client's post_handshake_auth offer");
    }

    // The extension is an empty marker. A non-empty body must not be treated as a valid offer.
    {
        tls_session client;
        client.set_type(session_type_t::tls);
        client.get_tls_protection().set_tls_version(tls_13);
        tls_handshake_client_hello offered(&client);
        offered.add_ciphersuite(0x1301);
        auto versions = new tls_extension_client_supported_versions(&offered);
        versions->add(tls_13);
        offered.get_extensions().add(versions);
        offered.get_extensions().add(new tls_extension_unknown(tls_extension_type_t::post_handshake_auth, &offered));
        binary_t malformed_client_hello;
        ret = offered.write(from_client, malformed_client_hello);
        _test_case.test(ret, __FUNCTION__, "construct a valid ClientHello before corrupting the PHA extension length");
        if (errorcode_t::success != ret) {
            return;
        }

        size_t extension_length_pos = 4 + 2 + 32;
        uint8 session_id_length = malformed_client_hello[extension_length_pos];
        extension_length_pos += 1 + session_id_length;
        uint16 cipher_suites_length = t_binary_to_integer<uint16>(&malformed_client_hello[extension_length_pos], sizeof(uint16));
        extension_length_pos += sizeof(uint16) + cipher_suites_length;
        uint8 compression_methods_length = malformed_client_hello[extension_length_pos];
        extension_length_pos += 1 + compression_methods_length;
        size_t extension_data_pos = extension_length_pos + sizeof(uint16);

        size_t post_handshake_auth_pos = malformed_client_hello.size();
        for (size_t i = extension_data_pos; i + 4 <= malformed_client_hello.size(); ++i) {
            if ((0x00 == malformed_client_hello[i]) && (0x31 == malformed_client_hello[i + 1]) && (0x00 == malformed_client_hello[i + 2]) &&
                (0x00 == malformed_client_hello[i + 3])) {
                post_handshake_auth_pos = i;
                break;
            }
        }
        _test_case.assert(malformed_client_hello.size() != post_handshake_auth_pos, __FUNCTION__, "locate the empty post_handshake_auth extension");
        if (malformed_client_hello.size() == post_handshake_auth_pos) {
            return;
        }

        malformed_client_hello.insert(malformed_client_hello.begin() + post_handshake_auth_pos + 4, 0x00);
        // The inserted byte belongs to post_handshake_auth itself. Update the
        // extension's own length, not only the enclosing ClientHello length.
        malformed_client_hello[post_handshake_auth_pos + 2] = 0x00;
        malformed_client_hello[post_handshake_auth_pos + 3] = 0x01;
        uint16 extension_length = t_binary_to_integer<uint16>(&malformed_client_hello[extension_length_pos], sizeof(uint16)) + 1;
        malformed_client_hello[extension_length_pos] = (byte_t)(extension_length >> 8);
        malformed_client_hello[extension_length_pos + 1] = (byte_t)extension_length;
        uint32 handshake_length = ((uint32)malformed_client_hello[1] << 16) | ((uint32)malformed_client_hello[2] << 8) | malformed_client_hello[3];
        ++handshake_length;
        malformed_client_hello[1] = (byte_t)(handshake_length >> 16);
        malformed_client_hello[2] = (byte_t)(handshake_length >> 8);
        malformed_client_hello[3] = (byte_t)handshake_length;

        tls_session server;
        server.set_type(session_type_t::tls);
        size_t server_pos = 0;
        auto parsed = tls_handshake::read(&server, from_client, malformed_client_hello.data(), malformed_client_hello.size(), server_pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject a non-empty post_handshake_auth extension");
        if (nullptr != parsed) {
            parsed->release();
        }
        size_t decode_error_count = 0;
        server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::decode_error == desc)) {
                ++decode_error_count;
            }
        });
        _test_case.assert(1 == decode_error_count, __FUNCTION__, "queue fatal decode_error for a non-empty post_handshake_auth extension");
        _test_case.assert(0 == server.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                          "do not record a malformed post_handshake_auth extension as an offer");
    }

    // post_handshake_auth is permitted only in a client-originated ClientHello.
    {
        tls_session server;
        server.set_type(session_type_t::tls);
        tls_handshake_encrypted_extensions encrypted_extensions(&server);
        encrypted_extensions.get_extensions().add(new tls_extension_unknown(tls_extension_type_t::post_handshake_auth, &encrypted_extensions));
        binary_t wire;
        ret = encrypted_extensions.write(from_server, wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "do not serialize post_handshake_auth from a server EncryptedExtensions");

        binary_t server_extension{0x00, 0x31, 0x00, 0x00};
        size_t pos = 0;
        auto parsed = tls_extension::read(&encrypted_extensions, from_server, server_extension.data(), server_extension.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject server-sent post_handshake_auth in EncryptedExtensions");
        size_t illegal_parameter_count = 0;
        server.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
                ++illegal_parameter_count;
            }
        });
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for server-sent post_handshake_auth");
    }

    // ClientHello2 must preserve the post_handshake_auth offer from ClientHello1.
    {
        auto write_client_hello = [](tls_session& session, bool offer) -> return_t {
            tls_handshake_client_hello hello(&session);
            hello.add_ciphersuite(0x1301);
            auto versions = new tls_extension_client_supported_versions(&hello);
            versions->add(tls_13);
            hello.get_extensions().add(versions);
            if (offer) {
                hello.get_extensions().add(new tls_extension_unknown(tls_extension_type_t::post_handshake_auth, &hello));
            }
            binary_t wire;
            return hello.write(from_client, wire);
        };

        {
            tls_session client;
            client.set_type(session_type_t::tls);
            client.get_tls_protection().set_tls_version(tls_13);
            ret = write_client_hello(client, true);
            _test_case.test(ret, __FUNCTION__, "write initial ClientHello with post_handshake_auth before HRR");
            if (errorcode_t::success == ret) {
                client.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
                ret = write_client_hello(client, false);
                _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject ClientHello2 that removes the original post_handshake_auth offer");
                size_t fatal_count = 0;
                bool illegal_parameter = false;
                client.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                    if (tls_alertlevel_t::fatal == level) {
                        ++fatal_count;
                        illegal_parameter = (tls_alertdesc_t::illegal_parameter == desc);
                    }
                });
                _test_case.assert(1 == fatal_count && illegal_parameter, __FUNCTION__, "reject inconsistent ClientHello2 with one fatal illegal_parameter");
                _test_case.assert(1 == client.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                                  "retain the original PHA offer after rejecting inconsistent ClientHello2");
            }
        }

        {
            tls_session client;
            client.set_type(session_type_t::tls);
            client.get_tls_protection().set_tls_version(tls_13);
            ret = write_client_hello(client, false);
            _test_case.test(ret, __FUNCTION__, "write initial ClientHello without post_handshake_auth before HRR");
            if (errorcode_t::success == ret) {
                client.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
                ret = write_client_hello(client, true);
                _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject ClientHello2 that adds a new post_handshake_auth offer");
                size_t fatal_count = 0;
                bool illegal_parameter = false;
                client.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                    if (tls_alertlevel_t::fatal == level) {
                        ++fatal_count;
                        illegal_parameter = (tls_alertdesc_t::illegal_parameter == desc);
                    }
                });
                _test_case.assert(1 == fatal_count && illegal_parameter, __FUNCTION__, "reject inconsistent ClientHello2 with one fatal illegal_parameter");
                _test_case.assert(0 == client.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                                  "do not promote a CH2-only PHA extension into an initial offer");
            }
        }

        {
            tls_session client;
            client.set_type(session_type_t::tls);
            client.get_tls_protection().set_tls_version(tls_13);
            ret = write_client_hello(client, true);
            _test_case.test(ret, __FUNCTION__, "write initial ClientHello with post_handshake_auth for valid HRR retry");
            if (errorcode_t::success == ret) {
                client.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
                ret = write_client_hello(client, true);
                _test_case.test(ret, __FUNCTION__, "accept ClientHello2 that preserves post_handshake_auth");
                _test_case.assert(1 == client.get_keyvalue().get(session_client_post_handshake_auth), __FUNCTION__,
                                  "preserve the original PHA offer across a valid HRR retry");
            }
        }
    }
}

void testcase_gpt_certificate() {
    test_tls13_certificate_verify_signature_policy();
    test_tls13_certificate_verify_signature_failure();
    test_tls13_certificate_request_signature_algorithms();
    test_tls13_empty_certificate_list_direction_policy();
    test_tls13_post_handshake_certificate_request_gate();
}
