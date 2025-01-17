/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

tls_session client_session;
tls_session server_session;

void test_construct_client_hello(tls_session* session, binary_t& bin) {
    tls_handshake_client_hello handshake(session);

    {
        openssl_prng prng;
        binary_t random;
        binary_t session_id;
        prng.random(random, 32);
        prng.random(session_id, 32);

        handshake.get_random() = random;
        handshake.get_session_id() = session_id;

        const char* cipher_list =

            // HTTP/2, TLS 1.3
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256"
            // concatenate
            ":"
            // HTTP/3, DTLS 1.2
            // current openssl support DTLS 1.2
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-"
            "RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-"
            "AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-"
            "AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA";
        handshake.add_ciphersuites(cipher_list);
    }

    {
        auto sni = new tls_extension_sni(session);
        auto& hostname = sni->get_hostname();
        // hostname = "server";
        handshake.get_extensions().add(sni);
    }
    {
        auto ec_point_formats = new tls_extension_ec_point_formats(session);
        (*ec_point_formats).add("uncompressed").add("ansiX962_compressed_prime").add("ansiX962_compressed_char2");
        handshake.get_extensions().add(ec_point_formats);
    }
    {
        auto supported_groups = new tls_extension_supported_groups(session);
        (*supported_groups)
            .add("x25519")
            .add("secp256r1")
            .add("x448")
            .add("secp521r1")
            .add("secp384r1")
            .add("ffdhe2048")
            .add("ffdhe3072")
            .add("ffdhe4096")
            .add("ffdhe6144")
            .add("ffdhe8192");
        handshake.get_extensions().add(supported_groups);
    }
    {
        auto signature_algorithms = new tls_extension_signature_algorithms(session);
        (*signature_algorithms)
            .add("ecdsa_secp256r1_sha256")
            .add("ecdsa_secp384r1_sha384")
            .add("ecdsa_secp521r1_sha512")
            .add("ed25519")
            .add("ed448")
            .add("rsa_pss_pss_sha256")
            .add("rsa_pss_pss_sha384")
            .add("rsa_pss_pss_sha512")
            .add("rsa_pss_rsae_sha256")
            .add("rsa_pss_rsae_sha384")
            .add("rsa_pss_rsae_sha512")
            .add("rsa_pkcs1_sha256")
            .add("rsa_pkcs1_sha384")
            .add("rsa_pkcs1_sha512");
        handshake.get_extensions().add(signature_algorithms);
    }
    {
        auto supported_versions = new tls_extension_client_supported_versions(session);
        (*supported_versions).add(tls_13).add(tls_12);
        handshake.get_extensions().add(supported_versions);
    }
    {
        auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(session);
        (*psk_key_exchange_modes).add("psk_dhe_ke");
        handshake.get_extensions().add(psk_key_exchange_modes);
    }
    {
        auto key_share = new tls_extension_client_key_share(session);
        (*key_share).add("x25519");
        handshake.get_extensions().add(key_share);
    }
    {
        basic_stream bs;
        tls_record_handshake record(session);
        record.get_handshakes().add(&handshake, true);
        record.write(from_client, bin);

        _test_case.assert(bin.size(), __FUNCTION__, "{*client->server} construct client hello message");
    }
    {
        basic_stream bs;
        auto pkey = session->get_tls_protection().get_keyexchange().find("client");
        dump_key(pkey, &bs);
        _logger->write(bs);
        _test_case.assert(pkey, __FUNCTION__, "{client} key share (client generated)");
    }
}

void test_send_client_hello(tls_session* session, tls_records& records, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    ret = records.read(session, from_client, bin, &bs);

    _logger->write(bs);
    _test_case.test(ret, __FUNCTION__, "{client->server*} send client hello");
}

void test_construct_server_hello(tls_session* session, const tls_records& records_client_hello, binary_t& bin) {
    tls_handshake_client_hello_selector selector(&records_client_hello);
    selector.select();  // TODO ...

    auto server_version = selector.get_version();
    auto server_cs = selector.get_cipher_suite();

    tls_handshake_server_hello handshake(session);

    {
        openssl_prng prng;
        binary_t random;
        binary_t session_id;
        prng.random(random, 32);
        prng.random(session_id, 32);

        handshake.get_random() = random;
        handshake.get_session_id() = session_id;
        handshake.set_cipher_suite(server_cs);
    }
    {
        auto supported_versions = new tls_extension_server_supported_versions(session);
        (*supported_versions).set(server_version);
        handshake.get_extensions().add(supported_versions);
    }
    {
        auto key_share = new tls_extension_server_key_share(session);
        (*key_share).add("x25519");
        handshake.get_extensions().add(key_share);
    }

    {
        basic_stream bs;
        tls_record_handshake record(session);
        record.get_handshakes().add(&handshake, true);
        record.write(from_client, bin);

        _test_case.assert(bin.size(), __FUNCTION__, "{*server->client} construct server hello message");
    }
    {
        basic_stream bs;
        auto pkey = session->get_tls_protection().get_keyexchange().find("server");
        dump_key(pkey, &bs);
        _logger->write(bs);
        _test_case.assert(pkey, __FUNCTION__, "{server} key share (server generated)");
    }
}

void test_send_server_hello(tls_session* session, tls_records& records, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    ret = records.read(session, from_server, bin, &bs);

    _logger->write(bs);
    _test_case.test(ret, __FUNCTION__, "{server->client*} send server hello");
}

void cross_check_keycalc(tls_secret_t secret, const char* secret_name) {
    auto& client_protection = client_session.get_tls_protection();
    auto& server_protection = server_session.get_tls_protection();

    binary_t client_secret;
    binary_t server_secret;

    client_protection.get_item(secret, client_secret);
    server_protection.get_item(secret, server_secret);

    _logger->writeln("client secret %s (internal 0x%04x) %s", secret_name, secret, base16_encode(client_secret).c_str());
    _logger->writeln("server secret %s (internal 0x%04x) %s", secret_name, secret, base16_encode(server_secret).c_str());

    _test_case.assert(client_secret == server_secret, __FUNCTION__, "cross-check secret %s", secret_name);
}

void test_keycalc() {
    cross_check_keycalc(tls_context_empty_hash, "tls_context_empty_hash");
    cross_check_keycalc(tls_context_shared_secret, "tls_context_shared_secret");
    cross_check_keycalc(tls_context_transcript_hash, "tls_context_transcript_hash");
    cross_check_keycalc(tls_secret_early_secret, "tls_secret_early_secret");
    cross_check_keycalc(tls_secret_handshake_derived, "tls_secret_handshake_derived");
    cross_check_keycalc(tls_secret_handshake, "tls_secret_handshake");
    cross_check_keycalc(tls_secret_c_hs_traffic, "tls_secret_c_hs_traffic");
    cross_check_keycalc(tls_secret_s_hs_traffic, "tls_secret_s_hs_traffic");
    cross_check_keycalc(tls_secret_handshake_client_key, "tls_secret_handshake_client_key");
    cross_check_keycalc(tls_secret_handshake_client_iv, "tls_secret_handshake_client_iv");
    cross_check_keycalc(tls_secret_handshake_server_key, "tls_secret_handshake_server_key");
    cross_check_keycalc(tls_secret_handshake_server_iv, "tls_secret_handshake_server_iv");
}

void test_construct_server_change_cipher_spec(tls_session* session, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_change_cipher_spec record(session);
        ret = record.write(from_server, bin);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "{*server->client} construct change_cipher_spec"); }
}

void test_send_server_change_cipher_spec(tls_session* session, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        basic_stream bs;
        tls_records records;
        ret = records.read(session, from_server, bin, &bs);
        _logger->write(bs);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "{server->client*} send change_cipher_spec"); }
}

void test_construct_encrypted_extensions(tls_session* session, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_handshake_encrypted_extensions handshake(session);
    basic_stream bs;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_handshakes().add(&handshake, true);
        ret = record.write(from_server, bin, &bs);
    }
    __finally2 {
        _logger->hdump("> construct", bin, 16, 3);
        _logger->write(bs);
        _test_case.test(ret, __FUNCTION__, "{*server->client} construct encrypted extensions");
    }
}

void test_send_encrypted_extensions(tls_session* session, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        basic_stream bs;
        tls_records records;
        ret = records.read(session, from_server, bin, &bs);
        _logger->write(bs);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "{server->client*} send encrypted extensions"); }
}

void test_construct_certificate(tls_session* session, const char* certfile, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_handshake_certificate handshake(session);
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handshake.set(from_server, certfile);  // SC (server certificate)

        basic_stream bs;
        tls_record_application_data record(session);
        record.get_handshakes().add(&handshake, true);
        record.write(from_server, bin, &bs);
        _logger->write(bs);
    }
    __finally2 {
        _logger->hdump("> construct", bin, 16, 3);
        _test_case.test(ret, __FUNCTION__, "{*server->client} construct certificate");
    }
}

void test_send_certificate(tls_session* session, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        basic_stream bs;
        tls_records records;
        ret = records.read(session, from_server, bin, &bs);
        _logger->write(bs);
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "{server->client*} send cerficate"); }
}

void test_construct() {
    _test_case.begin("construct");

    // C -> S {client}
    // construct : write + client_session
    // send : read + server_session
    // S -> C {server}
    // construct : write + server_session
    // send : read + client_session

    // C -> S CH
    tls_records records_client_hello;
    binary_t bin_client_hello;
    test_construct_client_hello(&client_session, bin_client_hello);
    test_send_client_hello(&server_session, records_client_hello, bin_client_hello);

    // S -> C SH
    tls_records records_server_hello;
    binary_t bin_server_hello;
    test_construct_server_hello(&server_session, records_client_hello, bin_server_hello);
    test_send_server_hello(&client_session, records_server_hello, bin_server_hello);

    test_keycalc();

    // S -> C CCS
    binary_t bin_server_change_cipher_spec;
    test_construct_server_change_cipher_spec(&server_session, bin_server_change_cipher_spec);
    test_send_server_change_cipher_spec(&client_session, bin_server_change_cipher_spec);

    // S -> C EE
    binary_t bin_encrypted_extensions;
    test_construct_encrypted_extensions(&server_session, bin_encrypted_extensions);
    test_send_encrypted_extensions(&client_session, bin_encrypted_extensions);

    // S -> C SC
    binary_t bin_certificate;
    test_construct_certificate(&server_session, "server.crt", bin_certificate);
    test_send_certificate(&client_session, bin_certificate);
}
