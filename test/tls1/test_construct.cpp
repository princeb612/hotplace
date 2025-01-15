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

void test_construct_client_hello(binary_t& bin) {
    tls_handshake_client_hello handshake(&client_session);

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
        auto sni = new tls_extension_sni(&client_session);
        auto& hostname = sni->get_hostname();
        // hostname = "server";
        handshake.get_extensions().add(sni);
    }
    {
        auto ec_point_formats = new tls_extension_ec_point_formats(&client_session);
        (*ec_point_formats).add("uncompressed").add("ansiX962_compressed_prime").add("ansiX962_compressed_char2");
        handshake.get_extensions().add(ec_point_formats);
    }
    {
        auto supported_groups = new tls_extension_supported_groups(&client_session);
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
        auto signature_algorithms = new tls_extension_signature_algorithms(&client_session);
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
        auto supported_versions = new tls_extension_client_supported_versions(&client_session);
        (*supported_versions).add(tls_13).add(tls_12);
        handshake.get_extensions().add(supported_versions);
    }
    {
        auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(&client_session);
        (*psk_key_exchange_modes).add("psk_dhe_ke");
        handshake.get_extensions().add(psk_key_exchange_modes);
    }
    {
        auto key_share = new tls_extension_client_key_share(&client_session);
        (*key_share).add("x25519");
        handshake.get_extensions().add(key_share);
    }
    {
        basic_stream bs;
        tls_record_handshake record(&client_session);
        record.get_handshakes().add(&handshake, true);
        record.write(from_client, bin);

        _test_case.assert(bin.size(), __FUNCTION__, "construct client hello message");
    }
    {
        basic_stream bs;
        auto pkey = client_session.get_tls_protection().get_keyexchange().find("client");
        dump_key(pkey, &bs);
        _logger->write(bs);
        _test_case.assert(pkey, __FUNCTION__, "key share (client generated)");
    }
}

void test_send_client_hello(tls_records& records, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    ret = records.read(&server_session, from_client, bin, &bs);

    _logger->write(bs);
    _test_case.test(ret, __FUNCTION__, "send client hello");
}

void test_construct_server_hello(const tls_records& records_client_hello, binary_t& bin) {
    tls_handshake_client_hello_selector selector(&records_client_hello);
    selector.select();  // TODO ...

    auto server_version = selector.get_version();
    auto server_cs = selector.get_cipher_suite();

    tls_handshake_server_hello handshake(&server_session);

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
        auto supported_versions = new tls_extension_server_supported_versions(&server_session);
        (*supported_versions).set(server_version);
        handshake.get_extensions().add(supported_versions);
    }
    {
        auto key_share = new tls_extension_server_key_share(&server_session);
        (*key_share).add("x25519");
        handshake.get_extensions().add(key_share);
    }

    {
        basic_stream bs;
        tls_record_handshake record(&server_session);
        record.get_handshakes().add(&handshake, true);
        record.write(from_client, bin);

        _test_case.assert(bin.size(), __FUNCTION__, "construct server hello message");
    }
    {
        basic_stream bs;
        auto pkey = server_session.get_tls_protection().get_keyexchange().find("server");
        dump_key(pkey, &bs);
        _logger->write(bs);
        _test_case.assert(pkey, __FUNCTION__, "key share (server generated)");
    }
}

void test_send_server_hello(tls_records& records, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    ret = records.read(&client_session, from_server, bin, &bs);

    _logger->write(bs);
    _test_case.test(ret, __FUNCTION__, "send server hello");
}

void test_construct() {
    _test_case.begin("construct");

    tls_records records_client_hello;
    binary_t bin_client_hello;
    test_construct_client_hello(bin_client_hello);                   // write + client_session
    test_send_client_hello(records_client_hello, bin_client_hello);  // read + server_session

    tls_records records_server_hello;
    binary_t bin_server_hello;
    test_construct_server_hello(records_client_hello, bin_server_hello);  // write + server_session
    test_send_server_hello(records_server_hello, bin_server_hello);       // read + client_session
}
