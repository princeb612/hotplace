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

void test_construct() {
    _test_case.begin("construct");

    tls_record_builder record_builder;
    binary_t bin;
    basic_stream bs;
    tls_session client_session;
    tls_session server_session;

    client_session.get_tls_protection().set_record_version(tls_12);
    server_session.get_tls_protection().set_record_version(tls_12);

    tls_record_handshake record_client_hello(&client_session);
    tls_handshake_client_hello handshake_client_hello(&client_session);

    {
        openssl_prng prng;
        binary_t random;
        binary_t session_id;
        prng.random(random, 32);
        prng.random(session_id, 32);

        handshake_client_hello.get_random() = random;
        handshake_client_hello.get_session_id() = session_id;

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
        handshake_client_hello.add_ciphersuites(cipher_list);
    }

    {
        auto sni = new tls_extension_sni(&client_session);
        auto& hostname = sni->get_hostname();
        hostname = "server";
        handshake_client_hello << sni;
    }
    {
        auto ec_point_formats = new tls_extension_ec_point_formats(&client_session);
        (*ec_point_formats).add_format(0).add_format(1).add_format(2);
        handshake_client_hello << ec_point_formats;
    }

    {
        handshake_client_hello.write(from_origin, bin, &bs);

        _logger->writeln(bs);
        _logger->hdump("> client hello", bin);
    }
    {
        // TODO ...
        binary_t record;
        tls_session session;
        binary_append(record, tls_content_type_handshake);
        binary_append(record, uint16(tls_12), hton16);
        binary_append(record, uint16(bin.size()), hton16);
        binary_append(record, bin);
        dump_record("# client_hello", &session, record, from_client);
    }
}
