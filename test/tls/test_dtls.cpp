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
 *  https://dtls.xargs.org/
 */

#include "sample.hpp"

void test_dtls_xargs_org() {
    _test_case.begin("https://dtls.xargs.org/");

    return_t ret = errorcode_t::success;
    tls_session session;

    crypto_keychain keychain;
    openssl_digest dgst;
    openssl_kdf kdf;
    basic_stream bs;
    size_t pos = 0;
    binary_t bin_clienthello_record;
    binary_t bin_serverhello_record;
    tls_advisor* advisor = tls_advisor::get_instance();

    // https://dtls.xargs.org/#client-key-exchange-generation
    {
        constexpr char constexpr_client_key[] = "client";
        crypto_key& key = session.get_tls_protection().get_keyexchange();
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        keychain.add_ec_b16(&key, ec_x25519, x, y, d, keydesc(constexpr_client_key));
        basic_stream bs;
        dump_key(key.find(constexpr_client_key), &bs);
        _logger->writeln(bs);
    }
    // https://dtls.xargs.org/#client-hello-datagram
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 00 00 9d 01 00 00 91 00 00 00 00 00 00 00 91 fe fd e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 "
            "f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 06 13 01 13 02 13 03 01 00 00 61 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df "
            "91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2b 00 03 02 fe fc 00 0d 00 20 00 1e 06 03 05 03 04 03 02 03 08 06 08 0b 08 05 08 0a "
            "08 04 08 09 06 01 05 01 04 01 03 01 02 01 00 16 00 00 00 0a 00 04 00 02 00 1d";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &session, bin_record, role_client);
    }
    // https://dtls.xargs.org/#server-key-exchange-generation
    {
        constexpr char constexpr_server_key[] = "server";
        crypto_key& key = session.get_tls_protection().get_keyexchange();
        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        keychain.add_ec_b16(&key, ec_x25519, x, y, d, keydesc(constexpr_server_key));
        basic_stream bs;
        dump_key(key.find(constexpr_server_key), &bs);
        _logger->writeln(bs);
    }
    // https://dtls.xargs.org/#server-hello-datagram
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 00 00 62 02 00 00 56 00 00 00 00 00 00 00 56 fe fd 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 "
            "85 86 87 88 89 8a 8b 8c 8d 8e 8f 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 "
            "fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 fe fc";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &session, bin_record, role_server);
    }
    // https://dtls.xargs.org/#server-handshake-keys-calc
    // https://dtls.xargs.org/#client-handshake-keys-calc
    {
        binary_t shared_secret;
        test_keycalc(&session, tls_context_shared_secret, shared_secret, "shared_secret", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");
        binary_t hello_hash;
        test_keycalc(&session, tls_context_transcript_hash, hello_hash, "hello_hash", "aee8eba0d2ee87052fbbc6864c1514c5a927d6f0ffb4f7954c7f379d95f1b1d7");
        binary_t client_handshake_key;
        test_keycalc(&session, tls_secret_handshake_client_key, client_handshake_key, "client_handshake_key", "6caa2633d5e48f10051e69dc45549c97");
        binary_t client_handshake_iv;
        test_keycalc(&session, tls_secret_handshake_client_iv, client_handshake_iv, "client_handshake_iv", "106dc6e393b7a9ea8ef29dd7");
        binary_t server_handshake_key;
        test_keycalc(&session, tls_secret_handshake_server_key, server_handshake_key, "server_handshake_key", "004e03e64ab6cba6b542775ec230e20a");
        binary_t server_handshake_iv;
        test_keycalc(&session, tls_secret_handshake_server_iv, server_handshake_iv, "server_handshake_iv", "6d9924be044ee97c624913f2");
        binary_t client_handshake_sn_key;
        test_keycalc(&session, tls_secret_handshake_client_sn_key, client_handshake_sn_key, "client_handshake_sn_key", "beed6218676635c2cb46a45694144fec");
        binary_t server_handshake_sn_key;
        test_keycalc(&session, tls_secret_handshake_server_sn_key, server_handshake_sn_key, "server_handshake_sn_key", "7173fac51194e775001d625ef69d7c9f");
    }
    // https://dtls.xargs.org/#server-encrypted-extensions-datagram
    {
        const char* record =
            "2e 79 fa 00 2f ee 9d cf f3 f8 67 9a 48 59 fe 68 37 7f b3 4a da 85 df 87 9c 67 3e 50 1d 7a 4e 8f 19 50 e0 fc f6 7f e4 42 e7 d7 d2 b8 a3 d5 fa 59 "
            "57 4f fd 00";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("encrypted-extensions-datagram", &session, bin_record, role_server);
    }
}
