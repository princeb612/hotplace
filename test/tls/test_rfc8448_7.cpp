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
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 */

#include "sample.hpp"

void test_rfc8448_7() {
    _test_case.begin("RFC 8448 7.  Compatibility Mode");

    // RFC 8446 D.4.  Middlebox Compatibility Mode

    return_t ret = errorcode_t::success;
    tls_session session;
    crypto_keychain keychain;
    auto& protection = session.get_tls_protection();
    binary_t bin;

    {
        // {client}  create an ephemeral x25519 key pair
        constexpr char constexpr_client[] = KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE;
        const char* x =
            "8e 72 92 cf 30 56 db b0 d2 5f cb e5 5c 10"
            "7d c9 bb f8 3d d9 70 8f 39 20 3b a3 41 24 9a 7d 9b 63";
        const char* y = nullptr;
        const char* d =
            "de a0 0b 45 69 5d c7 81 f1 9d 34 a6 2c"
            "1a fd 31 ab 43 69 af 1e 85 5a 3b bb 25 8d 84 42 cd e6 d7";
        crypto_key& key = protection.get_key();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_client));

        _logger->writeln(constexpr_client);
        _logger->writeln([&](basic_stream& bs) -> void { dump_key(key.find(constexpr_client), &bs); });

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        const char* record =
            "16 03 01 00 e0 01 00 00 dc 03 03 4e"
            "64 0a 3f 2c 27 38 f0 9c 94 18 bd 78 ed cc d7 55 9d 05 31 19 92"
            "76 d4 d9 2a 0e 9e e9 d7 7d 09 20 a8 0c 16 55 81 a8 e0 d0 6c 00"
            "18 d5 4d 3a 06 dd 32 cf d4 05 1e b0 26 fa d3 fd 0b a9 92 69 e6"
            "ef 00 06 13 01 13 03 13 02 01 00 00 8d 00 00 00 0b 00 09 00 00"
            "06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00"
            "17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 26 00 24"
            "00 1d 00 20 8e 72 92 cf 30 56 db b0 d2 5f cb e5 5c 10 7d c9 bb"
            "f8 3d d9 70 8f 39 20 3b a3 41 24 9a 7d 9b 63 00 2b 00 03 02 03"
            "04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06"
            "04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01"
            "01 00 1c 00 02 40 01";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("client_hello", &session, from_client, bin_record);
    }
    {
        // {server}  create an ephemeral x25519 key pair
        constexpr char constexpr_server[] = KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE;
        const char* x =
            "3e 30 f0 f4 ba 55 1a fd 62 76 83 41 17 5f"
            "52 65 e4 da f0 c8 84 16 17 aa 4f af dd 21 42 32 0c 22";
        const char* y = nullptr;
        const char* d =
            "01 7c 38 a3 64 79 21 ca 2d 9e d6 bd 7a"
            "e7 13 2b 94 21 1b 13 31 bb 20 8c 8c cd d5 15 56 40 99 95";
        crypto_key& key = protection.get_key();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_server));

        _logger->writeln(constexpr_server);
        _logger->writeln([&](basic_stream& bs) -> void { dump_key(key.find(constexpr_server), &bs); });

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        const char* record =
            "16 03 03 00 7a 02 00 00 76 03 03 e5"
            "dd 59 48 c4 35 f7 a3 8f 0f 01 30 70 8d c3 22 d9 df 09 ab d4 83"
            "81 17 c1 83 a7 bb 6d 99 4f 2c 20 a8 0c 16 55 81 a8 e0 d0 6c 00"
            "18 d5 4d 3a 06 dd 32 cf d4 05 1e b0 26 fa d3 fd 0b a9 92 69 e6"
            "ef 13 01 00 00 2e 00 33 00 24 00 1d 00 20 3e 30 f0 f4 ba 55 1a"
            "fd 62 76 83 41 17 5f 52 65 e4 da f0 c8 84 16 17 aa 4f af dd 21"
            "42 32 0c 22 00 2b 00 02 03 04";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("server_hello", &session, from_server, bin_record);
    }
    {
        // {server}  extract secret "early"
        test_keycalc(&session, tls_secret_early_secret, bin, "early", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        // {server}  derive secret for handshake "tls13 derived"
        test_keycalc(&session, tls_secret_handshake_derived, bin, "derived", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        // {server}  extract secret "handshake"
        test_keycalc(&session, tls_secret_handshake, bin, "handshake", "f91761354a67e9b07c6dcc3a55707efa69c4519d8040e5f215121e0df69afa4a");
        // {server}  derive secret "tls13 c hs traffic"
        test_keycalc(&session, tls_secret_c_hs_traffic, bin, "c hs traffic", "2c3cb24a1081edb59518ee6861e89a6b72b3801afe7713e4cbbc21c0795bf831");
        // {server}  derive secret "tls13 s hs traffic"
        test_keycalc(&session, tls_secret_s_hs_traffic, bin, "s hs traffic", "cace3d555cc1c577cf970cff28cf978d6a9800085442e18d695b50f3151d18c8");
        // {server}  derive secret for master "tls13 derived"
        test_keycalc(&session, tls_secret_application_derived, bin, "application_derived", "5da12dc47835ba73fdd994b14ab7e63cc63f0d79162f6756e9a46756c8b2b642");
        // {server}  derive write traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_server_key, bin, "handshake_server_key", "041091fdab29f2c8abfb156dc5fc8d54");
        test_keycalc(&session, tls_secret_handshake_server_iv, bin, "handshake_server_iv", "7464d791685de05998fcbadb");
    }
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("change_cipher_spec", &session, from_server, bin_record);
    }
    {
        const char* record =
            "17 03 03 02 a2 48 de 89 1d 9c 36 24"
            "a6 7a 6c 6f 06 01 ab 7a c2 0c 1f 6a 9e 14 d2 e6 00 7e 99 9e 13"
            "03 67 a8 af 1b cf ea 94 98 fb ce 19 df 45 05 ee ce 3a 25 da 52"
            "3c be 55 ea 1b 3b da 4e 91 99 5e 45 5d 50 0a 4f aa 62 27 b7 11"
            "1e 1c 85 47 e2 d7 c1 79 db 21 53 03 d2 58 27 f3 cd 18 f4 8f 64"
            "91 32 8c f5 c0 f8 14 d3 88 15 0b d9 e9 26 4a ae 49 1d b6 99 50"
            "69 be a1 76 65 d5 e0 c8 17 28 4d 4a c2 18 80 05 4c 36 57 33 1e"
            "23 a9 30 4d c8 8a 15 c0 4e c8 0b d3 85 2b f7 f9 d3 c6 61 5b 15"
            "fa c8 3b bc a0 31 c6 d2 31 0d 9f 5d 7a 4b 02 0a 4f 7c 19 06 2b"
            "65 c0 5a 1d 32 64 b5 57 ec 9d 8e 0f 7c ee 27 e3 6f 79 30 39 de"
            "8d d9 6e df ca 90 09 e0 65 10 34 bf f3 1d 7f 34 9e ec e0 1d 99"
            "fc b5 fc ab 84 0d 77 07 c7 22 99 c3 b5 d0 45 64 e8 80 a3 3c 5e"
            "84 6c 76 2e 3d 92 2b b5 53 03 d1 d8 7c c0 f0 65 73 f1 7d cb 9b"
            "8f fd 35 bb d8 83 c1 cb 3a a2 4f cc 32 50 05 f7 68 ce 2f b6 24"
            "ca 97 b6 c4 d9 8e 17 f3 5b c2 c7 94 0a 06 10 0c 2d 44 8d b7 18"
            "0b 2d 86 21 64 43 5c 9c 21 0e 98 60 39 4e 05 aa b2 3f f1 b0 20"
            "3f 66 2c 58 8d a5 bc 44 11 47 7a 30 b4 11 36 c4 88 a0 a6 3f ca"
            "b5 c1 5a c6 13 22 6d ae 82 7a 1d 1f e9 5e ce 6b 30 bc ee 15 60"
            "a8 d4 08 d2 64 55 5e 76 0f 9b fc 62 4c 2c 87 fd 04 56 c9 bf b4"
            "1b cd 1a 7b 21 27 86 d2 b6 7f d5 78 04 fa cf a1 ee f7 cf 29 19"
            "d8 b9 98 c9 78 9f 76 3b 4d 9c aa 09 3a 9d ed 43 17 5d 46 a7 6b"
            "4d 54 f0 ce 0c 5d 22 59 b6 07 e3 0a 9d 24 12 63 87 4f a5 9d 6f"
            "57 0d c4 0d 83 a2 d8 3b f9 e9 85 0d 45 4c 57 80 65 35 a8 99 8a"
            "e0 35 7d f9 2f 00 b9 66 73 44 c2 41 14 cc c9 ef 53 91 24 b2 04"
            "e7 e6 e7 48 c3 0a 28 a3 d1 d1 83 99 72 43 ea cc bb d3 3b 0c 11"
            "15 a0 32 71 06 a1 e6 a7 52 71 d4 98 30 86 f6 32 ff 0e b8 b4 c6"
            "31 02 cb ce f5 bb 72 da e1 27 9d 5d e8 eb 19 09 6d 8c db 07 fa"
            "8e a9 89 78 8f ac 23 e6 6e 04 88 c1 93 f3 f3 fe a8 c8 83 88 96"
            "bf 3a e4 b6 84 8d 42 ce d4 bd f4 1a be 6f c3 31 b4 42 25 e7 a1"
            "f7 d3 56 41 47 d5 45 8e 71 aa 90 9c b0 2b e9 58 bb c4 2e 3a a5"
            "a2 7c c6 ea f4 b6 fe 51 ae 44 95 69 4d 8a b6 32 0a ab 92 01 83"
            "fd 5b 31 a3 59 04 2f bd 67 39 1e c5 e4 d1 89 2a 2e 52 10 14 1a"
            "49 4e 93 01 b2 4a 11 3c 47 4c 7f 2a 73 45 78 47";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("encrypted_extensions certificate certificate_verify finished", &session, from_server, bin_record);
    }
    {
        // {server}  derive secret "tls13 c ap traffic"
        test_keycalc(&session, tls_secret_c_ap_traffic, bin, "c ap traffic", "743e4c6b56cf3909d1b06d01956ccd2c4b37758449aec41d98dae44924eaa299");
        // {server}  derive secret "tls13 s ap traffic"
        test_keycalc(&session, tls_secret_s_ap_traffic, bin, "s ap traffic", "b6b8144aa335ed3059c0c9c8f0ecabf7afc94af6643bdecdfd9210188fab7451");
        // {server}  derive secret "tls13 exp master"
        test_keycalc(&session, tls_secret_exp_master, bin, "exp master", "fb69121cea334db459e12272d179baca2369b643d11a6ac72b8b27a5c964feb1");
        // {server}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_server_key, bin, "application_server_key", "edc4cbd0041c28cc7167441d7ca53e6a");
        test_keycalc(&session, tls_secret_application_server_iv, bin, "application_server_iv", "bf6c7d8e0a9545b427dcf139");
        // {server}  derive read traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_client_key, bin, "handshake_client_key", "62d13c13ffd7402fc1c09e3d163665cb");
        test_keycalc(&session, tls_secret_handshake_client_iv, bin, "handshake_client_iv", "7166f20028bf146dcfbd5a40");
        // {client}  derive secret for handshake "tls13 derived"
        test_keycalc(&session, tls_secret_handshake_derived, bin, "handshake_derived", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    }
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("change_cipher_spec", &session, from_client, bin_record);
    }
    {
        const char* record =
            "17 03 03 00 35 32 d0 30 e2 73 77 3a"
            "86 96 c7 99 98 1a f6 ce d0 7f 87 48 2e 81 56 5e 39 4e 87 c8 67"
            "f3 3d f3 d6 5b 75 06 f1 a6 26 af 91 d4 82 1d 5f 7a 1f 21 0e f8"
            "dd 3c 6d 16";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("finished", &session, from_client, bin_record);
    }
    {
        // {client}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_client_key, bin, "application_client_key", "33d7f9709756c966488ad4438437e673");
        test_keycalc(&session, tls_secret_application_client_iv, bin, "application_client_iv", "c5f30d34b0e91b7d6c8eea65");
        // {client}  derive secret "tls13 res master"
        test_keycalc(&session, tls_secret_res_master, bin, "res master", "0b5d4407cea0a42a3a81dd477647b7fe9180db297e5114f1ad8796b4dc475004");
    }
    {
        const char* record =
            "17 03 03 00 13 0f 62 91 55 38 2d ba"
            "23 c4 e2 c5 f7 f8 4e 6f 2e d3 08 3d";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("alert (close_notify)", &session, from_client, bin_record);
    }
    {
        const char* record =
            "17 03 03 00 13 b7 25 7b 0f ec af 69"
            "d4 f0 9e 3f 89 1e 2a 25 d1 e2 88 45";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("alert (close_notify)", &session, from_server, bin_record);
    }
}
