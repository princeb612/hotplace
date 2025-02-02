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

void test_rfc8448_5() {
    _test_case.begin("RFC 8448 5.  HelloRetryRequest");

    return_t ret = errorcode_t::success;
    tls_session session;
    crypto_keychain keychain;
    auto& protection = session.get_tls_protection();
    basic_stream bs;

    {
        // {client}  create an ephemeral x25519 key pair
        constexpr char constexpr_client[] = "client";
        const char* x =
            "e8 e8 e3 f3 b9 3a 25 ed 97 a1 4a 7d ca cb"
            "8a 27 2c 62 88 e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f";
        const char* y = nullptr;
        const char* d =
            "0e d0 2f 8e 81 17 ef c7 5c a7 ac 32 aa"
            "7e 34 ed a6 4c dc 0d da d1 54 a5 e8 52 89 f9 59 f6 32 04";
        crypto_key& key = protection.get_keyexchange();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_client));

        _logger->writeln(constexpr_client);
        dump_key(key.find(constexpr_client), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        // > extension - 0033 key_share
        //  > extension len 0x0026(38)
        //  > len 36(0x0024)
        //   > key share entry
        //    > group 0x001d (x25519)
        //    > public key len 0020(32)
        const char* record =
            "16 03 01 00 b4 01 00 00 b0 03 03 b0"
            "b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a"
            "2b 8c ee 92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00"
            "00 81 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 26 00 24 00 1d"
            "00 20 e8 e8 e3 f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88"
            "e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f 00 2b 00 03 02 03 04 00"
            "0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01"
            "05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00"
            "1c 00 02 40 01";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &session, bin_record, from_client);
    }
    {
        // {client}  create an ephemeral P-256 key pair
        constexpr char constexpr_server[] = "client";
        const char* priv =
            "ab 54 73 46 7e 19 34 6c eb 0a 04 14 e4"
            "1d a2 1d 4d 24 45 bc 30 25 af e9 7c 4e 8d c8 d5 13 da 39";
        const char* pub =
            "04 a6 da 73 92 ec 59 1e 17 ab fd 53 59 64"
            "b9 98 94 d1 3b ef b2 21 b3 de f2 eb e3 83 0e ac 8f 01 51 81 26"
            "77 c4 d6 d2 23 7e 85 cf 01 d6 91 0c fb 83 95 4e 76 ba 73 52 83"
            "05 34 15 98 97 e8 06 57 80";
        crypto_key& key = protection.get_keyexchange();
        ret = keychain.add_ec_uncompressed_b16rfc(&key, ec_p256, pub, priv, keydesc(constexpr_server));

        _logger->writeln(constexpr_server);
        dump_key(key.find(constexpr_server), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "P-256 key pair");
    }
    {
        // > extension - 0033 key_share
        //  > extension len 0x0002(2)
        //  > group 0x0017 (secp256r1)
        const char* record =
            "16 03 03 00 b0 02 00 00 ac 03 03 cf"
            "21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb"
            "8c 5e 07 9e 09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00"
            "17 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18 91 19 39 8a 00 00"
            "00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95"
            "3f 4e df 62 56 36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10"
            "d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d 6e 50 78 1b 5e"
            "da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0"
            "34 22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03"
            "04";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &session, bin_record, from_server, false);
    }
    {
        // {client}  construct a ClientHello handshake message
        const char* record =
            "16 03 03 02 00 01 00 01 fc 03 03 b0"
            "b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a"
            "2b 8c ee 92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00"
            "01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 47 00 45 00 17"
            "00 41 04 a6 da 73 92 ec 59 1e 17 ab fd 53 59 64 b9 98 94 d1 3b"
            "ef b2 21 b3 de f2 eb e3 83 0e ac 8f 01 51 81 26 77 c4 d6 d2 23"
            "7e 85 cf 01 d6 91 0c fb 83 95 4e 76 ba 73 52 83 05 34 15 98 97"
            "e8 06 57 80 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03"
            "06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05"
            "02 06 02 02 02 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18 91 19"
            "39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65"
            "dd 00 30 95 3f 4e df 62 56 36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b"
            "40 31 8d 10 d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d 6e"
            "50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84"
            "1d d9 e4 c0 34 22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34 b0 00"
            "2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 af 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00";

        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &session, bin_record, from_client);
    }
    {
        // {server}  create an ephemeral P-256 key pair
        constexpr char constexpr_server[] = "server";
        const char* priv =
            "8c 51 06 01 f9 76 5b fb 8e d6 93 44 9a"
            "48 98 98 59 b5 cf a8 79 cb 9f 54 43 c4 1c 5f f1 06 34 ed";
        const char* pub =
            "04 58 3e 05 4b 7a 66 67 2a e0 20 ad 9d 26"
            "86 fc c8 5b 5a d4 1a 13 4a 0f 03 ee 72 b8 93 05 2b d8 5b 4c 8d"
            "e6 77 6f 5b 04 ac 07 d8 35 40 ea b3 e3 d9 c5 47 bc 65 28 c4 31"
            "7d 29 46 86 09 3a 6c ad 7d";
        crypto_key& key = protection.get_keyexchange();
        ret = keychain.add_ec_uncompressed_b16rfc(&key, ec_p256, pub, priv, keydesc(constexpr_server));

        _logger->writeln(constexpr_server);
        dump_key(key.find(constexpr_server), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "P-256 key pair");
    }
    {
        const char* record =
            "16 03 03 00 7b 02 00 00 77 03 03 bb"
            "34 1d 84 7f d7 89 c4 7c 38 71 72 dc 0c 9b f1 47 fc ca cb 50 43"
            "d8 6c a4 c5 98 d3 ff 57 1b 98 00 13 01 00 00 4f 00 33 00 45 00"
            "17 00 41 04 58 3e 05 4b 7a 66 67 2a e0 20 ad 9d 26 86 fc c8 5b"
            "5a d4 1a 13 4a 0f 03 ee 72 b8 93 05 2b d8 5b 4c 8d e6 77 6f 5b"
            "04 ac 07 d8 35 40 ea b3 e3 d9 c5 47 bc 65 28 c4 31 7d 29 46 86"
            "09 3a 6c ad 7d 00 2b 00 02 03 04";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &session, bin_record, from_server);
    }
    {
        binary_t bin;

        // {server}  extract secret "early"
        test_keycalc(&session, tls_secret_early_secret, bin, "early", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        // {server}  derive secret for handshake "tls13 derived"
        test_keycalc(&session, tls_secret_handshake_derived, bin, "derived", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        // {server}  extract secret "handshake"
        test_keycalc(&session, tls_secret_handshake, bin, "handshake", "ce022e5e6e81e50736d773f2d3adfce8220d049bf510f0dbfac927ef4243b148");

        // Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn)
        test_keycalc(&session, tls_context_transcript_hash, bin, "hash", "8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8");

        // {server}  derive secret "tls13 c hs traffic"
        test_keycalc(&session, tls_secret_c_hs_traffic, bin, "c hs traffic", "158aa7ab8855073582b41d674b4055cabcc534728f659314861b4e08e2011566");
        // {server}  derive secret "tls13 s hs traffic"
        test_keycalc(&session, tls_secret_s_hs_traffic, bin, "s hs traffic", "3403e781e2af7b6508da28574f6e95a1abf162de83a97927c37672a4a0cef8a1");
        // {server}  derive secret for master "tls13 derived"
        test_keycalc(&session, tls_secret_application_derived, bin, "application_derived", "ad1cbcd3a0dc7053eeb3ed3a47901d16a9fc63a73c64beb567481a7dfb3a2cb3");
        // {server}  extract secret "master"
        test_keycalc(&session, tls_secret_application, bin, "secret_application", "1131545d0baf79ddce9b87f06945781a57dd18ef378dcd2060f8f9a569027ed8");
    }
    {
        const char* record =
            "17 03 03 02 96 99 be e2 0b af 5b 7f"
            "c7 27 bf ab 62 23 92 8a 38 1e 6d 0c f9 c4 da 65 3f 9d 2a 7b 23"
            "f7 de 11 cc e8 42 d5 cf 75 63 17 63 45 0f fb 8b 0c c1 d2 38 e6"
            "58 af 7a 12 ad c8 62 43 11 4a b1 4a 1d a2 fa e4 26 21 ce 48 3f"
            "b6 24 2e ab fa ad 52 56 6b 02 b3 1d 2e dd ed ef eb 80 e6 6a 99"
            "00 d5 f9 73 b4 0c 4f df 74 71 9e cf 1b 68 d7 f9 c3 b6 ce b9 03"
            "ca 13 dd 1b b8 f8 18 7a e3 34 17 e1 d1 52 52 2c 58 22 a1 a0 3a"
            "d5 2c 83 8c 55 95 3d 61 02 22 87 4c ce 8e 17 90 b2 29 a2 aa 0b"
            "53 c8 d3 77 ee 72 01 82 95 1d c6 18 1d c5 d9 0b d1 f0 10 5e d1"
            "e8 4a a5 f7 59 57 c6 66 18 97 07 9e 5e a5 00 74 49 e3 19 7b dc"
            "7c 9b ee ed dd ea fd d8 44 af a5 c3 15 ec fe 65 e5 76 af e9 09"
            "81 28 80 62 0e c7 04 8b 42 d7 f5 c7 8d 76 f2 99 d6 d8 25 34 bd"
            "d8 f5 12 fe bc 0e d3 81 4a ca 47 0c d8 00 0d 3e 1c b9 96 2b 05"
            "2f bb 95 0d f6 83 a5 2c 2b a7 7e d3 71 3b 12 29 37 a6 e5 17 09"
            "64 e2 ab 79 69 dc d9 80 b3 db 9b 45 8d a7 60 31 24 d6 dc 00 5e"
            "4d 6e 04 b4 d0 c4 ba f3 27 5d b8 27 db ba 0a 6d b0 96 72 17 1f"
            "c0 57 b3 85 1d 7e 02 68 41 e2 97 8f bd 23 46 bb ef dd 03 76 bb"
            "11 08 fe 9a cc 92 18 9f 56 50 aa 5e 85 d8 e8 c7 b6 7a c5 10 db"
            "a0 03 d3 d7 e1 63 50 bb 66 d4 50 13 ef d4 4c 9b 60 7c 0d 31 8c"
            "4c 7d 1a 1f 5c bc 57 e2 06 11 80 4e 37 87 d7 b4 a4 b5 f0 8e d8"
            "fd 70 bd ae ad e0 22 60 b1 2a b8 42 ef 69 0b 4a 3e e7 91 1e 84"
            "1b 37 4e cd 5e bb bc 2a 54 d0 47 b6 00 33 6d d7 d0 c8 8b 4b c1"
            "0e 58 ee 6c b6 56 de 72 47 fa 20 d8 e9 1d eb 84 62 86 08 cf 80"
            "61 5b 62 e9 6c 14 91 c7 ac 37 55 eb 69 01 40 5d 34 74 fe 1a c7"
            "9d 10 6a 0c ee 56 c2 57 7f c8 84 80 f9 6c b6 b8 c6 81 b7 b6 8b"
            "53 c1 46 09 39 08 f3 50 88 81 75 bd fb 0b 1e 31 ad 61 e3 0b a0"
            "ad fe 6d 22 3a a0 3c 07 83 b5 00 1a 57 58 7c 32 8a 9a fc fc fb"
            "97 8d 1c d4 32 8f 7d 9d 60 53 0e 63 0b ef d9 6c 0c 81 6e e2 0b"
            "01 00 76 8a e2 a6 df 51 fc 68 f1 72 74 0a 79 af 11 39 8e e3 be"
            "12 52 49 1f a9 c6 93 47 9e 87 7f 94 ab 7c 5f 8c ad 48 02 03 e6"
            "ab 7b 87 dd 71 e8 a0 72 91 13 df 17 f5 ee e8 6c e1 08 d1 d7 20"
            "07 ec 1c d1 3c 85 a6 c1 49 62 1e 77 b7 d7 8d 80 5a 30 f0 be 03"
            "0c 31 5e 54";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("encrypted_extensions certificate certificate_verify finished", &session, bin_record, from_server);
    }
    {
        binary_t bin;
        // {server}  derive write traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_server_key, bin, "handshake_server_key", "4646bfac1712c426cd78d8a24a8a6f6b");
        test_keycalc(&session, tls_secret_handshake_server_iv, bin, "handshake_server_iv", "c7d395c08d62f297d13768ea");

        // {server}  derive secret "tls13 c ap traffic"
        test_keycalc(&session, tls_secret_c_ap_traffic, bin, "c ap traffic", "75ecf4b972525aa0dcd057c9944d4cd5d82671d8843141d7dc2a4ff15a21dc51");
        // {server}  derive secret "tls13 s ap traffic"
        test_keycalc(&session, tls_secret_s_ap_traffic, bin, "s ap traffic", "5c74f87df04225db0f8209c9de6429e49435fdefa7cad61864874d12f31cfc8d");
        // {server}  derive secret "tls13 exp master"
        test_keycalc(&session, tls_secret_exp_master, bin, "exp master", "7c06d3ae106a3a374ace4837b3985cac67780a6e2c5c04b58319d584df09d223");
        // {server}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_server_key, bin, "application_server_key", "f27a5d97bd25550c4823b0f3e5d29388");
        test_keycalc(&session, tls_secret_application_server_iv, bin, "application_server_iv", "0dd631f7b71cbbc797c35fe7");
        // {server}  derive read traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_client_key, bin, "handshake_client_key", "2f1f918663d590e7421149a29d94b0b6");
        test_keycalc(&session, tls_secret_handshake_client_iv, bin, "handshake_client_iv", "414d5485235e1a688793bd74");
    }
    {
        const char* record =
            "17 03 03 00 35 d7 4f 19 23 c6 62 fd"
            "34 13 7c 6f 50 2f 3d d2 b9 3d 95 1d 1b 3b c9 7e 42 af e2 3c 31"
            "ab ea 92 fe 91 b4 74 99 9e 85 e3 b7 91 ce 25 2f e8 c3 e9 f9 39"
            "a4 12 0c b2";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("finished", &session, bin_record, from_client);
    }
    {
        binary_t bin;
        // {client}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_client_key, bin, "application_client_key", "a7eb2a0525eb4331d58fcbf9f7ca2e9c");
        test_keycalc(&session, tls_secret_application_client_iv, bin, "application_client_iv", "86e8be227c1bd2b3e39cb444");
        // {client}  derive secret "tls13 res master"
        test_keycalc(&session, tls_secret_res_master, bin, "res master", "09170c6d472721566f9cf99b08699daff561ec8fb22d5a32c3f94ce009b69975");
    }
    {
        // {client}  send alert record
        const char* record =
            "17 03 03 00 13 2e a6 cd f7 49 19 60"
            "23 e2 b3 a4 94 91 69 55 36 42 60 47";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("alert (close_notify)", &session, bin_record, from_client);
    }
    {
        // {server}  send alert record
        const char* record =
            "17 03 03 00 13 51 9f c5 07 5c b0 88"
            "43 49 75 9f f9 ef 6f 01 1b b4 c6 f2";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("alert (close_notify)", &session, bin_record, from_server);
    }
}
