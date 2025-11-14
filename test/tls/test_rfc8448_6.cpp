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

void test_rfc8448_6() {
    _test_case.begin("RFC 8448 6.  Client Authentication");

    // The client uses a certificate with an RSA key
    // the server uses an Elliptic Curve Digital Signature Algorithm (ECDSA) certificate with a P-256 key

    return_t ret = errorcode_t::success;
    tls_session session;
    crypto_keychain keychain;
    auto& protection = session.get_tls_protection();
    binary_t bin;

    {
        // {client}  create an ephemeral x25519 key pair
        constexpr char constexpr_client[] = KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE;
        const char* x =
            "08 9c c2 67 1f 73 8d 9a 67 1e 5b 2e 46 49"
            "81 d0 5b 76 e3 61 aa 22 ae a9 1f 1d 49 ca 10 a7 a3 62";
        const char* y = nullptr;
        const char* d =
            "c0 40 b2 bb 8f 3a dd d2 0f d4 05 8c 54"
            "70 03 a3 c6 f9 c1 cd 91 5d 5e 53 5c 87 d8 d1 91 aa f0 71";
        crypto_key& key = protection.get_key();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_client));

        _logger->writeln(constexpr_client);
        _logger->writeln([&](basic_stream& bs) -> void { dump_key(key.find(constexpr_client), &bs); });

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        const char* record =
            "16 03 01 00 c0 01 00 00 bc 03 03 6a"
            "47 22 36 32 8b 83 af 40 38 6d 3a 3e 1f 1c e6 24 fa 4e d8 9a b8"
            "65 a4 ff 0f 41 44 ce 3a e2 33 00 00 06 13 01 13 03 13 02 01 00"
            "00 8d 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
            "01 03 01 04 00 33 00 26 00 24 00 1d 00 20 08 9c c2 67 1f 73 8d"
            "9a 67 1e 5b 2e 46 49 81 d0 5b 76 e3 61 aa 22 ae a9 1f 1d 49 ca"
            "10 a7 a3 62 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03"
            "06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05"
            "02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("client_hello", &session, from_client, bin_record);
    }
    {
        // {server}  create an ephemeral x25519 key pair
        constexpr char constexpr_server[] = KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE;
        const char* d =
            "73 82 a5 ad 1c dd 20 56 ae 18 cc 70 8b"
            "d0 07 d9 81 30 db e2 cd 4d 9e ad 9b 96 95 2b ec bb 08 88";
        const char* x =
            "6c 2e 50 e8 65 91 9a 6b 5a 12 df af 91 8f"
            "92 b4 42 56 7b 0f 89 bc 54 47 8c 69 21 36 66 58 f0 62";
        crypto_key& key = protection.get_key();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_server));

        _logger->writeln(constexpr_server);
        _logger->writeln([&](basic_stream& bs) -> void { dump_key(key.find(constexpr_server), &bs); });

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        const char* record =
            "16 03 03 00 5a 02 00 00 56 03 03 3b"
            "50 fd f1 c3 d5 72 e4 0e 68 95 3e 7f ff 4e 27 58 45 9c 59 af a0"
            "58 2c 0e a0 32 87 42 55 fe 6e 00 13 01 00 00 2e 00 33 00 24 00"
            "1d 00 20 6c 2e 50 e8 65 91 9a 6b 5a 12 df af 91 8f 92 b4 42 56"
            "7b 0f 89 bc 54 47 8c 69 21 36 66 58 f0 62 00 2b 00 02 03 04";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("server_hello", &session, from_server, bin_record);
    }
    {
        // {server}  extract secret "early"
        test_keycalc(&session, tls_secret_early_secret, bin, "early", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        // {server}  derive secret for handshake "tls13 derived"
        test_keycalc(&session, tls_secret_handshake_derived, bin, "derived", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        // {server}  extract secret "handshake"
        test_keycalc(&session, tls_secret_handshake, bin, "handshake", "d995243674fb6400d7d37bc0e9861bdbd9ed095601dcf2994874f2803de22e39");
        // {server}  derive secret "tls13 c hs traffic"
        test_keycalc(&session, tls_secret_c_hs_traffic, bin, "c hs traffic", "cec7a30c6872070f22a7eeb065768db67c45e29533db879908ce6dc66f5911de");
        // {server}  derive secret "tls13 s hs traffic"
        test_keycalc(&session, tls_secret_s_hs_traffic, bin, "s hs traffic", "8b02d3c00442a2722c4098ebe8675b23e801510f0d7ed778d8eb0b8f42a19a5e");
        // {server}  derive secret for master "tls13 derived"
        test_keycalc(&session, tls_secret_application_derived, bin, "application_derived", "74575526b07c81a9c1b17e6b34e0e6d084747a61f396f597ebb92c0736ec60e8");
        // {server}  extract secret "master"
        test_keycalc(&session, tls_secret_application, bin, "application", "57c15d7b9d441b3d40a9c6ea8a3d730e07b3a1ea7a3339ed7070b9a74a3f4f28");
    }
    {
        const char* record =
            "17 03 03 02 16 6d 0a 7a c0 79 b3 2a"
            "94 aa 68 c4 e2 89 3e 8b d0 d3 c1 85 f5 49 c2 36 fb bc e3 d6 47"
            "f0 8f 3c 94 a2 bf 42 4d 87 08 88 36 05 ad 89 55 f9 77 18 b0 21"
            "3d ea d1 3d fb 23 eb b8 38 1d a5 82 75 66 12 bc b5 a5 d4 08 47"
            "71 9f be 9f 17 9b fa e6 56 f3 ec fd 59 a4 c0 d3 51 32 ce 41 8a"
            "7e 46 f6 b6 a6 06 22 f8 a6 c0 6b 28 d8 33 60 16 35 63 be 9c 37"
            "f9 7e b9 02 32 69 24 a7 2b 3e d8 c8 38 12 77 d1 58 1c ab 9c 37"
            "15 ac 24 01 39 84 67 ad 7e bf ab 3d 0c 34 19 e7 50 10 4f 7d 62"
            "c5 02 79 01 f2 e4 cd 4c a5 b8 07 1e b0 3d 3c 73 2d 83 21 50 66"
            "df c4 d2 91 d4 c1 ff 3b 8d 7e 42 98 f6 77 d4 d5 1d ea 11 68 d8"
            "f1 6c b2 7b a4 02 66 31 3a 1f ed f9 e2 3c c7 7f 76 54 50 f9 e9"
            "6f 05 d0 8f 3d a2 45 b1 4d 49 46 f0 7e c8 1e ed 6d 56 f2 6b d5"
            "74 f0 b7 f7 c7 04 70 37 c1 6f ce 3b 23 75 4e 66 2f ad 73 e2 b7"
            "21 3f 6a f2 96 76 9c 99 a1 d3 8e 62 32 e0 ec 8d c4 f8 4d 6a a6"
            "f7 de 38 87 be 00 57 86 2f 90 18 e0 ab 39 67 05 aa 40 90 ab 5f"
            "2d ff 63 25 a5 57 e7 32 0d 4e ff d4 6b b4 f9 97 d1 63 20 7c ce"
            "66 65 29 4a a4 46 55 41 e3 fe 37 ee 73 50 65 9e a5 50 d6 dc b6"
            "af 3c 51 88 52 c7 a1 4c 3c c1 5b c3 2b 32 73 bd f1 75 1d a1 84"
            "20 31 35 b1 17 d3 00 20 4f b1 2d 58 ca 9a c3 4b 68 ec a2 70 30"
            "83 2f 7a 4b 46 d2 a5 57 57 f6 3f e8 f6 e8 5a c4 74 69 e6 19 8d"
            "a8 8a 64 58 6b f2 3c 69 59 0d e8 22 26 3b e7 5f d8 36 84 72 40"
            "c4 8f 8c 14 5c d6 bd 69 89 62 e7 ed c2 34 eb e5 92 31 35 1e ef"
            "8d 76 52 cf 3b 08 ab 3a f6 e5 ec 74 c5 8a 8d a3 4b 39 f9 b0 d6"
            "c4 27 9a 9a 1f 82 07 17 29 e7 05 9d d7 f7 b9 5b 94 33 c4 68 4c"
            "e1 89 1a 6d 33 43 2d 52 ed db 0b 8c ee 91 81 d4 03 ec cc 12 99"
            "1f 1a d4 aa 62 c3 60 49 71 3a 7b b1 35 fd da 66 61 a0 5a 93 f8"
            "c1 6f";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("encrypted_extensions certificate_request certificate certificate_verify finished", &session, from_server, bin_record);
    }
    {
        // {server}  derive write traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_server_key, bin, "handshake_server_key", "6cb6e60619d8c7355c5d4c4bc2be90d5");
        test_keycalc(&session, tls_secret_handshake_server_iv, bin, "handshake_server_iv", "64f239530c3b888fde85e0be");
        // {server}  derive secret "tls13 c ap traffic"
        test_keycalc(&session, tls_secret_c_ap_traffic, bin, "c ap traffic", "73c2e890fa8d067258d6d50fa92fe456b098cf00d9727eed91e8892ef4e6f860");
        // {server}  derive secret "tls13 s ap traffic":
        test_keycalc(&session, tls_secret_s_ap_traffic, bin, "s ap traffic", "c49a91faf57f8c545d5048a015bf849ff63942e4a7edcd319f8b438a97c52e21");
        // {server}  derive secret "tls13 exp master"
        test_keycalc(&session, tls_secret_exp_master, bin, "exp master", "052e39795e5f2be6e4e0974cfdd86c6a7afe3e57e5589810a3cccf642958beb2");
        // {server}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_server_key, bin, "application_server_key", "88b3123ddecadf8c1ba298e2c18176b0");
        test_keycalc(&session, tls_secret_application_server_iv, bin, "application_server_iv", "4e0978513f9de8327c08e4f3");
        // {server}  derive read traffic keys for handshake data
        test_keycalc(&session, tls_secret_handshake_client_key, bin, "handshake_client_key", "916948f728d9823fa41a004d083f217f");
        test_keycalc(&session, tls_secret_handshake_client_iv, bin, "handshake_client_iv", "64153d79bac9ea10ca5a0a88");
        // {client}  derive secret for handshake "tls13 derived"
        test_keycalc(&session, tls_secret_handshake_derived, bin, "handshake_derived", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    }
    {
        // {client}  construct a Certificate handshake message
        // {client}  construct a CertificateVerify handshake message
        // {client}  calculate finished "tls13 finished"

        const char* record =
            "17 03 03 02 80 b4 6a 63 93 4e 67 38"
            "41 ab af 26 74 03 bc 67 7f 6b 6d 2a 1e 2f 12 bb 5f 62 68 3b fe"
            "36 a8 26 73 f0 6d 62 87 dd d6 09 bc f2 f5 fd 32 25 92 3d 24 af"
            "3c 76 68 2c 18 0e e5 71 a1 7c a4 bf be 2f 51 0d c9 a0 e1 fc a5"
            "cf f2 ce e8 7d 11 cb 53 1a 6e f9 0b f5 30 9a 6b 63 bb bc 0b 88"
            "ea 45 10 3a 43 04 09 15 43 85 9f a1 1e c0 32 ed 87 34 44 cd 51"
            "85 ea d5 f6 a7 64 20 f0 f0 28 6a ce f8 02 c8 e4 78 8c 23 27 5f"
            "1b 06 da 60 0f 4a 7d ec d0 bc 59 d7 be f1 0e 64 9a e3 26 90 39"
            "7f c3 d4 ed 6f 30 f8 01 d8 cd 56 9b 71 ad 4f a0 5e a7 cf 2a c2"
            "df a1 50 d2 20 50 5d 40 11 b3 4d 09 d5 38 53 eb a6 1a 10 1e 4f"
            "8d ca 47 d8 17 1a 88 4b 19 25 9a 3d d4 8c 5a c1 41 98 3e dc 77"
            "81 4d 25 e7 f6 6b bb db 90 96 83 92 66 e0 65 61 82 8e cf b2 7e"
            "af d4 e9 e8 1a 0b 96 e3 bf a4 2d ae 5a d8 03 59 b9 a6 66 14 02"
            "c3 a2 10 41 77 03 01 06 db d8 f6 5b b6 a0 15 9d 51 2e b1 3a f2"
            "2a 25 9f 31 3b d5 8c 2e 21 fe 05 3d 57 f2 a9 62 b0 a4 ea 68 2c"
            "96 f7 0b 79 b5 60 13 61 92 82 3b 27 be 6a 2f b7 b1 c7 51 cc c0"
            "e3 30 36 15 54 14 85 b7 b3 07 b4 23 33 2c 11 ef a8 0b 72 f9 b8"
            "0a 53 e5 3f 7b b3 8a 3a f4 c5 9f 80 08 ba d0 54 4e 56 14 e6 88"
            "ff 57 bc cd 69 35 f8 1f 44 7f 42 0c 1c 1b f4 05 88 18 e9 0b f5"
            "dc 71 6c ca e4 25 24 85 6d f8 25 0b cd bd 7a f6 5f 82 dd 53 06"
            "1d 02 4f 6d 2f f5 c1 1e 37 92 a9 a7 0e 0e e2 a3 c2 0a 1b 96 8a"
            "c3 91 f8 f9 28 31 13 5d 25 24 2a da 2f e2 41 c2 65 3e c9 96 33"
            "9d fa 12 df ae 7a 33 73 df 88 b0 7c a2 7a ef 6d c2 66 a2 5f 13"
            "f7 5c 76 03 9c 1f 46 fd 7a 53 ae 63 99 c9 99 f4 b2 ae e1 8e 48"
            "0d 6d 12 bf ae 22 6b bd c9 2a 6a d5 0b 4d 3b ac 7a bc 3b 36 51"
            "eb 5b e5 6f 33 bf 41 12 7b 3c a8 86 dc 71 4a 50 d1 49 03 57 bd"
            "40 d9 fd 6b e4 22 09 a4 dd b9 eb b2 98 7e 29 f1 20 f0 58 14 61"
            "4d 2c 79 32 00 15 b4 61 fe 73 24 44 76 70 a1 af 5f 65 ca ed 15"
            "b4 74 ab 7f aa 49 50 16 ad f8 08 e5 3b 94 ef 54 af bb 0e 0a 3a"
            "27 32 ab 59 7f 7d 59 23 c7 73 86 aa 51 24 73 1f 8c c7 3e 70 3b"
            "34 1c 17 5a 45 49 39 a7 7a b6 43 13 c1 5c f3 fe 03 c4 f3 38 42"
            "56 49 76";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("certificate certificate_verify finished", &session, from_client, bin_record);
    }
    {
        // {client}  derive write traffic keys for application data
        test_keycalc(&session, tls_secret_application_client_key, bin, "application_client_key", "cdc09c806aa8f86dfcd51efc44a0c039");
        test_keycalc(&session, tls_secret_application_client_iv, bin, "application_client_iv", "6ef852e78b46d913668e53e7");
        // {client}  derive secret "tls13 res master"
        test_keycalc(&session, tls_secret_res_master, bin, "res master", "1006dccbf40eb4eb978bff0392a9e452a4fbad58aa14784d5a241c6b49daccfb");
    }
    {
        // {client}  send alert record
        const char* record =
            "17 03 03 00 13 e4 ad 7d 44 c2 92 45"
            "33 9d 35 59 62 c7 79 b8 9e f4 4c 58";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("alert (close_notify)", &session, from_client, bin_record);
    }
    {
        // {server}  send alert record
        const char* record =
            "17 03 03 00 13 1d ec c5 d6 e6 4b ba"
            "8a 6f 21 b4 fd 07 74 97 da 2a 90 cb";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("alert (close_notify)", &session, from_server, bin_record);
    }
}
