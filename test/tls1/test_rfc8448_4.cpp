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

// understanding ...
// replay mitigation not implemented

// RFC 8448 4.  Resumed 0-RTT Handshake
// This handshake resumes from the handshake in Section 3.
void test_rfc8448_4() {
    _test_case.begin("RFC 8448 4.  Resumed 0-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;
    crypto_keychain keychain;
    auto& protection = rfc8448_session.get_tls_protection();
    binary_t bin;

    // {client}  create an ephemeral x25519 key pair:
    {
        constexpr char constexpr_client[] = "client";
        const char* d =
            "bf f9 11 88 28 38 46 dd 6a 21 34 ef 71"
            "80 ca 2b 0b 14 fb 10 dc e7 07 b5 09 8c 0d dd c8 13 b2 df";
        const char* x =
            "e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34"
            "6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b";
        crypto_key& key = protection.get_keyexchange();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_client));

        _logger->writeln(constexpr_client);
        dump_key(key.find(constexpr_client), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }

    // {client}  send handshake record:
    {
        const char* record =
            "16 03 01 02 00 01 00 01 fc 03 03 1b"
            "c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49"
            "d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00"
            "01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
            "01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d"
            "96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1"
            "8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
            "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
            "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"
            "00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59"
            "ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb"
            "33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc"
            "55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3"
            "6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66"
            "4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29"
            "51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72"
            "14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6"
            "21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93"
            "4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca"
            "3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f"
            "9d";
        // verify PSK binder == finished
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &rfc8448_session, bin_record, role_client);
    }
    {
        openssl_kdf kdf;
        binary_t context;

        binary_t bin;
        test_keycalc(&rfc8448_session, tls_secret_res_master, bin, "secret_resumption_master",
                     "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");
        test_keycalc(&rfc8448_session, tls_secret_resumption, bin, "secret_resumption", "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
        test_keycalc(&rfc8448_session, tls_secret_resumption_early, bin, "secret_resumption_early",
                     "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");

        // tls_extension_pre_shared_key
        test_keycalc(&rfc8448_session, tls_context_resumption_binder_hash, bin, "binder_hash",
                     "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
        test_keycalc(&rfc8448_session, tls_context_resumption_binder_key, bin, "binder key (PRK)",
                     "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256");
        test_keycalc(&rfc8448_session, tls_context_resumption_finished_key, bin, "finished key (expanded)",
                     "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa");
        test_keycalc(&rfc8448_session, tls_context_resumption_finished, bin, "finished (PSK binder)",
                     "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

        // {client}  derive secret "tls13 c e traffic"
        test_keycalc(&rfc8448_session, tls_secret_c_e_traffic, bin, "c e traffic", "3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62");
        // {client}  derive secret "tls13 e exp master"
        test_keycalc(&rfc8448_session, tls_secret_e_exp_master, bin, "e exp master", "b2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df");
        // {client}  derive write traffic keys for early application data
        test_keycalc(&rfc8448_session, tls_secret_c_e_traffic_key, bin, "secret_c_e_traffic_key", "920205a5b7bf2115e6fc5c2942834f54");
        test_keycalc(&rfc8448_session, tls_secret_c_e_traffic_iv, bin, "secret_c_e_traffic_iv", "6d475f0993c8e564610db2b9");
    }
    {
        // {client}  send application_data record
        const char* record =
            "17 03 03 00 17 ab 1d f4 20 e7 5c 45"
            "7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0";
        // application_data after CH (decryption)
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("application_data", &rfc8448_session, bin_record, role_client);
    }
    {
        // {server}  create an ephemeral x25519 key pair
        constexpr char constexpr_server[] = "server";
        const char* d =
            "de 5b 44 76 e7 b4 90 b2 65 2d 33 8a cb"
            "f2 94 80 66 f2 55 f9 44 0e 23 b9 8f c6 98 35 29 8d c1 07";
        const char* x =
            "12 17 61 ee 42 c3 33 e1 b9 e7 7b 60 dd 57"
            "c2 05 3c d9 45 12 ab 47 f1 15 e8 6e ff 50 94 2c ea 31";
        crypto_key& key = protection.get_keyexchange();
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_server));

        _logger->writeln(constexpr_server);
        dump_key(key.find(constexpr_server), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    {
        // {server}  construct a ServerHello handshake message
        const char* record =
            "16 03 03 00 60 02 00 00 5c 03 03 3c"
            "cf d2 de c8 90 22 27 63 47 2a e8 13 67 77 c9 d7 35 87 77 bb 66"
            "e9 1e a5 12 24 95 f5 59 ea 2d 00 13 01 00 00 34 00 29 00 02 00"
            "00 00 33 00 24 00 1d 00 20 12 17 61 ee 42 c3 33 e1 b9 e7 7b 60"
            "dd 57 c2 05 3c d9 45 12 ab 47 f1 15 e8 6e ff 50 94 2c ea 31 00"
            "2b 00 02 03 04";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &rfc8448_session, bin_record, role_server);
    }
    {
        // {server}  derive secret for handshake "tls13 derived"
        test_keycalc(&rfc8448_session, tls_secret_handshake_derived, bin, "derived", "5f1790bbd82c5e7d376ed2e1e52f8e6038c9346db61b43be9a52f77ef3998e80");
        // {server}  extract secret "handshake"
        test_keycalc(&rfc8448_session, tls_secret_handshake, bin, "secret", "005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6");
        // {server}  derive secret "tls13 c hs traffic"
        test_keycalc(&rfc8448_session, tls_secret_c_hs_traffic, bin, "c hs traffic", "2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f");
        // {server}  derive secret "tls13 s hs traffic"
        test_keycalc(&rfc8448_session, tls_secret_s_hs_traffic, bin, "s hs traffic", "fe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803");
        // {server}  derive write traffic keys for handshake data
        test_keycalc(&rfc8448_session, tls_secret_handshake_server_key, bin, "secret_handshake_server_key", "27c6bdc0a3dcea39a47326d79bc9e4ee");
        test_keycalc(&rfc8448_session, tls_secret_handshake_server_iv, bin, "secret_handshake_server_iv", "9569ecdd4d0536705e9ef725");
    }
    {
        // construct an EncryptedExtensions handshake message
        // {server}  construct a Finished handshake message
        // {server}  send handshake record
        const char* record =
            "17 03 03 00 61 dc 48 23 7b 4b 87 9f"
            "50 d0 d4 d2 62 ea 8b 47 16 eb 40 dd c1 eb 95 7e 11 12 6e 8a 71"
            "49 c2 d0 12 d3 7a 71 15 95 7e 64 ce 30 00 8b 9e 03 23 f2 c0 5a"
            "9c 1c 77 b4 f3 78 49 a6 95 ab 25 50 60 a3 3f ee 77 0c a9 5c b8"
            "48 6b fd 08 43 b8 70 24 86 5c a3 5c c4 1c 4e 51 5c 64 dc b1 36"
            "9f 98 63 5b c7 a5";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("encrypted_extensions .. finished", &rfc8448_session, bin_record, role_server);
    }
    {
        // {server}  derive secret "tls13 c ap traffic"
        test_keycalc(&rfc8448_session, tls_secret_application_client, bin, "secret_application_client",
                     "2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1");
        // {server}  derive secret "tls13 s ap traffic"
        test_keycalc(&rfc8448_session, tls_secret_application_server, bin, "secret_application_server",
                     "cc21f1bf8feb7dd5fa505bd9c4b468a9984d554a993dc49e6d285598fb672691");
        // {server}  derive secret "tls13 exp master"
        test_keycalc(&rfc8448_session, tls_secret_exporter_master, bin, "secret_exporter_master",
                     "3fd93d4ffddc98e64b14dd107aedf8ee4add23f4510f58a4592d0b201bee56b4");
        // {server}  derive write traffic keys for application data
        test_keycalc(&rfc8448_session, tls_secret_application_server_key, bin, "secret_application_server_key", "e857c690a34c5a9129d833619684f95e");
        test_keycalc(&rfc8448_session, tls_secret_application_server_iv, bin, "secret_application_server_iv", "0685d6b561aab9ef1013faf9");
        // {server}  derive read traffic keys for early application data (same as client early application data write traffic keys)
    }
    // {client}  construct an EndOfEarlyData handshake message
    // {client}  send handshake record
    {
        const char* record =
            "17 03 03 00 15 ac a6 fc 94 48 41 29"
            "8d f9 95 93 72 5f 9b f9 75 44 29 b1 2f 09";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("end_of_early_data", &rfc8448_session, bin_record, role_client);
    }
    {
        // {client}  construct a Finished handshake message
        // {client}  send handshake record
        const char* record =
            "17 03 03 00 35 00 f8 b4 67 d1 4c f2"
            "2a 4b 3f 0b 6a e0 d8 e6 cc 8d 08 e0 db 35 15 ef 5c 2b df 19 22"
            "ea fb b7 00 09 96 47 16 d8 34 fb 70 c3 d2 a5 6c 5b 1f 5f 6b db"
            "a6 c3 33 cf";
        // binary_t bin_record = base16_decode_rfc(record);
        // dump_record("finished", &rfc8448_session, bin_record, role_client);
    }
    {
        // {client}  send application_data record
        const char* record =
            "17 03 03 00 43 b1 ce bc e2 42 aa 20"
            "1b e9 ae 5e 1c b2 a9 aa 4b 33 d4 e8 66 af 1e db 06 89 19 23 77"
            "41 aa 03 1d 7a 74 d4 91 c9 9b 9d 4e 23 2b 74 20 6b c6 fb aa 04"
            "fe 78 be 44 a9 b4 f5 43 20 a1 7e b7 69 92 af ac 31 03";
    }
    {
        // {server}  send application_data record
        const char* record =
            "17 03 03 00 43 27 5e 9f 20 ac ff 57"
            "bc 00 06 57 d3 86 7d f0 39 cc cf 79 04 78 84 cf 75 77 17 46 f7"
            "40 b5 a8 3f 46 2a 09 54 c3 58 13 93 a2 03 a2 5a 7d d1 41 41 ef"
            "1a 37 90 0c db 62 ff 62 de e1 ba 39 ab 25 90 cb f1 94";
    }
    {
        // {client}  send alert record
        const char* record =
            "17 03 03 00 13 0f ac ce 32 46 bd fc"
            "63 69 83 8d 6a 82 ae 6d e5 d4 22 dc";
    }
    {
        // {server}  send alert record
        const char* record =
            "17 03 03 00 13 5b 18 af 44 4e 8e 1e"
            "ec 71 58 fb 62 d8 f2 57 7d 37 ba 5d";
    }
}
