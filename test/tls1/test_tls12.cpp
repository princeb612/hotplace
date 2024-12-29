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
 *  https://tls13.xargs.org/
 */

#include "sample.hpp"

void test_tls12_xargs_org() {
    _test_case.begin("https://tls12.xargs.org/");

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

    // https://tls12.xargs.org/#client-hello
    {
        const char* record =
            "16 03 01 00 A5 01 00 00 A1 03 03 00 01 02 03 04"
            "05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14"
            "15 16 17 18 19 1A 1B 1C 1D 1E 1F 00 00 20 CC A8"
            "CC A9 C0 2F C0 30 C0 2B C0 2C C0 13 C0 09 C0 14"
            "C0 0A 00 9C 00 9D 00 2F 00 35 C0 12 00 0A 01 00"
            "00 58 00 00 00 18 00 16 00 00 13 65 78 61 6D 70"
            "6C 65 2E 75 6C 66 68 65 69 6D 2E 6E 65 74 00 05"
            "00 05 01 00 00 00 00 00 0A 00 0A 00 08 00 1D 00"
            "17 00 18 00 19 00 0B 00 02 01 00 00 0D 00 12 00"
            "10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02"
            "03 FF 01 00 01 00 00 12 00 00 -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &session, bin_record, role_client);
    }
    // https://tls12.xargs.org/#server-hello
    {
        const char* record =
            "16 03 03 00 31 02 00 00 2D 03 03 70 71 72 73 74"
            "75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84"
            "85 86 87 88 89 8A 8B 8C 8D 8E 8F 00 C0 13 00 00"
            "05 FF 01 00 01 00 -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &session, bin_record, role_server);

        test_transcript_hash(&session, base16_decode_rfc("331f31e2702c54c318fef7d82f4ae6714bd5123b7be9d0c2b6428740cdb97356"));
    }
    // https://tls12.xargs.org/#server-certificate
    {
        const char* record =
            "16 03 03 03 2F 0B 00 03 2B 00 03 28 00 03 25 30"
            "82 03 21 30 82 02 09 A0 03 02 01 02 02 08 15 5A"
            "92 AD C2 04 8F 90 30 0D 06 09 2A 86 48 86 F7 0D"
            "01 01 0B 05 00 30 22 31 0B 30 09 06 03 55 04 06"
            "13 02 55 53 31 13 30 11 06 03 55 04 0A 13 0A 45"
            "78 61 6D 70 6C 65 20 43 41 30 1E 17 0D 31 38 31"
            "30 30 35 30 31 33 38 31 37 5A 17 0D 31 39 31 30"
            "30 35 30 31 33 38 31 37 5A 30 2B 31 0B 30 09 06"
            "03 55 04 06 13 02 55 53 31 1C 30 1A 06 03 55 04"
            "03 13 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68 65"
            "69 6D 2E 6E 65 74 30 82 01 22 30 0D 06 09 2A 86"
            "48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82"
            "01 0A 02 82 01 01 00 C4 80 36 06 BA E7 47 6B 08"
            "94 04 EC A7 B6 91 04 3F F7 92 BC 19 EE FB 7D 74"
            "D7 A8 0D 00 1E 7B 4B 3A 4A E6 0F E8 C0 71 FC 73"
            "E7 02 4C 0D BC F4 BD D1 1D 39 6B BA 70 46 4A 13"
            "E9 4A F8 3D F3 E1 09 59 54 7B C9 55 FB 41 2D A3"
            "76 52 11 E1 F3 DC 77 6C AA 53 37 6E CA 3A EC BE"
            "C3 AA B7 3B 31 D5 6C B6 52 9C 80 98 BC C9 E0 28"
            "18 E2 0B F7 F8 A0 3A FD 17 04 50 9E CE 79 BD 9F"
            "39 F1 EA 69 EC 47 97 2E 83 0F B5 CA 95 DE 95 A1"
            "E6 04 22 D5 EE BE 52 79 54 A1 E7 BF 8A 86 F6 46"
            "6D 0D 9F 16 95 1A 4C F7 A0 46 92 59 5C 13 52 F2"
            "54 9E 5A FB 4E BF D7 7A 37 95 01 44 E4 C0 26 87"
            "4C 65 3E 40 7D 7D 23 07 44 01 F4 84 FF D0 8F 7A"
            "1F A0 52 10 D1 F4 F0 D5 CE 79 70 29 32 E2 CA BE"
            "70 1F DF AD 6B 4B B7 11 01 F4 4B AD 66 6A 11 13"
            "0F E2 EE 82 9E 4D 02 9D C9 1C DD 67 16 DB B9 06"
            "18 86 ED C1 BA 94 21 02 03 01 00 01 A3 52 30 50"
            "30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 05 A0"
            "30 1D 06 03 55 1D 25 04 16 30 14 06 08 2B 06 01"
            "05 05 07 03 02 06 08 2B 06 01 05 05 07 03 01 30"
            "1F 06 03 55 1D 23 04 18 30 16 80 14 89 4F DE 5B"
            "CC 69 E2 52 CF 3E A3 00 DF B1 97 B8 1D E1 C1 46"
            "30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 03"
            "82 01 01 00 59 16 45 A6 9A 2E 37 79 E4 F6 DD 27"
            "1A BA 1C 0B FD 6C D7 55 99 B5 E7 C3 6E 53 3E FF"
            "36 59 08 43 24 C9 E7 A5 04 07 9D 39 E0 D4 29 87"
            "FF E3 EB DD 09 C1 CF 1D 91 44 55 87 0B 57 1D D1"
            "9B DF 1D 24 F8 BB 9A 11 FE 80 FD 59 2B A0 39 8C"
            "DE 11 E2 65 1E 61 8C E5 98 FA 96 E5 37 2E EF 3D"
            "24 8A FD E1 74 63 EB BF AB B8 E4 D1 AB 50 2A 54"
            "EC 00 64 E9 2F 78 19 66 0D 3F 27 CF 20 9E 66 7F"
            "CE 5A E2 E4 AC 99 C7 C9 38 18 F8 B2 51 07 22 DF"
            "ED 97 F3 2E 3E 93 49 D4 C6 6C 9E A6 39 6D 74 44"
            "62 A0 6B 42 C6 D5 BA 68 8E AC 3A 01 7B DD FC 8E"
            "2C FC AD 27 CB 69 D3 CC DC A2 80 41 44 65 D3 AE"
            "34 8C E0 F3 4A B2 FB 9C 61 83 71 31 2B 19 10 41"
            "64 1C 23 7F 11 A5 D6 5C 84 4F 04 04 84 99 38 71"
            "2B 95 9E D6 85 BC 5C 5D D6 45 ED 19 90 94 73 40"
            "29 26 DC B4 0E 34 69 A1 59 41 E8 E2 CC A8 4B B6"
            "08 46 36 A0 -- -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate", &session, bin_record, role_server);

        test_transcript_hash(&session, base16_decode_rfc("f0851dbc5eaf7c855ebf15e1cba14617ed0a2c6d520261f72abb689b197b56cb"));
    }
    // https://tls12.xargs.org/#server-key-exchange-generation
    binary_t shared_secret;
    {
        const char* kid = "server";
        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        crypto_key& keyexchange = session.get_tls_protection().get_keyexchange();
        keychain.add_ec_b16(&keyexchange, ec_x25519, x, y, d, keydesc(kid));

        dump_key(keyexchange.find(kid), &bs);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls12.xargs.org/#server-key-exchange
    {
        const char* record =
            "16 03 03 01 2C 0C 00 01 28 03 00 1D 20 9F D7 AD"
            "6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 A0 53 5B"
            "14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 04 01 01"
            "00 04 02 B6 61 F7 C1 91 EE 59 BE 45 37 66 39 BD"
            "C3 D4 BB 81 E1 15 CA 73 C8 34 8B 52 5B 0D 23 38"
            "AA 14 46 67 ED 94 31 02 14 12 CD 9B 84 4C BA 29"
            "93 4A AA CC E8 73 41 4E C1 1C B0 2E 27 2D 0A D8"
            "1F 76 7D 33 07 67 21 F1 3B F3 60 20 CF 0B 1F D0"
            "EC B0 78 DE 11 28 BE BA 09 49 EB EC E1 A1 F9 6E"
            "20 9D C3 6E 4F FF D3 6B 67 3A 7D DC 15 97 AD 44"
            "08 E4 85 C4 AD B2 C8 73 84 12 49 37 25 23 80 9E"
            "43 12 D0 C7 B3 52 2E F9 83 CA C1 E0 39 35 FF 13"
            "A8 E9 6B A6 81 A6 2E 40 D3 E7 0A 7F F3 58 66 D3"
            "D9 99 3F 9E 26 A6 34 C8 1B 4E 71 38 0F CD D6 F4"
            "E8 35 F7 5A 64 09 C7 DC 2C 07 41 0E 6F 87 85 8C"
            "7B 94 C0 1C 2E 32 F2 91 76 9E AC CA 71 64 3B 8B"
            "98 A9 63 DF 0A 32 9B EA 4E D6 39 7E 8C D0 1A 11"
            "0A B3 61 AC 5B AD 1C CD 84 0A 6C 8A 6E AA 00 1A"
            "9D 7D 87 DC 33 18 64 35 71 22 6C 4D D2 C2 AC 41"
            "FB -- -- -- -- -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_key_exchange", &session, bin_record, role_server);

        test_transcript_hash(&session, base16_decode_rfc("9f1b0b59a0bb1d533050e177f69addcf2243fbbcaa13d00ea8502dc66aef0414"));
    }
    // https://tls12.xargs.org/#server-hello-done
    {
        const char* record = "16 03 03 00 04 0e 00 00 00";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello_done", &session, bin_record, role_server);

        test_transcript_hash(&session, base16_decode_rfc("0d468c0e45b4e5da1baba29c3e835d8a9200e9d18ace76f360beab536275cab2"));
    }
    // https://tls12.xargs.org/#client-key-exchange-generation
    {
        const char* kid = "client";
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        crypto_key& keyexchange = session.get_tls_protection().get_keyexchange();
        keychain.add_ec_b16(&keyexchange, ec_x25519, x, y, d, keydesc(kid));
        basic_stream bs;
        dump_key(keyexchange.find(kid), &bs);
        _logger->writeln(bs);
    }
    // https://tls12.xargs.org/#client-key-exchange
    {
        const char* record =
            "16 03 03 00 25 10 00 00 21 20 35 80 72 D6 36 58"
            "80 D1 AE EA 32 9A DF 91 21 38 38 51 ED 21 A2 8E"
            "3B 75 E9 65 D0 D2 CD 16 62 54 -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_key_exchange", &session, bin_record, role_client);

        test_transcript_hash(&session, base16_decode_rfc("061dda04b3c2217ff73bd79b9cf88a2bb6ec505404aac8722db03ef417b54cb4"));
    }
    // https://tls12.xargs.org/#client-encryption-keys-calculation
    {
        binary_t secret_master;
        test_keycalc(&session, tls_secret_master, secret_master, "secret_master",
                     "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c");
        binary_t secret_client_mac_key;
        test_keycalc(&session, tls_secret_client_mac_key, secret_client_mac_key, "secret_client_mac_key", "1b7d117c7d5f690bc263cae8ef60af0f1878acc2");
        binary_t secret_server_mac_key;
        test_keycalc(&session, tls_secret_server_mac_key, secret_server_mac_key, "secret_server_mac_key", "2ad8bdd8c601a617126f63540eb20906f781fad2");
        binary_t secret_client_key;
        test_keycalc(&session, tls_secret_client_key, secret_client_key, "secret_client_key", "f656d037b173ef3e11169f27231a84b6");
        binary_t secret_server_key;
        test_keycalc(&session, tls_secret_server_key, secret_server_key, "secret_server_key", "752a18e7a9fcb7cbcdd8f98dd8f769eb");
        binary_t secret_client_iv;
        test_keycalc(&session, tls_secret_client_iv, secret_client_iv, "secret_client_iv", "a0d2550c9238eebfef5c32251abb67d6");
        binary_t secret_server_iv;
        test_keycalc(&session, tls_secret_server_iv, secret_server_iv, "secret_server_iv", "434528db4937d540d393135e06a11bb8");
    }  // https://tls12.xargs.org/#client-change-cipher-spec/
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client change-cipher-spec", &session, bin_record, role_client);

        test_transcript_hash(&session, base16_decode_rfc("061dda04b3c2217ff73bd79b9cf88a2bb6ec505404aac8722db03ef417b54cb4"));
    }
    // https://tls12.xargs.org/#client-handshake-finished
    {
        const char* record =
            "16 03 03 00 40 40 41 42 43 44 45 46 47 48 49 4A"
            "4B 4C 4D 4E 4F 22 7B C9 BA 81 EF 30 F2 A8 A7 8F"
            "F1 DF 50 84 4D 58 04 B7 EE B2 E2 14 C3 2B 68 92"
            "AC A3 DB 7B 78 07 7F DD 90 06 7C 51 6B AC B3 BA"
            "90 DE DF 72 0F -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client finished", &session, bin_record, role_client);
    }
    // https://tls12.xargs.org/#server-encryption-keys-calculation
    {
        //
    }  // https://tls12.xargs.org/#server-change-cipher-spec
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server change-cipher-spec", &session, bin_record, role_server);
    }
    // https://tls12.xargs.org/#server-handshake-finished
    {
        const char* record =
            "16 03 03 00 40 51 52 53 54 55 56 57 58 59 5A 5B"
            "5C 5D 5E 5F 60 18 E0 75 31 7B 10 03 15 F6 08 1F"
            "CB F3 13 78 1A AC 73 EF E1 9F E2 5B A1 AF 59 C2"
            "0B E9 4F C0 1B DA 2D 68 00 29 8B 73 A7 E8 49 D7"
            "4B D4 94 CF 7D -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server finished", &session, bin_record, role_server);
    }
    // https://tls12.xargs.org/#client-application-data
    {
        const char* record =
            "17 03 03 00 30 00 01 02 03 04 05 06 07 08 09 0A"
            "0B 0C 0D 0E 0F 6C 42 1C 71 C4 2B 18 3B FA 06 19"
            "5D 13 3D 0A 09 D0 0F C7 CB 4E 0F 5D 1C DA 59 D1"
            "47 EC 79 0C 99 -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client application data", &session, bin_record, role_client);
    }
    // https://tls12.xargs.org/#server-application-data
    {
        const char* record =
            "17 03 03 00 30 61 62 63 64 65 66 67 68 69 6A 6B"
            "6C 6D 6E 6F 70 97 83 48 8A F5 FA 20 BF 7A 2E F6"
            "9D EB B5 34 DB 9F B0 7A 8C 27 21 DE E5 40 9F 77"
            "AF 0C 3D DE 56 -- -- -- -- -- -- -- -- -- -- --";

        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server application data", &session, bin_record, role_server);
    }
    // https://tls12.xargs.org/#client-close-notify
    {
        const char* record =
            "15 03 03 00 30 10 11 12 13 14 15 16 17 18 19 1A"
            "1B 1C 1D 1E 1F 0D 83 F9 79 04 75 0D D8 FD 8A A1"
            "30 21 86 32 63 4F D0 65 E4 62 83 79 B8 8B BF 9E"
            "FD 12 87 A6 2D -- -- -- -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client close notify", &session, bin_record, role_client);
    }
}
