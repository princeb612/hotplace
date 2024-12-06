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

void test_tls13_xargs_org() {
    _test_case.begin("https://tls13.xargs.org/");

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

    {
        const char* servercert =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE\n"
            "BhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx\n"
            "MDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo\n"
            "ZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr\n"
            "CJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK\n"
            "E+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng\n"
            "KBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2\n"
            "Rm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP\n"
            "eh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5\n"
            "BhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\n"
            "AQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB\n"
            "RjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+\n"
            "/zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5\n"
            "jN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m\n"
            "f85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938\n"
            "jiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4\n"
            "cSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==\n"
            "-----END CERTIFICATE-----";

        crypto_key key;
        keychain.load_cert(&key, servercert, 0);

        dump_key(key.any(), &bs);
        _logger->writeln(bs);
        bs.clear();
    }

    /**
     * https://tls13.xargs.org/#client-key-exchange-generation
     */
    {
        crypto_key key;
        // Client Key Exchange Generation
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc("client key"));
        basic_stream bs;
        dump_key(key.find("client key"), &bs);
        _logger->writeln(bs);

        // > handshake type 1 (client_hello)
        //   > extension - 0033 key_share
        //    > extension len 38
        //    > group 0x001d (x25519)
        //    > public key len 32
        //      00000000 : 35 80 72 D6 36 58 80 D1 AE EA 32 9A DF 91 21 38 | 5.r.6X....2...!8
        //      00000010 : 38 51 ED 21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54 | 8Q.!..;u.e....bT
        //      358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
    }
    /**
     * C -> S
     * https://tls13.xargs.org/#client-hello
     */
    {
        const char* record =
            "16 03 01 00 F8 01 00 00 F4 03 03 00 01 02 03 04"
            "05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14"
            "15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 00 08 13 02"
            "13 03 13 01 00 FF 01 00 00 A3 00 00 00 18 00 16"
            "00 00 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68 65"
            "69 6D 2E 6E 65 74 00 0B 00 04 03 00 01 02 00 0A"
            "00 16 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00"
            "01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00"
            "00 17 00 00 00 0D 00 1E 00 1C 04 03 05 03 06 03"
            "08 07 08 08 08 09 08 0A 08 0B 08 04 08 05 08 06"
            "04 01 05 01 06 01 00 2B 00 03 02 03 04 00 2D 00"
            "02 01 01 00 33 00 26 00 24 00 1D 00 20 35 80 72"
            "D6 36 58 80 D1 AE EA 32 9A DF 91 21 38 38 51 ED"
            "21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54 -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello", &session, bin_record, role_client);
    }
    /**
     * https://tls13.xargs.org/#server-key-exchange-generation
     */
    binary_t shared_secret;
    {
        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        crypto_key& server_keys = session.get_tls_protection().get_key();
        keychain.add_ec_b16(&server_keys, "X25519", x, y, d, keydesc("server key"));

        dump_key(server_keys.find("server key"), &bs);
        _logger->writeln(bs);
        bs.clear();
    }
    /**
     * S -> C
     * https://tls13.xargs.org/#server-hello
     */
    {
        const char* record =
            "16 03 03 00 7A 02 00 00 76 03 03 70 71 72 73 74"
            "75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84"
            "85 86 87 88 89 8A 8B 8C 8D 8E 8F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 13 02 00 00"
            "2E 00 2B 00 02 03 04 00 33 00 24 00 1D 00 20 9F"
            "D7 AD 6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 A0"
            "53 5B 14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello", &session, bin_record, role_server);
    }

    // > handshake type 2 (server_hello)
    //  > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
    uint16 cipher_suite = session.get_tls_protection().get_cipher_suite();
    _test_case.assert(0x1302 == cipher_suite, __FUNCTION__, "cipher suite");

    /**
     * https://quic.xargs.org/#server-handshake-server_keys-calc
     */
    {
        binary_t hello_hash;
        test_keycalc(&session, tls_secret_hello_hash, hello_hash, "hello_hash",
                     "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");

        binary_t shared_secret;
        test_keycalc(&session, tls_secret_shared_secret, shared_secret, "shared_secret", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");

        binary_t early_secret;
        test_keycalc(&session, tls_secret_early_secret, early_secret, "early_secret",
                     "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5");
        binary_t empty_hash;
        test_keycalc(&session, tls_secret_empty_hash, empty_hash, "empty_hash",
                     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        binary_t secret_handshake_derived;
        test_keycalc(&session, tls_secret_handshake_derived, secret_handshake_derived, "secret_handshake_derived",
                     "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b");
        binary_t secret_handshake;
        test_keycalc(&session, tls_secret_handshake, secret_handshake, "secret_handshake",
                     "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");
        binary_t secret_handshake_client;
        test_keycalc(&session, tls_secret_handshake_client, secret_handshake_client, "secret_handshake_client",
                     "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");
        binary_t secret_handshake_server;
        test_keycalc(&session, tls_secret_handshake_server, secret_handshake_server, "secret_handshake_server",
                     "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");
        binary_t client_handshake_key;
        test_keycalc(&session, tls_secret_handshake_client_key, client_handshake_key, "client_handshake_key",
                     "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69");
        binary_t client_handshake_iv;
        test_keycalc(&session, tls_secret_handshake_client_iv, client_handshake_iv, "client_handshake_iv", "4256d2e0e88babdd05eb2f27");
        binary_t server_handshake_key;
        test_keycalc(&session, tls_secret_handshake_server_key, server_handshake_key, "server_handshake_key",
                     "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f");
        binary_t server_handshake_iv;
        test_keycalc(&session, tls_secret_handshake_server_iv, server_handshake_iv, "server_handshake_iv", "9563bc8b590f671f488d2da3");
    }
    /**
     * S -> C
     * https://tls13.xargs.org/#server-change-cipher-spec
     */
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("change cipher spec", &session, bin_record, role_server);
    }

    /**
     * S -> C
     * https://tls13.xargs.org/#wrapped-record
     */
    {
        const char* record =
            "17 03 03 00 17 6B E0 2F 9D A7 C2 DC 9D DE F5 6F"
            "24 68 B9 0A DF A2 51 01 AB 03 44 AE -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record (encrypted_extensions)", &session, bin_record, role_server);

        // TODO
        // https://tls13.xargs.org/#server-encrypted-extensions/annotated

        // > decrypted
        //   00000000 : 08 00 00 02 00 00 16 -- -- -- -- -- -- -- -- -- | .......
    }
    /**
     * S -> C
     * https://tls13.xargs.org/#wrapped-record-2
     */
    {
        const char* record =
            "17 03 03 03 43 BA F0 0A 9B E5 0F 3F 23 07 E7 26"
            "ED CB DA CB E4 B1 86 16 44 9D 46 C6 20 7A F6 E9"
            "95 3E E5 D2 41 1B A6 5D 31 FE AF 4F 78 76 4F 2D"
            "69 39 87 18 6C C0 13 29 C1 87 A5 E4 60 8E 8D 27"
            "B3 18 E9 8D D9 47 69 F7 73 9C E6 76 83 92 CA CA"
            "8D CC 59 7D 77 EC 0D 12 72 23 37 85 F6 E6 9D 6F"
            "43 EF FA 8E 79 05 ED FD C4 03 7E EE 59 33 E9 90"
            "A7 97 2F 20 69 13 A3 1E 8D 04 93 13 66 D3 D8 BC"
            "D6 A4 A4 D6 47 DD 4B D8 0B 0F F8 63 CE 35 54 83"
            "3D 74 4C F0 E0 B9 C0 7C AE 72 6D D2 3F 99 53 DF"
            "1F 1C E3 AC EB 3B 72 30 87 1E 92 31 0C FB 2B 09"
            "84 86 F4 35 38 F8 E8 2D 84 04 E5 C6 C2 5F 66 A6"
            "2E BE 3C 5F 26 23 26 40 E2 0A 76 91 75 EF 83 48"
            "3C D8 1E 6C B1 6E 78 DF AD 4C 1B 71 4B 04 B4 5F"
            "6A C8 D1 06 5A D1 8C 13 45 1C 90 55 C4 7D A3 00"
            "F9 35 36 EA 56 F5 31 98 6D 64 92 77 53 93 C4 CC"
            "B0 95 46 70 92 A0 EC 0B 43 ED 7A 06 87 CB 47 0C"
            "E3 50 91 7B 0A C3 0C 6E 5C 24 72 5A 78 C4 5F 9F"
            "5F 29 B6 62 68 67 F6 F7 9C E0 54 27 35 47 B3 6D"
            "F0 30 BD 24 AF 10 D6 32 DB A5 4F C4 E8 90 BD 05"
            "86 92 8C 02 06 CA 2E 28 E4 4E 22 7A 2D 50 63 19"
            "59 35 DF 38 DA 89 36 09 2E EF 01 E8 4C AD 2E 49"
            "D6 2E 47 0A 6C 77 45 F6 25 EC 39 E4 FC 23 32 9C"
            "79 D1 17 28 76 80 7C 36 D7 36 BA 42 BB 69 B0 04"
            "FF 55 F9 38 50 DC 33 C1 F9 8A BB 92 85 83 24 C7"
            "6F F1 EB 08 5D B3 C1 FC 50 F7 4E C0 44 42 E6 22"
            "97 3E A7 07 43 41 87 94 C3 88 14 0B B4 92 D6 29"
            "4A 05 40 E5 A5 9C FA E6 0B A0 F1 48 99 FC A7 13"
            "33 31 5E A0 83 A6 8E 1D 7C 1E 4C DC 2F 56 BC D6"
            "11 96 81 A4 AD BC 1B BF 42 AF D8 06 C3 CB D4 2A"
            "07 6F 54 5D EE 4E 11 8D 0B 39 67 54 BE 2B 04 2A"
            "68 5D D4 72 7E 89 C0 38 6A 94 D3 CD 6E CB 98 20"
            "E9 D4 9A FE ED 66 C4 7E 6F C2 43 EA BE BB CB 0B"
            "02 45 38 77 F5 AC 5D BF BD F8 DB 10 52 A3 C9 94"
            "B2 24 CD 9A AA F5 6B 02 6B B9 EF A2 E0 13 02 B3"
            "64 01 AB 64 94 E7 01 8D 6E 5B 57 3B D3 8B CE F0"
            "23 B1 FC 92 94 6B BC A0 20 9C A5 FA 92 6B 49 70"
            "B1 00 91 03 64 5C B1 FC FE 55 23 11 FF 73 05 58"
            "98 43 70 03 8F D2 CC E2 A9 1F C7 4D 6F 3E 3E A9"
            "F8 43 EE D3 56 F6 F8 2D 35 D0 3B C2 4B 81 B5 8C"
            "EB 1A 43 EC 94 37 E6 F1 E5 0E B6 F5 55 E3 21 FD"
            "67 C8 33 2E B1 B8 32 AA 8D 79 5A 27 D4 79 C6 E2"
            "7D 5A 61 03 46 83 89 19 03 F6 64 21 D0 94 E1 B0"
            "0A 9A 13 8D 86 1E 6F 78 A2 0A D3 E1 58 00 54 D2"
            "E3 05 25 3C 71 3A 02 FE 1E 28 DE EE 73 36 24 6F"
            "6A E3 43 31 80 6B 46 B4 7B 83 3C 39 B9 D3 1C D3"
            "00 C2 A6 ED 83 13 99 77 6D 07 F5 70 EA F0 05 9A"
            "2C 68 A5 F3 AE 16 B6 17 40 4A F7 B7 23 1A 4D 94"
            "27 58 FC 02 0B 3F 23 EE 8C 15 E3 60 44 CF D6 7C"
            "D6 40 99 3B 16 20 75 97 FB F3 85 EA 7A 4D 99 E8"
            "D4 56 FF 83 D4 1F 7B 8B 4F 06 9B 02 8A 2A 63 A9"
            "19 A7 0E 3A 10 E3 08 41 58 FA A5 BA FA 30 18 6C"
            "6B 2F 23 8E B5 30 C7 3E -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-2 (certificate)", &session, bin_record, role_server);
    }
    /**
     * S -> C
     * https://tls13.xargs.org/certificate.html#server-certificate-detail/annotated
     */
    {
        const char* cert =
            "30 82 03 21 30 82 02 09 A0 03 02 01 02 02 08 15"
            "5A 92 AD C2 04 8F 90 30 0D 06 09 2A 86 48 86 F7"
            "0D 01 01 0B 05 00 30 22 31 0B 30 09 06 03 55 04"
            "06 13 02 55 53 31 13 30 11 06 03 55 04 0A 13 0A"
            "45 78 61 6D 70 6C 65 20 43 41 30 1E 17 0D 31 38"
            "31 30 30 35 30 31 33 38 31 37 5A 17 0D 31 39 31"
            "30 30 35 30 31 33 38 31 37 5A 30 2B 31 0B 30 09"
            "06 03 55 04 06 13 02 55 53 31 1C 30 1A 06 03 55"
            "04 03 13 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68"
            "65 69 6D 2E 6E 65 74 30 82 01 22 30 0D 06 09 2A"
            "86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30"
            "82 01 0A 02 82 01 01 00 C4 80 36 06 BA E7 47 6B"
            "08 94 04 EC A7 B6 91 04 3F F7 92 BC 19 EE FB 7D"
            "74 D7 A8 0D 00 1E 7B 4B 3A 4A E6 0F E8 C0 71 FC"
            "73 E7 02 4C 0D BC F4 BD D1 1D 39 6B BA 70 46 4A"
            "13 E9 4A F8 3D F3 E1 09 59 54 7B C9 55 FB 41 2D"
            "A3 76 52 11 E1 F3 DC 77 6C AA 53 37 6E CA 3A EC"
            "BE C3 AA B7 3B 31 D5 6C B6 52 9C 80 98 BC C9 E0"
            "28 18 E2 0B F7 F8 A0 3A FD 17 04 50 9E CE 79 BD"
            "9F 39 F1 EA 69 EC 47 97 2E 83 0F B5 CA 95 DE 95"
            "A1 E6 04 22 D5 EE BE 52 79 54 A1 E7 BF 8A 86 F6"
            "46 6D 0D 9F 16 95 1A 4C F7 A0 46 92 59 5C 13 52"
            "F2 54 9E 5A FB 4E BF D7 7A 37 95 01 44 E4 C0 26"
            "87 4C 65 3E 40 7D 7D 23 07 44 01 F4 84 FF D0 8F"
            "7A 1F A0 52 10 D1 F4 F0 D5 CE 79 70 29 32 E2 CA"
            "BE 70 1F DF AD 6B 4B B7 11 01 F4 4B AD 66 6A 11"
            "13 0F E2 EE 82 9E 4D 02 9D C9 1C DD 67 16 DB B9"
            "06 18 86 ED C1 BA 94 21 02 03 01 00 01 A3 52 30"
            "50 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 05"
            "A0 30 1D 06 03 55 1D 25 04 16 30 14 06 08 2B 06"
            "01 05 05 07 03 02 06 08 2B 06 01 05 05 07 03 01"
            "30 1F 06 03 55 1D 23 04 18 30 16 80 14 89 4F DE"
            "5B CC 69 E2 52 CF 3E A3 00 DF B1 97 B8 1D E1 C1"
            "46 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00"
            "03 82 01 01 00 59 16 45 A6 9A 2E 37 79 E4 F6 DD"
            "27 1A BA 1C 0B FD 6C D7 55 99 B5 E7 C3 6E 53 3E"
            "FF 36 59 08 43 24 C9 E7 A5 04 07 9D 39 E0 D4 29"
            "87 FF E3 EB DD 09 C1 CF 1D 91 44 55 87 0B 57 1D"
            "D1 9B DF 1D 24 F8 BB 9A 11 FE 80 FD 59 2B A0 39"
            "8C DE 11 E2 65 1E 61 8C E5 98 FA 96 E5 37 2E EF"
            "3D 24 8A FD E1 74 63 EB BF AB B8 E4 D1 AB 50 2A"
            "54 EC 00 64 E9 2F 78 19 66 0D 3F 27 CF 20 9E 66"
            "7F CE 5A E2 E4 AC 99 C7 C9 38 18 F8 B2 51 07 22"
            "DF ED 97 F3 2E 3E 93 49 D4 C6 6C 9E A6 39 6D 74"
            "44 62 A0 6B 42 C6 D5 BA 68 8E AC 3A 01 7B DD FC"
            "8E 2C FC AD 27 CB 69 D3 CC DC A2 80 41 44 65 D3"
            "AE 34 8C E0 F3 4A B2 FB 9C 61 83 71 31 2B 19 10"
            "41 64 1C 23 7F 11 A5 D6 5C 84 4F 04 04 84 99 38"
            "71 2B 95 9E D6 85 BC 5C 5D D6 45 ED 19 90 94 73"
            "40 29 26 DC B4 0E 34 69 A1 59 41 E8 E2 CC A8 4B"
            "B6 08 46 36 A0 -- -- -- -- -- -- -- -- -- -- --";

        // # openssl x509 -in server.crt -text
    }
    /**
     * S -> C
     * https://tls13.xargs.org/#wrapped-record-3
     * https://tls13.xargs.org/#server-certificate-verify
     */
    {
        const char* record =
            "17 03 03 01 19 73 71 9F CE 07 EC 2F 6D 3B BA 02"
            "92 A0 D4 0B 27 70 C0 6A 27 17 99 A5 33 14 F6 F7"
            "7F C9 5C 5F E7 B9 A4 32 9F D9 54 8C 67 0E BE EA"
            "2F 2D 5C 35 1D D9 35 6E F2 DC D5 2E B1 37 BD 3A"
            "67 65 22 F8 CD 0F B7 56 07 89 AD 7B 0E 3C AB A2"
            "E3 7E 6B 41 99 C6 79 3B 33 46 ED 46 CF 74 0A 9F"
            "A1 FE C4 14 DC 71 5C 41 5C 60 E5 75 70 3C E6 A3"
            "4B 70 B5 19 1A A6 A6 1A 18 FA FF 21 6C 68 7A D8"
            "D1 7E 12 A7 E9 99 15 A6 11 BF C1 A2 BE FC 15 E6"
            "E9 4D 78 46 42 E6 82 FD 17 38 2A 34 8C 30 10 56"
            "B9 40 C9 84 72 00 40 8B EC 56 C8 1E A3 D7 21 7A"
            "B8 E8 5A 88 71 53 95 89 9C 90 58 7F 72 E8 DD D7"
            "4B 26 D8 ED C1 C7 C8 37 D9 F2 EB BC 26 09 62 21"
            "90 38 B0 56 54 A6 3A 0B 12 99 9B 4A 83 06 A3 DD"
            "CC 0E 17 C5 3B A8 F9 C8 03 63 F7 84 13 54 D2 91"
            "B4 AC E0 C0 F3 30 C0 FC D5 AA 9D EE F9 69 AE 8A"
            "B2 D9 8D A8 8E BB 6E A8 0A 3A 11 F0 0E A2 96 A3"
            "23 23 67 FF 07 5E 1C 66 DD 9C BE DC 47 13 -- --";
        binary_t bin_record = base16_decode_rfc(record);
        // > handshake type 15 (certificate_verify)
        //  > signature algorithm 0x0804 rsa_pss_rsae_sha256
        //  > len 0x0100(256)
        dump_record("wrapped-record-3 (certificate_verify)", &session, bin_record, role_server);
    }
    /**
     * S -> C
     * https://tls13.xargs.org/#wrapped-record-4
     * https://tls13.xargs.org/#server-handshake-finished
     */
    {
        const char* record =
            "17 03 03 00 45 10 61 DE 27 E5 1C 2C 9F 34 29 11"
            "80 6F 28 2B 71 0C 10 63 2C A5 00 67 55 88 0D BF"
            "70 06 00 2D 0E 84 FE D9 AD F2 7A 43 B5 19 23 03"
            "E4 DF 5C 28 5D 58 E3 C7 62 24 07 84 40 C0 74 23"
            "74 74 4A EC F2 8C F3 18 2F D0 -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-4 (finished)", &session, bin_record, role_server);
    }
    /**
     * https://tls13.xargs.org/#server-application-keys-calc
     * https://tls13.xargs.org/#client-application-keys-calc
     */
    {
        binary_t secret_application_derived;
        test_keycalc(&session, tls_secret_application_derived, secret_application_derived, "secret_application_derived",
                     "be3a8cdfcd10e46d3fe5d2902568518993ae43f2fb7c5438cde4776d1bc220242041a83f388266fd07b0177bf29e9486");
        binary_t secret_application;
        test_keycalc(&session, tls_secret_application, secret_application, "secret_application",
                     "2931209e1b7840e16d0d6bfd4bda1102f3a984f1162dc450f9606654f45bd55d9cb8857a8d14b59b98d7250fee55d3c3");
        binary_t secret_application_client;
        test_keycalc(&session, tls_secret_application_client, secret_application_client, "secret_application_client",
                     "9e47af27cb60d818a9ea7d233cb5ed4cc525fcd74614fb24b0ee59acb8e5aa7ff8d88b89792114208fec291a6fa96bad");
        binary_t secret_application_client_key;
        test_keycalc(&session, tls_secret_application_client_key, secret_application_client_key, "secret_application_client_key",
                     "de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc");
        binary_t secret_application_client_iv;
        test_keycalc(&session, tls_secret_application_client_iv, secret_application_client_iv, "secret_application_client_iv", "bb007956f474b25de902432f");
        binary_t secret_application_server;
        test_keycalc(&session, tls_secret_application_server, secret_application_server, "secret_application_server",
                     "86c967fd7747a36a0685b4ed8d0e6b4c02b4ddaf3cd294aa44e9f6b0183bf911e89a189ba5dfd71fccffb5cc164901f8");
        binary_t secret_application_server_key;
        test_keycalc(&session, tls_secret_application_server_key, secret_application_server_key, "secret_application_server_key",
                     "01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27");
        binary_t secret_application_server_iv;
        test_keycalc(&session, tls_secret_application_server_iv, secret_application_server_iv, "secret_application_server_iv", "196a750b0c5049c0cc51a541");
    }
    /**
     * C -> S
     * https://tls13.xargs.org/#client-change-cipher-spec/annotated
     */
    {
        const char* record = "14 03 03 00 01 01";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client-change-cipher-spec", &session, bin_record, role_client);
    }
    /**
     * C -> S
     * https://tls13.xargs.org/#wrapped-record-5
     * https://tls13.xargs.org/#client-handshake-finished
     */
    {
        const char* record =
            "17 03 03 00 45 9f f9 b0 63 17 51 77 32 2a 46 dd 98 96 f3 c3 bb 82 0a b5 17 43 eb c2 5f da dd 53 45 4b 73 de b5 4c c7 24 8d 41 1a 18 bc cf 65 7a "
            "96 08 24 e9 a1 93 64 83 7c 35 0a 69 a8 8d 4b f6 35 c8 5e b8 74 ae bc 9d fd e8";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-5 (finished)", &session, bin_record, role_client);  // 1 for C -> S
    }
    /**
     * C -> S
     * https://tls13.xargs.org/#wrapped-record-6/
     * https://tls13.xargs.org/#client-application-data
     */
    {
        const char* record = "17 03 03 00 15 82 81 39 cb 7b 73 aa ab f5 b8 2f bf 9a 29 61 bc de 10 03 8a 32";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-6 (ping)", &session, bin_record, role_client);  // 1 for C -> S
    }
    /**
     * C <- S
     * https://tls13.xargs.org/#wrapped-record-7
     * https://tls13.xargs.org/#server-new-session-ticket-1
     */
    {
        const char* record =
            "17 03 03 00 ea 38 2d 8c 19 a4 7f 4e 8d 9b 0c 51 0b c3 48 db 2c c9 9b 24 1c d0 d1 8b 31 d0 ca 1a c1 2d c1 e3 03 c5 8d 0c 7e 9e 27 29 4c 6b 0e 31 "
            "98 f7 d3 19 eb 14 62 2e c4 8b 6a c8 f8 66 d7 49 4f a7 75 c8 80 ff 43 ad 4b 1a f5 3a 03 ca 19 77 95 77 8f ff 2f fe 1d 3b 99 b3 4d e7 82 a7 6a bf "
            "a8 40 e6 36 6c d7 34 9d 9b cf f6 41 f5 e0 df f9 5e 40 d7 2e 09 ef fe 18 ee 64 67 2c b9 60 05 40 44 88 ad 18 96 c4 4a 5f d1 74 99 8e 9b 00 94 d8 "
            "e6 d8 4d 29 29 b7 88 3d c9 a3 c3 c7 31 3a 87 29 3f 31 b6 1d 24 d9 90 97 c8 85 3b fb eb 95 d1 d0 1f 99 ca 05 b0 50 18 59 cf 63 40 e8 37 70 75 97 "
            "01 52 fa 94 f5 f5 be 29 06 e7 2a 15 e4 08 36 a4 1f 4c d3 db e7 d5 13 c1 6e 88 61 1d 3e ae 93 38 d9 db 1f 91 ca 3d 58 42 60 2a 61 0b 43 a4 63";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-7 (new_session_ticket)", &session, bin_record, role_server);
    }
    /**
     * C <- S
     * https://tls13.xargs.org/#wrapped-record-8
     * https://tls13.xargs.org/#server-new-session-ticket-2
     */
    {
        const char* record =
            "17 03 03 00 ea 38 ad fb 1d 01 fd 95 a6 03 85 e8 bb f1 fd 8d cb 46 70 98 97 e7 d6 74 c2 f7 37 0e c1 1d 8e 33 eb 4f 4f e7 f5 4b f4 dc 0b 92 fa e7 "
            "42 1c 33 c6 45 3c eb c0 73 15 96 10 a0 97 40 ab 2d 05 6f 8d 51 cf a2 62 00 7d 40 12 36 da fc 2f 72 92 ff 0c c8 86 a4 ef 38 9f 2c ed 12 26 c6 b4 "
            "dc f6 9d 99 4f f9 14 8e f9 69 bc 77 d9 43 3a b1 d3 a9 32 54 21 82 82 9f 88 9a d9 5f 04 c7 52 f9 4a ce 57 14 6a 5d 84 b0 42 bf b3 48 5a 64 e7 e9 "
            "57 b0 89 80 cd 08 ba f9 69 8b 89 29 98 6d 11 74 d4 aa 6d d7 a7 e8 c0 86 05 2c 3c 76 d8 19 34 bd f5 9b 96 6e 39 20 31 f3 47 1a de bd dd db e8 4f "
            "cf 1f f4 08 84 6a e9 b2 8c a4 a9 e7 28 84 4a 49 3d 80 45 5d 6e af f2 05 b4 0a 1e f1 85 74 ef c0 b9 6a d3 83 af bd 8d fc 86 f8 08 7c 1f 7d c8";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-8 (new_session_ticket)", &session, bin_record, role_server);
    }
    /**
     * C <- S
     * https://tls13.xargs.org/#wrapped-record-9
     * https://tls13.xargs.org/#server-application-data
     */
    {
        const char* record = "17 03 03 00 15 0c da 85 f1 44 7a e2 3f a6 6d 56 f4 c5 40 84 82 b1 b1 d4 c9 98";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-9 (pong)", &session, bin_record, role_server);
    }
}
