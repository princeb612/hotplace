/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 *            QUIC integrates the TLS handshake [TLS13], although using a customized framing for protecting packets.
 *
 *          RFC 2246 The TLS Protocol Version 1.0
 *           7.4. Handshake protocol
 *           7.4.1. Hello messages
 *           7.4.1.1. Hello request
 *           7.4.1.2. Client hello
 *
 *          RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
 *           7.4. Handshake Protocol
 *           7.4.1. Hello Messages
 *           7.4.1.2. Client Hello
 *
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *           7.4.  Handshake Protocol
 *           7.4.1.  Hello Messages
 *           7.4.1.2.  Client Hello
 *
 *           4.1.2.  Client Hello
 *             Structure of this message:
 *
 *                uint16 ProtocolVersion;
 *                opaque Random[32];
 *
 *                uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 *                struct {
 *                    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *                    Random random;
 *                    opaque legacy_session_id<0..32>;
 *                    CipherSuite cipher_suites<2..2^16-2>;
 *                    opaque legacy_compression_methods<1..2^8-1>;
 *                    Extension extensions<8..2^16-1>;
 *                } ClientHello;
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

tls_session server_session;

void test_quic_xargs_org() {
    _test_case.begin("https://quic.xargs.org/");

    tls_protection& protection = server_session.get_tls_protection();
    crypto_keychain keychain;
    openssl_digest dgst;
    openssl_kdf kdf;

    /**
     * https://quic.xargs.org/#client-key-exchange-generation
     */
    {
        // Client Key Exchange Generation
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        crypto_key key;
        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc("client key"));
        basic_stream bs;
        dump_key(key.find("client key"), &bs);
        _logger->writeln(bs);
    }
    /**
     * https://quic.xargs.org/#client-initial-keys-calc
     * https://quic.xargs.org/#server-initial-keys-calc
     */
    {
        const char* dcid = "00 01 02 03 04 05 06 07";
        binary_t bin_dcid = base16_decode_rfc(dcid);
        quic_protection quicpp(bin_dcid);

        _test_case.assert(quicpp.get_item(quic_client_key) == base16_decode_rfc("b14b918124fda5c8d79847602fa3520b"), __FUNCTION__, "server initial key");
        _test_case.assert(quicpp.get_item(quic_client_iv) == base16_decode_rfc("ddbc15dea80925a55686a7df"), __FUNCTION__, "server initial iv");
        _test_case.assert(quicpp.get_item(quic_client_hp) == base16_decode_rfc("6df4e9d737cdf714711d7c617ee82981"), __FUNCTION__, "server initial hp");
        _test_case.assert(quicpp.get_item(quic_server_key) == base16_decode_rfc("d77fc4056fcfa32bd1302469ee6ebf90"), __FUNCTION__, "server initial key");
        _test_case.assert(quicpp.get_item(quic_server_iv) == base16_decode_rfc("fcb748e37ff79860faa07477"), __FUNCTION__, "server initial iv");
        _test_case.assert(quicpp.get_item(quic_server_hp) == base16_decode_rfc("440b2725e91dc79b370711ef792faa3d"), __FUNCTION__, "server initial hp");
    }
    /**
     * UDP Datagram 1 - Client hello
     * https://quic.xargs.org/#client-initial-packet
     */
    {
        testvector_initial_packet test;
        memset(&test, 0, sizeof(test));
        test.text = "#client-initial-packet";
        test.func = __FUNCTION__;
        test.odcid = "00 01 02 03 04 05 06 07";
        test.dcid = "00 01 02 03 04 05 06 07";
        test.scid = "63 5f 63 69 64";
        test.expect_unprotected_header = "c00000000108000102030405060705635f63696400410300";
        test.expect_protected_header = "cd0000000108000102030405060705635f63696400410398";
        // CRYPTO frame, TLS: ClientHello
        test.frame =
            "06 00 40 EE 01 00 00 EA 03 03 00 01 02 03 04 05"
            "06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15"
            "16 17 18 19 1A 1B 1C 1D 1E 1F 00 00 06 13 01 13"
            "02 13 03 01 00 00 BB 00 00 00 18 00 16 00 00 13"
            "65 78 61 6D 70 6C 65 2E 75 6C 66 68 65 69 6D 2E"
            "6E 65 74 00 0A 00 08 00 06 00 1D 00 17 00 18 00"
            "10 00 0B 00 09 08 70 69 6E 67 2F 31 2E 30 00 0D"
            "00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01"
            "08 06 06 01 02 01 00 33 00 26 00 24 00 1D 00 20"
            "35 80 72 D6 36 58 80 D1 AE EA 32 9A DF 91 21 38"
            "38 51 ED 21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54"
            "00 2D 00 02 01 01 00 2B 00 03 02 03 04 00 39 00"
            "31 03 04 80 00 FF F7 04 04 80 A0 00 00 05 04 80"
            "10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08"
            "01 0A 09 01 0A 0A 01 03 0B 01 19 0F 05 63 5F 63"
            "69 64 -- -- -- -- -- -- -- -- -- -- -- -- -- --";
        test.expect_result =
            "CD 00 00 00 01 08 00 01 02 03 04 05 06 07 05 63"
            "5F 63 69 64 00 41 03 98 1C 36 A7 ED 78 71 6B E9"
            "71 1B A4 98 B7 ED 86 84 43 BB 2E 0C 51 4D 4D 84"
            "8E AD CC 7A 00 D2 5C E9 F9 AF A4 83 97 80 88 DE"
            "83 6B E6 8C 0B 32 A2 45 95 D7 81 3E A5 41 4A 91"
            "99 32 9A 6D 9F 7F 76 0D D8 BB 24 9B F3 F5 3D 9A"
            "77 FB B7 B3 95 B8 D6 6D 78 79 A5 1F E5 9E F9 60"
            "1F 79 99 8E B3 56 8E 1F DC 78 9F 64 0A CA B3 85"
            "8A 82 EF 29 30 FA 5C E1 4B 5B 9E A0 BD B2 9F 45"
            "72 DA 85 AA 3D EF 39 B7 EF AF FF A0 74 B9 26 70"
            "70 D5 0B 5D 07 84 2E 49 BB A3 BC 78 7F F2 95 D6"
            "AE 3B 51 43 05 F1 02 AF E5 A0 47 B3 FB 4C 99 EB"
            "92 A2 74 D2 44 D6 04 92 C0 E2 E6 E2 12 CE F0 F9"
            "E3 F6 2E FD 09 55 E7 1C 76 8A A6 BB 3C D8 0B BB"
            "37 55 C8 B7 EB EE 32 71 2F 40 F2 24 51 19 48 70"
            "21 B4 B8 4E 15 65 E3 CA 31 96 7A C8 60 4D 40 32"
            "17 0D EC 28 0A EE FA 09 5D 08 B3 B7 24 1E F6 64"
            "6A 6C 86 E5 C6 2C E0 8B E0 99 -- -- -- -- -- --";
        test.mode = tls_mode_client;
        test.pad = false;
        test.pn = 0;
        test.pn_length = 1;
        test.length = 259;

        test_rfc_9001_initial(&test, &server_session);
    }

    /**
     * Server Handshake Keys Calc
     * https://quic.xargs.org/#server-handshake-keys-calc
     */
    {
        /**
         * # openssl pkey -in server-ephemeral-private.key -text
         * -----BEGIN PRIVATE KEY-----
         * MC4CAQAwBQYDK2VuBCIEIJCRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6v
         * -----END PRIVATE KEY-----
         * X25519 Private-Key:
         * priv:
         *     90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:
         *     9f:a0:a1:a2:a3:a4:a5:a6:a7:a8:a9:aa:ab:ac:ad:
         *     ae:af
         * pub:
         *     9f:d7:ad:6d:cf:f4:29:8d:d3:f9:6d:5b:1b:2a:f9:
         *     10:a0:53:5b:14:88:d7:f8:fa:bb:34:9a:98:28:80:
         *     b6:15
         *
         * # openssl pkey -pubin -in client-ephemeral-public.key -text
         * -----BEGIN PUBLIC KEY-----
         * MCowBQYDK2VuAyEANYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ=
         * -----END PUBLIC KEY-----
         * X25519 Public-Key:
         * pub:
         *     35:80:72:d6:36:58:80:d1:ae:ea:32:9a:df:91:21:
         *     38:38:51:ed:21:a2:8e:3b:75:e9:65:d0:d2:cd:16:
         *     62:54
         */

        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

        crypto_key& server_keys = protection.get_key();
        crypto_key& key = protection.get_key();

        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc("server key"));

        basic_stream bs;
        dump_key(key.find("server key"), &bs);
        _logger->writeln(bs);
    }

    /**
     * UDP Datagram 2 - Server hello and handshake
     * https://quic.xargs.org/#server-initial-packet
     */
    {
        testvector_initial_packet test;
        memset(&test, 0, sizeof(test));
        test.text = "#server-initial-packet";
        test.func = __FUNCTION__;
        test.odcid = "00 01 02 03 04 05 06 07";
        test.dcid = "63 5f 63 69 64";  // c_cid
        test.scid = "73 5f 63 69 64";  // s_cid
        test.expect_unprotected_header = "c0 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 00 40 75 00";
        test.expect_protected_header = "cd 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 00 40 75 3a";
        // CRYPTO frame, TLS: ServerHello
        test.frame =
            "02 00 42 40 00 00 06 00 40 5A 02 00 00 56 03 03"
            "70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F"
            "80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F"
            "00 13 01 00 00 2E 00 33 00 24 00 1D 00 20 9F D7"
            "AD 6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 A0 53"
            "5B 14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 00 2B"
            "00 02 03 04 -- -- -- -- -- -- -- -- -- -- -- --";
        test.expect_result =
            "CD 00 00 00 01 05 63 5F 63 69 64 05 73 5F 63 69"
            "64 00 40 75 3A 83 68 55 D5 D9 C8 23 D0 7C 61 68"
            "82 CA 77 02 79 24 98 64 B5 56 E5 16 32 25 7E 2D"
            "8A B1 FD 0D C0 4B 18 B9 20 3F B9 19 D8 EF 5A 33"
            "F3 78 A6 27 DB 67 4D 3C 7F CE 6C A5 BB 3E 8C F9"
            "01 09 CB B9 55 66 5F C1 A4 B9 3D 05 F6 EB 83 25"
            "2F 66 31 BC AD C7 40 2C 10 F6 5C 52 ED 15 B4 42"
            "9C 9F 64 D8 4D 64 FA 40 6C F0 B5 17 A9 26 D6 2A"
            "54 A9 29 41 36 B1 43 B0 33 -- -- -- -- -- -- --";
        test.mode = tls_mode_server;
        test.pad = false;
        test.pn = 0;
        test.pn_length = 1;
        test.length = 117;

        test_rfc_9001_initial(&test, &server_session);
    }

    {
        // https://quic.xargs.org/#server-handshake-keys-calc
        //  It then calculates the SHA256 hash of all handshake messages to this point (ClientHello and ServerHello).
        //  The hash does not include the 6-byte CRYPTO frame headers.
        //  This "hello_hash" is ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b:

        auto keysize = 0;
        auto dlen = 0;
        auto hashalg = 0;
        std::string hashname;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(0x1301);
        if (hint_tls_alg) {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            const hint_blockcipher_t* hint_cipher = advisor->hintof_blockcipher(hint_tls_alg->cipher);
            const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
            if (hint_cipher) {
                keysize = hint_cipher->keysize;
            }
            if (hint_mac) {
                dlen = hint_mac->digest_size;
                hashalg = hint_mac->algorithm;
                hashname = hint_mac->fetchname;
            }
        }
        _logger->writeln("keysize : %i", keysize);
        _logger->writeln("hash : %s", hashname.c_str());
        _logger->writeln("dlen : %i", dlen);
        _test_case.assert(keysize == 16, __FUNCTION__, "TLS_AES_128_GCM_SHA256 keysize %i", keysize);
        _test_case.assert(dlen == 32, __FUNCTION__, "TLS_AES_128_GCM_SHA256 dlen %i", dlen);

        auto lambda_test = [&](tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) -> void {
            protection.get_item(tls_secret, secret);
            _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
            _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
        };

        binary_t shared_secret;
        lambda_test(tls_secret_shared_secret, shared_secret, "shared_secret", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");
        binary_t hello_hash;
        lambda_test(tls_secret_hello_hash, hello_hash, "hello_hash", "ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b");
        binary_t early_secret;
        lambda_test(tls_secret_early_secret, early_secret, "early_secret", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        binary_t empty_hash;
        lambda_test(tls_secret_empty_hash, empty_hash, "empty_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        binary_t derived_secret;
        lambda_test(tls_secret_handshake_derived, derived_secret, "derived_secret", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        binary_t handshake_secret;
        lambda_test(tls_secret_handshake, handshake_secret, "handshake_secret", "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a");
        binary_t client_secret;
        lambda_test(tls_secret_handshake_client, client_secret, "client_secret", "b8902ab5f9fe52fdec3aea54e9293e4b8eabf955fcd88536bf44b8b584f14982");
        binary_t server_secret;
        lambda_test(tls_secret_handshake_server, server_secret, "server_secret", "88ad8d3b0986a71965a28d108b0f40ffffe629284a6028c80ddc5dc083b3f5d1");
        binary_t client_handshake_key;
        lambda_test(tls_secret_handshake_quic_client_key, client_handshake_key, "client_handshake_key", "30a7e816f6a1e1b3434cf39cf4b415e7");
        binary_t client_handshake_iv;
        lambda_test(tls_secret_handshake_quic_client_iv, client_handshake_iv, "client_handshake_iv", "11e70a5d1361795d2bb04465");
        binary_t client_handshake_hp;
        lambda_test(tls_secret_handshake_quic_client_hp, client_handshake_hp, "client_handshake_hp", "84b3c21cacaf9f54c885e9a506459079");
        binary_t protection;
        lambda_test(tls_secret_handshake_quic_server_key, protection, "protection", "17abbf0a788f96c6986964660414e7ec");
        binary_t server_handshake_iv;
        lambda_test(tls_secret_handshake_quic_server_iv, server_handshake_iv, "server_handshake_iv", "09597a2ea3b04c00487e71f3");
        binary_t server_handshake_hp;
        lambda_test(tls_secret_handshake_quic_server_hp, server_handshake_hp, "server_handshake_hp", "2a18061c396c2828582b41b0910ed536");
    }
    /*
     * UDP Datagram 3 - Server handshake finished
     * https://quic.xargs.org/#server-handshake-packet-2
     */
    {
        // study
    }  // UDP Datagram 4 - Acks
    /**
     * https://quic.xargs.org/#client-initial-packet-2
     */
    {
        // study
    }  // UDP Datagram 5 - Client handshake finished, "ping"
    /**
     * https://quic.xargs.org/#client-handshake-packet-2
     */
    {
        // study
    }  // UDP Datagram 6 - "pong"
    /**
     * https://quic.xargs.org/#server-handshake-packet-3
     */
    {
        // study
    }  // UDP Datagram 7 - Acks
    /**
     * https://quic.xargs.org/#client-application-packet-2
     */
    {
        // study
    }  // UDP Datagram 8 - Close connection
    /**
     * https://quic.xargs.org/#server-application-packet-2
     */
    {
        // study
    }
}
