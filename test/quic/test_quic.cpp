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

static tls_session server_session(session_quic);

void test_quic_xargs_org() {
    _test_case.begin("https://quic.xargs.org/");

    return_t ret = errorcode_t::success;
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
        crypto_key& key = protection.get_keyexchange();
        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE));
        basic_stream bs;
        dump_key(key.find("client key"), &bs);
        _logger->writeln(bs);
    }
    /**
     * https://quic.xargs.org/#client-initial-keys-calc
     * https://quic.xargs.org/#server-initial-keys-calc
     */
    const char* dcid = "00 01 02 03 04 05 06 07";
    const char* scid = "63 5f 63 69 64";
    binary_t bin_dcid = base16_decode_rfc(dcid);
    binary_t bin_scid = base16_decode_rfc(scid);

    protection.set_item(tls_context_quic_dcid, bin_dcid);
    protection.calc(&server_session, tls_hs_client_hello, from_client);

    {
        _test_case.assert(protection.get_item(tls_context_quic_initial_client_key) == base16_decode_rfc("b14b918124fda5c8d79847602fa3520b"), __FUNCTION__,
                          "server initial key");
        _test_case.assert(protection.get_item(tls_context_quic_initial_client_iv) == base16_decode_rfc("ddbc15dea80925a55686a7df"), __FUNCTION__,
                          "server initial iv");
        _test_case.assert(protection.get_item(tls_context_quic_initial_client_hp) == base16_decode_rfc("6df4e9d737cdf714711d7c617ee82981"), __FUNCTION__,
                          "server initial hp");
        _test_case.assert(protection.get_item(tls_context_quic_initial_server_key) == base16_decode_rfc("d77fc4056fcfa32bd1302469ee6ebf90"), __FUNCTION__,
                          "server initial key");
        _test_case.assert(protection.get_item(tls_context_quic_initial_server_iv) == base16_decode_rfc("fcb748e37ff79860faa07477"), __FUNCTION__,
                          "server initial iv");
        _test_case.assert(protection.get_item(tls_context_quic_initial_server_hp) == base16_decode_rfc("440b2725e91dc79b370711ef792faa3d"), __FUNCTION__,
                          "server initial hp");
    } /**
       * UDP Datagram 1 - Client hello
       * https://quic.xargs.org/#client-initial-packet
       */
    {
        const char* packet =
            "cd 00 00 00 01 08 00 01 02 03 04 05 06 07 05 63 5f 63 69 64 00 41 03 98 1c 36 a7 ed 78 71 6b e9 71 1b a4 98 b7 ed 86 84 43 bb 2e 0c 51 4d 4d 84 "
            "8e ad cc 7a 00 d2 5c e9 f9 af a4 83 97 80 88 de 83 6b e6 8c 0b 32 a2 45 95 d7 81 3e a5 41 4a 91 99 32 9a 6d 9f 7f 76 0d d8 bb 24 9b f3 f5 3d 9a "
            "77 fb b7 b3 95 b8 d6 6d 78 79 a5 1f e5 9e f9 60 1f 79 99 8e b3 56 8e 1f dc 78 9f 64 0a ca b3 85 8a 82 ef 29 30 fa 5c e1 4b 5b 9e a0 bd b2 9f 45 "
            "72 da 85 aa 3d ef 39 b7 ef af ff a0 74 b9 26 70 70 d5 0b 5d 07 84 2e 49 bb a3 bc 78 7f f2 95 d6 ae 3b 51 43 05 f1 02 af e5 a0 47 b3 fb 4c 99 eb "
            "92 a2 74 d2 44 d6 04 92 c0 e2 e6 e2 12 ce f0 f9 e3 f6 2e fd 09 55 e7 1c 76 8a a6 bb 3c d8 0b bb 37 55 c8 b7 eb ee 32 71 2f 40 f2 24 51 19 48 70 "
            "21 b4 b8 4e 15 65 e3 ca 31 96 7a c8 60 4d 40 32 17 0d ec 28 0a ee fa 09 5d 08 b3 b7 24 1e f6 64 6a 6c 86 e5 c6 2c e0 8b e0 99";
        binary_t bin_packet = base16_decode_rfc(packet);
        quic_packet_initial initial(&server_session);
        size_t pos = 0;
        ret = initial.read(from_client, &bin_packet[0], bin_packet.size(), pos);
        _test_case.test(ret, __FUNCTION__, "client_hello");
    }
    /**
     * https://quic.xargs.org/#server-key-exchange-generation
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

        crypto_key& key = protection.get_keyexchange();

        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE));

        basic_stream bs;
        dump_key(key.find("server key"), &bs);
        _logger->writeln(bs);
    }
    /**
     * Server Handshake Keys Calc
     * https://quic.xargs.org/#server-handshake-keys-calc
     */
    {
        //
    } /**
       * UDP Datagram 2 - Server hello and handshake
       * https://quic.xargs.org/#server-initial-packet
       */
    {
        const char* packet =
            "cd 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 00 40 75 3a 83 68 55 d5 d9 c8 23 d0 7c 61 68 82 ca 77 02 79 24 98 64 b5 56 e5 16 32 25 7e 2d "
            "8a b1 fd 0d c0 4b 18 b9 20 3f b9 19 d8 ef 5a 33 f3 78 a6 27 db 67 4d 3c 7f ce 6c a5 bb 3e 8c f9 01 09 cb b9 55 66 5f c1 a4 b9 3d 05 f6 eb 83 25 "
            "2f 66 31 bc ad c7 40 2c 10 f6 5c 52 ed 15 b4 42 9c 9f 64 d8 4d 64 fa 40 6c f0 b5 17 a9 26 d6 2a 54 a9 29 41 36 b1 43 b0 33";
        binary_t bin_packet = base16_decode_rfc(packet);
        quic_packet_initial initial(&server_session);
        size_t pos = 0;
        // initial.attach(&quicpp);
        ret = initial.read(from_server, &bin_packet[0], bin_packet.size(), pos);
        _test_case.test(ret, __FUNCTION__, "server_hello");
    }
    {
        // https://quic.xargs.org/#server-handshake-keys-calc
        //  It then calculates the SHA256 hash of all handshake messages to this point (ClientHello and ServerHello).
        //  The hash does not include the 6-byte CRYPTO frame headers.
        //  This "hello_hash" is ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b:

        //  server_hello
        //  > cipher suite 0x1301 TLS_AES_128_GCM_SHA256
        //  > compression method 0 null
        //  > extension len 0x2e(46)
        //  > extension - 0033 key_share
        //    00000000 : 00 33 00 24 00 1D 00 20 9F D7 AD 6D CF F4 29 8D | .3.$... ...m..).
        //    00000010 : D3 F9 6D 5B 1B 2A F9 10 A0 53 5B 14 88 D7 F8 FA | ..m[.*...S[.....
        //    00000020 : BB 34 9A 98 28 80 B6 15 -- -- -- -- -- -- -- -- | .4..(...
        //   > extension len 0x0024(36)
        //   > group 0x001d (x25519)
        //   > public key len 32
        //     00000000 : 9F D7 AD 6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 | ...m..)...m[.*..
        //     00000010 : A0 53 5B 14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 | .S[......4..(...
        //     9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615
        //  > extension - 002b supported_versions
        //    00000000 : 00 2B 00 02 03 04 -- -- -- -- -- -- -- -- -- -- | .+....
        //   > extension len 0x0002(2)
        //    > 0x0304 TLS v1.3

        auto cs = protection.get_cipher_suite();
        _test_case.assert(0x1301 == cs, __FUNCTION__, "cipher suite 0x%04x", cs);
        auto tlsver = protection.get_tls_version();
        _test_case.assert(tls_13 == tlsver, __FUNCTION__, "TLS version 0x%04x", tlsver);

        auto lambda_test = [&](tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) -> void {
            protection.get_item(tls_secret, secret);
            _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
            _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
        };

        binary_t shared_secret;
        lambda_test(tls_context_shared_secret, shared_secret, "shared_secret", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");
        binary_t hello_hash;
        lambda_test(tls_context_transcript_hash, hello_hash, "hello_hash", "ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b");
        binary_t early_secret;
        lambda_test(tls_secret_early_secret, early_secret, "early_secret", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        binary_t empty_hash;
        lambda_test(tls_context_empty_hash, empty_hash, "empty_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        binary_t derived_secret;
        lambda_test(tls_secret_handshake_derived, derived_secret, "derived_secret", "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        binary_t handshake_secret;
        lambda_test(tls_secret_handshake, handshake_secret, "handshake_secret", "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a");
        binary_t client_secret;
        lambda_test(tls_secret_c_hs_traffic, client_secret, "client_secret", "b8902ab5f9fe52fdec3aea54e9293e4b8eabf955fcd88536bf44b8b584f14982");
        binary_t server_secret;
        lambda_test(tls_secret_s_hs_traffic, server_secret, "server_secret", "88ad8d3b0986a71965a28d108b0f40ffffe629284a6028c80ddc5dc083b3f5d1");
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
    /**
     * https://quic.xargs.org/#server-handshake-packet
     */
    {
        const char* packet =
            "ed 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 44 14 b7 dd 73 ae 29 62 09 df f2 d0 2d 3d 50 af 69 21 76 dd 4d 50 9f e8 cb 1b 46 e4 5b 09 36 "
            "4d 81 5f a7 a5 74 8e 21 80 da d2 b7 b6 68 ca b8 6f bd c2 98 8c 45 cb b8 51 dd cf 16 01 b7 80 d7 48 b9 ee 64 1e bc be 20 12 6e 32 26 7e 66 4d 2f "
            "37 cf 53 b7 53 d1 24 71 7c 2e 13 c4 8a 09 e3 42 8b 11 dc 73 ba eb d4 98 e8 ca f5 be ce fe a7 60 d0 e7 a5 cd b7 6b 52 bc b1 92 29 97 3e 5d 09 aa "
            "05 5e 9c 97 18 dc 58 14 54 77 5c 58 ec dd 5e e7 e7 72 78 f5 60 10 70 40 41 62 a7 9e e8 c5 96 45 d6 ca 24 a2 00 18 6a e9 9c e4 7e ac e1 cf c9 52 "
            "7b 24 ae 8b c6 cc db ac b7 9b 81 c9 1a 26 95 47 07 ba 35 cb a0 ca e9 af f4 18 c6 e0 8d a6 50 61 63 a3 9f 19 b6 76 a6 6a c1 74 e3 29 5f 1a b9 ea "
            "73 83 a9 c2 85 d7 3e 95 75 8d c9 bd 8d a9 07 34 a9 fe df d7 e1 f7 4d 2b 69 c7 0b f7 39 a4 8c 5a 5d 0a fa 0b fa 16 03 47 1b 0c 61 a9 ca de 12 0b "
            "39 86 a6 ce 02 95 be 82 28 c6 92 70 13 b0 6d a5 8d 31 99 62 31 b9 e3 15 0b b5 82 70 96 0e 61 cb c6 69 8a 2f 13 79 a2 25 84 65 da 73 25 b3 49 c6 "
            "cd 55 d1 05 fd 54 85 fd 0a c7 9a 1d f1 db ba 7f 85 b4 9b 72 36 5b fa b9 d5 78 e0 1d cb ff 85 15 a6 32 fd 70 01 38 2e d9 0f 6c dc b1 7d b9 9a 33 "
            "fa 11 81 f6 f6 1a 89 e7 83 cf b0 42 fc 0f 2f 67 cd b6 0e 89 f2 63 88 56 81 ae 64 5a 1c 7a b1 59 0e b2 f8 46 9f 46 0f 04 e0 9f ea 2a 3a 41 1b 49 "
            "86 63 01 0b 3c 38 2a 3f 25 83 7c 2c 70 86 af 5a 9a d2 90 cf 3c cf 1a c6 eb 0f 44 55 35 e8 b0 0a 55 7c 87 a5 3d 93 07 14 62 a0 bc 22 61 4e 5c 3a "
            "e0 84 17 b7 20 a7 36 c1 ad 48 ea 37 75 cd 0f 00 9f 0c 57 50 0e 0b b2 e7 e9 c5 3f 83 69 9a 47 e5 f1 3b b2 07 72 ab 23 50 64 24 b7 6f 6e f9 6a 61 "
            "c9 17 22 6e 6e 04 8d e6 f8 24 26 ca 63 ea bf 3b 59 43 af 0b 5f 0d 12 3d 9a f0 45 bb 35 7c ad bd 10 92 ad 0a 1d 75 51 16 2a 3b 4b 48 6c 27 1e 00 "
            "24 4b 23 d8 ad ec 81 c9 2e 31 23 9c 75 af 41 cb 07 98 08 57 1b 48 ac b5 07 33 3f fb f1 a4 86 d8 05 3e dc c8 62 b6 a9 bf d3 6a 09 cd db a3 29 1b "
            "9b 8b a1 58 49 34 59 80 5c e2 41 da f5 c1 30 85 99 fc 0e 6e 6e a7 10 30 33 b2 94 cc 7a 5f db 2d 46 54 f1 d4 40 78 25 eb c3 75 ab df b2 cc a1 ab "
            "f5 a2 41 34 3d ec 3b 16 5d 32 0a f8 4b c1 fa 21 11 2e fd b9 d4 5c 6c fc 7b 8a 64 42 ff 59 3d 09 21 93 36 fa 07 56 d9 e4 5b ab 4f a6 33 94 a2 a8 "
            "80 3d f4 67 8e 79 21 6f df 13 1f 55 82 2f 9e ad 69 4a b7 5e e2 54 96 e6 b7 8c 3b 09 04 66 58 e2 c4 27 dd c4 53 8a f8 de 2a cb 81 39 8b 74 82 83 "
            "37 f2 69 cb 03 1d 99 7a 5c f6 3e 11 ab 05 0a a8 ae e1 f0 79 62 dd d7 51 5a b6 0e 19 2e 40 3c 30 03 11 e9 e4 b9 b7 0f 16 15 02 9d 07 fe 1c 23 19 "
            "39 02 71 49 f4 fd 29 72 02 3a 55 de 29 35 65 05 fb e7 49 90 8c 62 aa 33 eb 25 9a 39 9b f7 11 b9 2b 61 6c b7 48 de 73 c8 bf ad d5 d4 3e 2d ae 91 "
            "6a 7b a0 db 61 df cd 6f af 95 76 08 26 2b 68 34 e3 31 85 b8 d5 59 8f 87 e6 99 2a ac f5 76 96 ad d5 55 8a 7d 96 94 38 1f 5d 7d 65 9d a2 de 95 1b "
            "60 74 78 f6 1d a2 08 a2 4a 07 ba 8d a0 02 58 fa 7f 2f e1 0d ef 61 83 26 7f 5d 38 e0 4c 94 23 00 b9 c8 74 e8 98 3c 1b e1 4e 16 08 ff dc a6 7d 7e "
            "45 13 cc 0c b9 ca b8 1d 63 19 dd 10 74 b2 17 e5 19 54 65 13 1e 06 dd 0b af ab a8 4e b5 2c 22 a4 a8 c6 12 a4 05 fe 6c 87 42 32 e4 a9 34 61 1b c7 "
            "3c 56 fe 70 b2 cb 7a 59 6c 1f 53 c7 29 b6 64 3c bd 70 d5 30 fe 31 96 06 9f c0 07 8e 89 fb b7 0d c1 b3 8a b4 e1 77 0c 8f fb 53 31 6d 67 3a 32 b8 "
            "92 59 b5 d3 3e 94 ad";
        binary_t bin_packet = base16_decode_rfc(packet);
        // quic_packet_handshake handshake(&server_session);
        // size_t pos = 0;
        // handshake.attach(&quicpp);
        // ret = handshake.read(from_server, &bin_packet[0], bin_packet.size(), pos);
        // _test_case.test(ret, __FUNCTION__, "encrypted_extensions..certificate");
    }
    /*
     * UDP Datagram 3 - Server handshake finished
     * https://quic.xargs.org/#server-handshake-packet-2
     */
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
