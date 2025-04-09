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

static tls_session server_session(session_quic);
static tls_session client_session(session_quic);

void test_rfc_9001_section4() {
    _test_case.begin("RFC 9001 4.  Carrying TLS Messages");
    // studying ...
}

void test_rfc_9001_prepare_a1() {
    // Destination Connection ID of 0x8394c8f03e515708
    const char* dcid = "0x8394c8f03e515708";
    binary_t bin_dcid = std::move(base16_decode_rfc(dcid));

    {
        auto& protection = server_session.get_tls_protection();
        protection.set_cipher_suite(0x1301);
        protection.set_item(tls_context_quic_dcid, bin_dcid);
        protection.calc(&server_session, tls_hs_client_hello, from_client);
    }

    {
        auto& protection = client_session.get_tls_protection();
        protection.set_cipher_suite(0x1301);
        protection.set_item(tls_context_quic_dcid, bin_dcid);
        protection.calc(&server_session, tls_hs_client_hello, from_client);
    }

    _logger->hdump("> DCID", bin_dcid, 16, 3);
}

void test_rfc_9001_a1() {
    _test_case.begin("RFC 9001 A.1.  Keys");

    test_rfc_9001_prepare_a1();

    {
        auto& protection = server_session.get_tls_protection();

        auto lambda_test = [&](const char* func, const char* text, const binary_t& bin_expect_result, const binary_t& bin_expect) -> void {
            // _logger->hdump(format("> %s", text), bin_expect_result, 16, 3);
            _logger->writeln("> %s : %s", text, base16_encode(bin_expect_result).c_str());
            _test_case.assert(bin_expect == bin_expect_result, func, text);
        };

        binary_t bin_expect;

        bin_expect = std::move(base16_decode("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"));
        lambda_test(__FUNCTION__, "tls_secret_initial_quic", protection.get_item(tls_secret_initial_quic), bin_expect);

        bin_expect = std::move(base16_decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
        lambda_test(__FUNCTION__, "client_initial_secret", protection.get_item(tls_secret_initial_quic_client), bin_expect);

        bin_expect = std::move(base16_decode("1f369613dd76d5467730efcbe3b1a22d"));
        lambda_test(__FUNCTION__, "client key", protection.get_item(tls_secret_initial_quic_client_key), bin_expect);

        bin_expect = std::move(base16_decode("fa044b2f42a3fd3b46fb255c"));
        lambda_test(__FUNCTION__, "client iv", protection.get_item(tls_secret_initial_quic_client_iv), bin_expect);

        bin_expect = std::move(base16_decode("9f50449e04a0e810283a1e9933adedd2"));
        lambda_test(__FUNCTION__, "client hp", protection.get_item(tls_secret_initial_quic_client_hp), bin_expect);

        bin_expect = std::move(base16_decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"));
        lambda_test(__FUNCTION__, "server_initial_secret", protection.get_item(tls_secret_initial_quic_server), bin_expect);

        bin_expect = std::move(base16_decode("cf3a5331653c364c88f0f379b6067e37"));
        lambda_test(__FUNCTION__, "server key", protection.get_item(tls_secret_initial_quic_server_key), bin_expect);

        bin_expect = std::move(base16_decode("0ac1493ca1905853b0bba03e"));
        lambda_test(__FUNCTION__, "server iv", protection.get_item(tls_secret_initial_quic_server_iv), bin_expect);

        bin_expect = std::move(base16_decode("c206b8d9b9f0f37644430b490eeaa314"));
        lambda_test(__FUNCTION__, "server hp", protection.get_item(tls_secret_initial_quic_server_hp), bin_expect);
    }
}

void test_rfc_9001_a2() {
    _test_case.begin("RFC 9001 A.2.  Client Initial");

    testvector_initial_packet test;
    memset(&test, 0, sizeof(test));
    test.text = "RFC 9001 A.2.  Client Initial";
    test.func = __FUNCTION__;
    test.odcid = "0x8394c8f03e515708";
    test.dcid = "0x8394c8f03e515708";
    test.scid = nullptr;
    //            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    // 00000000 : C3 00 00 00 01 08 83 94 C8 F0 3E 51 57 08 00 00 | ..........>QW...
    // 00000010 : 44 9E 00 00 00 02 -- -- -- -- -- -- -- -- -- -- | D.....
    // 22 bytes long
    // [0x00] header        : c3
    // [0x01] version       : 00000001
    // [0x05] DCID Length   : 08
    // [0x06] DCID          : 8394c8f03e515708
    // [0x0e] SCID Length   : 00
    // [0x0f] SCID
    // [0x0f] Token Length  : 00
    // [0x0f] Token
    // [0x10] Length        : 449e     ; 0x449e -> 1182 = pn_length(4) + payload(1162) + tag(16)
    // [0x12] Packet Number : 00000002 ; pnl 0x03 -> 4 bytes
    test.expect_unprotected_header = "c300000001088394c8f03e5157080000 449e00000002";
    test.expect_protected_header = "c000000001088394c8f03e5157080000 449e7b9aec34";
    // CRYPTO frame, plus enough PADDING frames
    // > frame CRYPTO @0
    //  > offset 0
    //  > length 241
    //  > crypto data (241)
    //    00000000 : 01 00 00 ED 03 03 EB F8 FA 56 F1 29 39 B9 58 4A | .........V.)9.XJ
    //    00000010 : 38 96 47 2E C4 0B B8 63 CF D3 E8 68 04 FE 3A 47 | 8.G....c...h..:G
    //    00000020 : F0 6A 2B 69 48 4C 00 00 04 13 01 13 02 01 00 00 | .j+iHL..........
    //    00000030 : C0 00 00 00 10 00 0E 00 00 0B 65 78 61 6D 70 6C | ..........exampl
    //    00000040 : 65 2E 63 6F 6D FF 01 00 01 00 00 0A 00 08 00 06 | e.com...........
    //    00000050 : 00 1D 00 17 00 18 00 10 00 07 00 05 04 61 6C 70 | .............alp
    //    00000060 : 6E 00 05 00 05 01 00 00 00 00 00 33 00 26 00 24 | n..........3.&.$
    //    00000070 : 00 1D 00 20 93 70 B2 C9 CA A4 7F BA BA F4 55 9F | ... .p........U.
    //    00000080 : ED BA 75 3D E1 71 FA 71 F5 0F 1C E1 5D 43 E9 94 | ..u=.q.q....]C..
    //    00000090 : EC 74 D7 48 00 2B 00 03 02 03 04 00 0D 00 10 00 | .t.H.+..........
    //    000000A0 : 0E 04 03 05 03 06 03 02 03 08 04 08 05 08 06 00 | ................
    //    000000B0 : 2D 00 02 01 01 00 1C 00 02 40 01 00 39 00 32 04 | -........@..9.2.
    //    000000C0 : 08 FF FF FF FF FF FF FF FF 05 04 80 00 FF FF 07 | ................
    //    000000D0 : 04 80 00 FF FF 08 01 10 01 04 80 00 75 30 09 01 | ............u0..
    //    000000E0 : 10 0F 08 83 94 C8 F0 3E 51 57 08 06 04 80 00 FF | .......>QW......
    //    000000F0 : FF -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
    // > frame PADDING @245
    //   ...
    // > frame PADDING @1161
    test.frame =
        "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a 00080006001d00170018001000070005"
        "04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408 050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000"
        "75300901100f088394c8f03e51570806 048000ffff";
    test.expect_result =
        "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11"
        "d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399"
        "1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c"
        "8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212"
        "30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5"
        "457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208"
        "4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec"
        "4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3"
        "485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db"
        "059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c"
        "7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8"
        "9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556"
        "be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74"
        "68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a"
        "c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00"
        "f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632"
        "291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964"
        "25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd"
        "14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff"
        "ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198"
        "e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd"
        "c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73"
        "203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f"
        "cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e"
        "fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade"
        "a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047"
        "90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2"
        "162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4"
        "40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0"
        "6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e"
        "8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0"
        "be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400"
        "54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab"
        "760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9"
        "f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4"
        "056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064"
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241"
        "e221af44860018ab0856972e194cd934";
    test.dir = from_client;
    test.pad = true;
    test.resize = 1162;
    test.pn = 2;
    test.pn_length = 4;  // 00000002
    test.length = 1182;  // pnl 4 + frame 1162 + tag 16 -> length 1182

    {
        // to avoid internal error related to key calcurations
        crypto_keychain keychain;
        auto& keyexchange = client_session.get_tls_protection().get_keyexchange();
        keychain.add_ec(&keyexchange, NID_X25519, keydesc(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE));
    }

    test_rfc_9001_construct_initial(&test, &client_session);
    test_rfc_9001_send_initial(&test, &server_session);
}

void test_rfc_9001_a3() {
    _test_case.begin("RFC 9001 A.3.  Server Initial");

    testvector_initial_packet test;
    memset(&test, 0, sizeof(test));
    test.text = "RFC 9001 A.3.  Server Initial";
    test.func = __FUNCTION__;
    test.odcid = "0x8394c8f03e515708";
    test.dcid = nullptr;
    test.scid = "0xf067a5502a4262b5";
    // 20 bytes long
    // [0x00] header        : c1
    // [0x01] version       : 00000001
    // [0x05] DCID Length   : 00
    // [0x05] DCID          :
    // [0x06] SCID Length   : 08
    // [0x07] SCID          : f067a5502a4262b5
    // [0x0f] Token Length  : 00
    // [0x0f] Token
    // [0x10] Length        : 4075 ; 0x4075 -> 117 = pn_length(2) + payload(99) + tag(16)
    // [0x12] Packet Number : 0001 ; pnl 0x01 -> 2 bytes
    test.expect_unprotected_header = "c1000000010008f067a5502a4262b500 40750001";
    test.expect_protected_header = "cf000000010008f067a5502a4262b500 4075c0d9";
    // including an ACK frame, a CRYPTO frame, and no PADDING frames
    // > frame ACK @0
    //  > largest ack 0
    //  > ack delay 0
    //  > ack range count 0
    //  > first ack range 0
    // > frame CRYPTO @5
    //  > offset 0
    //  > length 90
    //  > crypto data (90)
    //    00000000 : 02 00 00 56 03 03 EE FC E7 F7 B3 7B A1 D1 63 2E | ...V.......{..c.
    //    00000010 : 96 67 78 25 DD F7 39 88 CF C7 98 25 DF 56 6D C5 | .gx%..9....%.Vm.
    //    00000020 : 43 0B 9A 04 5A 12 00 13 01 00 00 2E 00 33 00 24 | C...Z........3.$
    //    00000030 : 00 1D 00 20 9D 3C 94 0D 89 69 0B 84 D0 8A 60 99 | ... .<...i....`.
    //    00000040 : 3C 14 4E CA 68 4D 10 81 28 7C 83 4D 53 11 BC F3 | <.N.hM..(|.MS...
    //    00000050 : 2B B9 DA 1A 00 2B 00 02 03 04 -- -- -- -- -- -- | +....+....
    test.frame =
        "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739"
        "88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94"
        "0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00"
        "020304";
    test.expect_result =
        "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a"
        "5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3"
        "dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84"
        "022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4"
        "2158407dd074ee";
    test.dir = from_server;
    test.pad = false;
    test.resize = 0;
    test.pn = 1;
    test.pn_length = 2;  // 0001
    test.length = 117;

    {
        // to avoid internal error related to key calcurations
        crypto_keychain keychain;
        auto& keyexchange = server_session.get_tls_protection().get_keyexchange();
        keychain.add_ec(&keyexchange, NID_X25519, keydesc(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE));
    }

    test_rfc_9001_construct_initial(&test, &server_session);
    test_rfc_9001_send_initial(&test, &client_session);
}

void test_rfc_9001_a4() {
    _test_case.begin("RFC 9001 A.4.  Retry");

    testvector_retry_packet test;
    test.text = "RFC 9001 A.4.  Retry";
    test.func = __FUNCTION__;
    test.odcid = "0x8394c8f03e515708";
    test.dcid = nullptr;
    test.scid = "0xf067a5502a4262b5";
    test.token = "0x746f6b656e";  // "token"
    test.expect_result =
        "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f"
        "0f2496ba";
    test.expect_tag = "04a265ba2eff4d829058fb3f0f2496ba";
    test.dir = from_server;

    test_rfc_9001_retry(&test, &server_session);
}

void test_rfc_9001_a5() {
    _test_case.begin("RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet");

    openssl_kdf kdf;
    const char* secret = "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b";
    binary_t bin_secret = std::move(base16_decode_rfc(secret));
    binary_t context;
    binary_t bin_key;
    binary_t bin_iv;
    binary_t bin_hp;
    binary_t bin_ku;
    const char* alg = "sha256";
    kdf.hkdf_expand_tls13_label(bin_key, alg, 32, bin_secret, str2bin("quic key"), context);
    kdf.hkdf_expand_tls13_label(bin_iv, alg, 12, bin_secret, str2bin("quic iv"), context);
    kdf.hkdf_expand_tls13_label(bin_hp, alg, 32, bin_secret, str2bin("quic hp"), context);
    kdf.hkdf_expand_tls13_label(bin_ku, alg, 32, bin_secret, str2bin("quic ku"), context);
    _logger->hdump("> key", bin_key, 16, 3);
    _test_case.assert(bin_key == base16_decode("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), __FUNCTION__, "key");
    _logger->hdump("> iv", bin_iv, 16, 3);
    _test_case.assert(bin_iv == base16_decode("e0459b3474bdd0e44a41c144"), __FUNCTION__, "iv");
    _logger->hdump("> hp", bin_hp, 16, 3);
    _test_case.assert(bin_hp == base16_decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), __FUNCTION__, "hp");
    _logger->hdump("> ku", bin_ku, 16, 3);
    _test_case.assert(bin_ku == base16_decode("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"), __FUNCTION__, "ku");
}
