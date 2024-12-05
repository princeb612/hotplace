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

void test_rfc_9001_section4() {
    _test_case.begin("RFC 9001 4.  Carrying TLS Messages");
    // studying ...
}

void test_rfc_9001_a1() {
    _test_case.begin("RFC 9001 A.1.  Keys");
    openssl_kdf kdf;

    // RFC 9001 5.2.  Initial Secrets
    const char* initial_salt = "0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

    // Destination Connection ID of 0x8394c8f03e515708
    // quic_initial_secret = HKDF-Extract(initial_salt, cid)
    const char* dcid = "0x8394c8f03e515708";
    const char* quic_initial_secret = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";
    const char* client_initial_secret = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
    const char* server_initial_secret = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";

    binary_t bin_dcid = base16_decode_rfc(dcid);
    binary_t bin_initial_salt = base16_decode_rfc(initial_salt);
    binary_t bin_initial_secret = base16_decode_rfc(quic_initial_secret);
    binary_t bin_client_initial_secret = base16_decode_rfc(client_initial_secret);
    binary_t bin_server_initial_secret = base16_decode_rfc(server_initial_secret);

    _logger->hdump("> DCID", bin_dcid, 16, 3);

    auto lambda_test = [&](const char* func, const char* text, const binary_t& bin_expect_result, const binary_t& bin_expect) -> void {
        _logger->hdump(format("> %s", text), bin_expect_result, 16, 3);
        _logger->writeln(" : %s", base16_encode(bin_expect_result).c_str());
        _test_case.assert(bin_expect == bin_expect_result, func, text);
    };

    binary_t bin_expect_result;
    binary_t bin_expect;
    quic_protection protection(bin_dcid);  // compute all keys

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_initial_secret);
    lambda_test(__FUNCTION__, "quic_initial_secret", bin_expect_result, bin_initial_secret);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_client_secret);
    bin_expect = base16_decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    lambda_test(__FUNCTION__, "client_initial_secret", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_client_key);
    bin_expect = base16_decode("1f369613dd76d5467730efcbe3b1a22d");
    lambda_test(__FUNCTION__, "client key", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_client_iv);
    bin_expect = base16_decode("fa044b2f42a3fd3b46fb255c");
    lambda_test(__FUNCTION__, "client iv", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_client_hp);
    bin_expect = base16_decode("9f50449e04a0e810283a1e9933adedd2");
    lambda_test(__FUNCTION__, "client hp", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_server_secret);
    bin_expect = base16_decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    lambda_test(__FUNCTION__, "server_initial_secret", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_server_key);
    bin_expect = base16_decode("cf3a5331653c364c88f0f379b6067e37");
    lambda_test(__FUNCTION__, "server key", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_server_iv);
    bin_expect = base16_decode("0ac1493ca1905853b0bba03e");
    lambda_test(__FUNCTION__, "server iv", bin_expect_result, bin_expect);

    bin_expect_result = protection.get_item(quic_initial_keys_t::quic_server_hp);
    bin_expect = base16_decode("c206b8d9b9f0f37644430b490eeaa314");
    lambda_test(__FUNCTION__, "server hp", bin_expect_result, bin_expect);
}

tls_session rfc9001_session;

void test_rfc_9001_initial(testvector_initial_packet* item, tls_session* session) {
    binary_t bin_odcid;
    binary_t bin_dcid;
    binary_t bin_scid;
    binary_t bin_token;
    binary_t bin_unprotected_header;
    binary_t bin_protected_header;
    binary_t bin_frame;
    binary_t bin_payload;
    binary_t bin_tag;
    binary_t bin_result;
    binary_t bin_expect_unprotected_header;
    binary_t bin_expect_protected_header;
    binary_t bin_expect_result;

    const char* text = item->text;
    const char* func = item->func;
    tls_mode_t mode = item->mode;
    uint32 pn = item->pn;
    uint8 pn_length = item->pn_length;
    size_t length = item->length;

    size_t pos = 0;
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;

    // DCID, expectation data, result, ...
    {
        bin_odcid = base16_decode_rfc(item->odcid);
        if (item->dcid) {
            bin_dcid = base16_decode_rfc(item->dcid);
        }
        if (item->scid) {
            bin_scid = base16_decode_rfc(item->scid);
        }
        if (item->token) {
            bin_token = base16_decode_rfc(item->token);
        }
        bin_frame = base16_decode_rfc(item->frame);
        if (item->pad) {
            bin_frame.resize(item->resize);
        }

        bin_expect_unprotected_header = base16_decode_rfc(item->expect_unprotected_header);
        bin_expect_protected_header = base16_decode_rfc(item->expect_protected_header);
        bin_expect_result = base16_decode_rfc(item->expect_result);
    }

    quic_protection quicpp(bin_odcid);

    {
        _logger->hdump("> initial secret", quicpp.get_item(quic_initial_secret), 16, 3);
        _logger->hdump("> client initial secret", quicpp.get_item(quic_client_secret), 16, 3);
        _logger->hdump("> client key", quicpp.get_item(quic_client_key), 16, 3);
        _logger->hdump("> client iv", quicpp.get_item(quic_client_iv), 16, 3);
        _logger->hdump("> client hp", quicpp.get_item(quic_client_hp), 16, 3);
        _logger->hdump("> server initial secret", quicpp.get_item(quic_server_secret), 16, 3);
        _logger->hdump("> server key", quicpp.get_item(quic_server_key), 16, 3);
        _logger->hdump("> server iv", quicpp.get_item(quic_server_iv), 16, 3);
        _logger->hdump("> server hp", quicpp.get_item(quic_server_hp), 16, 3);
        // _logger->hdump("> input frame", bin_frame, 16, 3);
        // _logger->hdump("> expect result", bin_expect_result, 16, 3);
    }

    // write
    {
        quic_packet_initial initial;

        initial.attach(&quicpp);
        initial.set_dcid(bin_dcid).set_scid(bin_scid).set_payload(bin_frame);
        initial.set_token(bin_token);
        initial.set_pn(pn, pn_length);

        // unprotected header
        initial.write(bin_unprotected_header);
        // packet protection -> protected header, payload, tag
        initial.write(bin_protected_header, bin_payload, bin_tag, mode);
        // packet
        initial.write(bin_result, mode);

        _logger->hdump("> unprotected header (AAD)", bin_unprotected_header, 16, 3);
        _logger->writeln(" : %s", base16_encode(bin_unprotected_header).c_str());
        _logger->hdump("> expected unprotected header (AAD)", bin_expect_unprotected_header, 16, 3);
        _logger->writeln(" : %s", base16_encode(bin_expect_unprotected_header).c_str());
        _logger->hdump("> protected header", bin_protected_header, 16, 3);
        _logger->writeln(" : %s", base16_encode(bin_protected_header).c_str());
        _logger->hdump("> expected protected header", bin_expect_protected_header, 16, 3);
        _logger->writeln(" : %s", base16_encode(bin_expect_protected_header).c_str());
        // _logger->hdump("> payload (encrypted)", bin_payload, 16, 3);
        // _logger->hdump("> tag", bin_tag, 16, 3);
        // _logger->hdump("> result", bin_result, 16, 3);

        _test_case.assert(quic_packet_type_initial == initial.get_type(), func, "%s #initial packet", text);
        _test_case.assert(bin_dcid == initial.get_dcid(), func, "%s #DCID", text);
        _test_case.assert(bin_scid == initial.get_scid(), func, "%s #SCID", text);
        _test_case.assert(length == initial.get_length(), func, "%s #length", text);
        _test_case.assert(pn == initial.get_pn(), func, "%s #packet number", text);
        _test_case.assert(pn_length == initial.get_pn_length(), func, "%s #packet number length", text);
        _test_case.assert(bin_expect_unprotected_header == bin_unprotected_header, func, "%s #unprotected header", text);
        _test_case.assert(bin_expect_protected_header == bin_protected_header, func, "%s #protected header", text);
        _test_case.assert(bin_expect_result == bin_result, func, "%s #result", text);
    }

    // read
    {
        quic_packet_initial initial;

        initial.attach(&quicpp);
        pos = 0;
        initial.read(&bin_expect_result[0], bin_expect_result.size(), pos, mode);

        basic_stream bs;
        initial.dump(&bs);
        _logger->writeln(bs);
        bs.clear();

        pos = 0;
        while (errorcode_t::success == quic_dump_frame(&bs, session, &bin_frame[0], bin_frame.size(), pos)) {
        };
        _logger->writeln(bs);

        _test_case.assert(quic_packet_type_initial == initial.get_type(), func, "%s #initial packet", text);
        _test_case.assert(bin_dcid == initial.get_dcid(), func, "%s #DCID", text);
        _test_case.assert(bin_scid == initial.get_scid(), func, "%s #SCID", text);
        _test_case.assert(pn == initial.get_pn(), func, "%s #packet number %i", text, initial.get_pn());
        _test_case.assert(pn_length == initial.get_pn_length(), func, "%s #packet number length %i", text, initial.get_pn_length());
        _test_case.assert(length == initial.get_length(), func, "%s #length %I64u", text, initial.get_length());
    }
}

void test_rfc_9001_retry(testvector_retry_packet* item) {
    binary_t bin_odcid;
    binary_t bin_dcid;
    binary_t bin_scid;
    binary_t bin_token;
    binary_t bin_result;
    binary_t bin_expect_header;
    binary_t bin_expect_result;
    binary_t bin_expect_tag;

    const char* text = item->text;
    const char* func = item->func;
    tls_mode_t mode = item->mode;

    {
        bin_odcid = base16_decode_rfc(item->odcid);
        if (item->dcid) {
            bin_dcid = base16_decode_rfc(item->dcid);
        }
        if (item->scid) {
            bin_scid = base16_decode_rfc(item->scid);
        }
        if (item->token) {
            bin_token = base16_decode_rfc(item->token);
        }
        bin_expect_result = base16_decode_rfc(item->expect_result);
        bin_expect_tag = base16_decode_rfc(item->expect_tag);
    }

    quic_protection quicpp(bin_odcid);

    // write
    {
        quic_packet_retry retry;
        retry.attach(&quicpp);
        retry.set_dcid(bin_dcid).set_scid(bin_scid);
        retry.set_retry_token(bin_token);
        retry.write(bin_result, mode);
        _test_case.assert(bin_result == bin_expect_result, func, "RFC 9001 A.4.  Retry #write");
    }

    // read
    {
        size_t pos = 0;
        quic_packet_retry retry;
        retry.attach(&quicpp);
        retry.read(&bin_result[0], bin_result.size(), pos);

        basic_stream bs;
        retry.dump(&bs);
        _logger->writeln(bs);
        _test_case.assert(bin_dcid == retry.get_dcid(), func, "RFC 9001 A.4.  Retry #dcid");
        _test_case.assert(bin_scid == retry.get_scid(), func, "RFC 9001 A.4.  Retry #scid");
        _test_case.assert(bin_token == retry.get_retry_token(), func, "RFC 9001 A.4.  Retry #retry token");
        _test_case.assert(bin_expect_tag == retry.get_integrity_tag(), func, "RFC 9001 A.4.  Retry #retry integrity tag");
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
    test.mode = tls_mode_client;
    test.pad = true;
    test.resize = 1162;
    test.pn = 2;
    test.pn_length = 4;  // 00000002
    test.length = 1182;  // pnl 4 + frame 1162 + tag 16 -> length 1182

    test_rfc_9001_initial(&test, &rfc9001_session);
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
    test.mode = tls_mode_server;
    test.pad = false;
    test.resize = 0;
    test.pn = 1;
    test.pn_length = 2;  // 0001
    test.length = 117;

    test_rfc_9001_initial(&test, &rfc9001_session);
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
    test.mode = tls_mode_server;

    test_rfc_9001_retry(&test);
}

void test_rfc_9001_a5() {
    _test_case.begin("RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet");
    openssl_kdf kdf;
    const char* secret = "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b";
    binary_t bin_secret = base16_decode_rfc(secret);
    binary_t context;
    binary_t bin_key;
    binary_t bin_iv;
    binary_t bin_hp;
    binary_t bin_ku;
    const char* alg = "sha256";
    kdf.hkdf_expand_label(bin_key, alg, 32, bin_secret, str2bin("quic key"), context);
    kdf.hkdf_expand_label(bin_iv, alg, 12, bin_secret, str2bin("quic iv"), context);
    kdf.hkdf_expand_label(bin_hp, alg, 32, bin_secret, str2bin("quic hp"), context);
    kdf.hkdf_expand_label(bin_ku, alg, 32, bin_secret, str2bin("quic ku"), context);
    _logger->hdump("> key", bin_key, 16, 3);
    _test_case.assert(bin_key == base16_decode("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), __FUNCTION__, "key");
    _logger->hdump("> iv", bin_iv, 16, 3);
    _test_case.assert(bin_iv == base16_decode("e0459b3474bdd0e44a41c144"), __FUNCTION__, "iv");
    _logger->hdump("> hp", bin_hp, 16, 3);
    _test_case.assert(bin_hp == base16_decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), __FUNCTION__, "hp");
    _logger->hdump("> ku", bin_ku, 16, 3);
    _test_case.assert(bin_ku == base16_decode("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"), __FUNCTION__, "ku");
}
