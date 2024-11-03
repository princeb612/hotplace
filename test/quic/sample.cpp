/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_rfc_9000_a1() {
    _test_case.begin("RFC 9000 A.1.  Sample Variable-Length Integer Decoding");

    auto lambda_read = [&](const char* input, uint64 expect) -> void {
        binary_t bin = base16_decode_rfc(input);
        size_t pos = 0;
        uint64 value = 0;
        quic_read_vle_int(&bin[0], bin.size(), pos, value);
        _logger->writeln("quic_read_vle_int %s -> %I64i");
        _test_case.assert(expect == value, __FUNCTION__, R"(RFC 9000 A.1. %s -> "%I64i")", input, expect);
    };

    lambda_read("0xc2197c5eff14e88c", 151288809941952652);  // prefix 3 length 8
    lambda_read("0x9d7f3e7d", 494878333);                   // prefix 2 length 4
    lambda_read("0x7bbd", 15293);                           // prefix 1 length 2

    lambda_read("0x00", 0x00);                              // MSB 00, length 1, 0
    lambda_read("0x3f", 0x3f);                              // MSB 00, length 1, 63
    lambda_read("0x4040", 0x40);                            // MSB 01, length 2, 64
    lambda_read("0x7fff", 0x3fff);                          // MSB 01, length 2, 16383
    lambda_read("0x80004000", 0x4000);                      // MSB 10, length 4, 16384
    lambda_read("0xbfffffff", 0x3fffffff);                  // MSB 10, length 4, 1073741823
    lambda_read("0xc000000040000000", 0x40000000);          // MSB 11, length 8, 1073741824
    lambda_read("0xffffffffffffffff", 0x3fffffffffffffff);  // MSB 11, length 8, 4611686018427387903

    auto lambda_write = [&](size_t value, const char* expect) -> void {
        binary_t bin_value;
        binary_t bin_expect;
        bin_expect = base16_decode_rfc(expect);
        quic_write_vle_int(value, bin_value);
        _logger->dump(bin_value);
        _test_case.assert(bin_value == bin_expect, __FUNCTION__, "RFC 9000 A.1. %I64i -> %s", value, expect);
    };

    lambda_write(151288809941952652, "0xc2197c5eff14e88c");
    lambda_write(494878333, "0x9d7f3e7d");
    lambda_write(15293, "0x7bbd");

    lambda_write(0x00, "0x00");                              // MSB 00, length 1, 0
    lambda_write(0x3f, "0x3f");                              // MSB 00, length 1, 63
    lambda_write(0x40, "0x4040");                            // MSB 01, length 2, 64
    lambda_write(0x3fff, "0x7fff");                          // MSB 01, length 2, 16383
    lambda_write(0x4000, "0x80004000");                      // MSB 10, length 4, 16384
    lambda_write(0x3fffffff, "0xbfffffff");                  // MSB 10, length 4, 1073741823
    lambda_write(0x40000000, "0xc000000040000000");          // MSB 11, length 8, 1073741824
    lambda_write(0x3fffffffffffffff, "0xffffffffffffffff");  // MSB 11, length 8, 4611686018427387903
}

void test_rfc_9000_a2() {
    _test_case.begin("RFC 9000 A.2.  Sample Packet Number Encoding Algorithm");
    auto lambda = [&](uint64 full_pn, uint64 largest_acked, uint64 expect_represent, uint8 expect_nbits) -> void {
        uint64 represent = 0;
        uint8 nbits = 0;
        encode_packet_number(full_pn, largest_acked, represent, nbits);
        _logger->writeln("full_pn %I64i largest_acked %I64i -> expect_represent %I64i expect_nbits %i", full_pn, largest_acked, represent, nbits);
        _test_case.assert(represent == expect_represent, __FUNCTION__, "RFC 9000 A.2 represent");
        _test_case.assert(nbits == expect_nbits, __FUNCTION__, "RFC 9000 A.2 bits required");
    };
    lambda(0xac5c02, 0xabe8b3, 0xe69e, 16);
    lambda(0xace8fe, 0xabe8b3, 0x020096, 18);
}

void test_rfc_9000_a3() {
    _test_case.begin("RFC 9000 A.3.  Sample Packet Number Decoding Algorithm");
    uint64 value = 0;
    decode_packet_number(0xa82f30ea, 0x9b32, 16, value);
    _test_case.assert(0xa82f9b32 == value, __FUNCTION__, "RFC 9000 A.3.");
}

void test_rfc_9001_section4() {
    _test_case.begin("RFC 9001 4.  Carrying TLS Messages");
    //
}

void test_rfc_9001_a1() {
    _test_case.begin("RFC 9001 A.1.  Keys");
    openssl_kdf kdf;

    const char* initial_salt = "0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    const char* client_in = "00200f746c73313320636c69656e7420696e00";
    const char* server_in = "00200f746c7331332073657276657220696e00";
    const char* quic_key = "00100e746c7331332071756963206b657900";
    const char* quic_iv = "000c0d746c733133207175696320697600";
    const char* quic_hp = "00100d746c733133207175696320687000";

    // Destination Connection ID of 0x8394c8f03e515708
    // initial_secret = HKDF-Extract(initial_salt, cid)
    const char* dcid = "0x8394c8f03e515708";
    const char* initial_secret = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";
    const char* client_initial_secret = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
    const char* server_initial_secret = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";

    binary_t bin_dcid = base16_decode_rfc(dcid);
    binary_t bin_initial_salt = base16_decode_rfc(initial_salt);
    binary_t bin_client_in = base16_decode_rfc(client_in);
    binary_t bin_server_in = base16_decode_rfc(server_in);
    binary_t bin_quic_key = base16_decode_rfc(quic_key);
    binary_t bin_quic_iv = base16_decode_rfc(quic_iv);
    binary_t bin_quic_hp = base16_decode_rfc(quic_hp);
    binary_t bin_initial_secret = base16_decode_rfc(initial_secret);
    binary_t bin_client_initial_secret = base16_decode_rfc(client_initial_secret);
    binary_t bin_server_initial_secret = base16_decode_rfc(server_initial_secret);

    _logger->hdump("> DCID", bin_dcid, 16, 2);
    _logger->hdump("> initial_secret", bin_initial_secret, 16, 2);
    _logger->hdump("> initial_salt", bin_initial_salt, 16, 2);
    _logger->hdump("> client_in", bin_client_in, 16, 2);
    _logger->hdump("> server_in", bin_server_in, 16, 2);
    _logger->hdump("> bin_quic_key", bin_quic_key, 16, 2);
    _logger->hdump("> bin_quic_iv", bin_quic_iv, 16, 2);
    _logger->hdump("> bin_quic_hp", bin_quic_hp, 16, 2);

    /**
     * RFC 5869
     *  HKDF-Extract(salt, IKM) -> PRK
     *  HKDF-Expand(PRK, info, L) -> OKM
     *
     * RFC 9001
     *  initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
     *  initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *  client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
     *  server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
     */

    binary_t bin_initial_secret_computed;
    kdf.hmac_kdf_extract(bin_initial_secret_computed, "sha256", bin_initial_salt, bin_dcid);
    _test_case.assert(bin_initial_secret == bin_initial_secret_computed, __FUNCTION__, "initial_secret");

    struct testvector {
        const char* text;
        const char* label;    // 1 .. 255 - 6
        const char* context;  // 0 .. 255
        uint16 dlen;
        binary_t* secret;
        binary_t* hkdflabel;
        const char* expect;
    } _testvector[] = {
        {
            "client_initial_secret",
            "client in",
            "",
            32,
            &bin_initial_secret,
            &bin_client_in,
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        },
        {
            "key (client)",
            "quic key",
            "",
            16,
            &bin_client_initial_secret,
            &bin_quic_key,
            "1f369613dd76d5467730efcbe3b1a22d",
        },
        {
            "iv (client)",
            "quic iv",
            "",
            12,
            &bin_client_initial_secret,
            &bin_quic_iv,
            "fa044b2f42a3fd3b46fb255c",
        },
        {
            "hp (client)",
            "quic hp",
            "",
            16,
            &bin_client_initial_secret,
            &bin_quic_hp,
            "9f50449e04a0e810283a1e9933adedd2",
        },
        {
            "server_initial_secret",
            "server in",
            "",
            32,
            &bin_initial_secret,
            &bin_server_in,
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        },
        {
            "key (server)",
            "quic key",
            "",
            16,
            &bin_server_initial_secret,
            &bin_quic_key,
            "cf3a5331653c364c88f0f379b6067e37",
        },
        {
            "iv (server)",
            "quic iv",
            "",
            12,
            &bin_server_initial_secret,
            &bin_quic_iv,
            "0ac1493ca1905853b0bba03e",
        },
        {
            "hp (server)",
            "quic hp",
            "",
            16,
            &bin_server_initial_secret,
            &bin_quic_hp,
            "c206b8d9b9f0f37644430b490eeaa314",
        },
    };

    for (auto item : _testvector) {
        binary_t bin_expect = base16_decode_rfc(item.expect);

        binary_t bin_computed1;
        binary_t bin_computed2;
        kdf.hkdf_expand(bin_computed1, "sha256", item.dlen, *item.secret, *item.hkdflabel);
        kdf.hkdf_expand_label(bin_computed2, "sha256", item.dlen, *item.secret, str2bin(item.label), str2bin(item.context));

        _logger->writeln(item.text);
        _logger->hdump("> expected", bin_expect, 16, 2);
        _logger->hdump("> hkdf_expand", bin_computed1, 16, 2);
        _logger->hdump("> hkdf_expand_label", bin_computed2, 16, 2);
        _test_case.assert(bin_computed1 == bin_expect, __FUNCTION__, "RFC 9000 A.1. %s", item.text);
        _test_case.assert(bin_computed2 == bin_expect, __FUNCTION__, "RFC 9000 A.1. %s", item.text);
    }
}

void test_rfc_9001_a2() {
    _test_case.begin("RFC 9001 A.2.  Client Initial");

    binary_t bin_crypto_frame_payload;
    binary_t bin_unprotected_header;
    basic_stream bs;
    size_t pos = 0;

    {
        /**
         * RFC 9000
         *  19.6.  CRYPTO Frames
         *  Figure 30: CRYPTO Frame Format
         */
        const char* crypto_frame_payload =
            "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868"
            "04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578"
            "616d706c652e636f6dff01000100000a 00080006001d00170018001000070005"
            "04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba"
            "baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408 050806002d00020101001c0002400100"
            "3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000"
            "75300901100f088394c8f03e51570806 048000ffff";
        bin_crypto_frame_payload = base16_decode_rfc(crypto_frame_payload);
    }

    {
        quic_packet_initial packet;
        const char* unprotected_header = "c300000001088394c8f03e5157080000449e00000002";
        bin_unprotected_header = base16_decode_rfc(unprotected_header);

        // unprotected header
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
        // [0x10] Length        : 449e (1182)
        // [0x12] Packet Number : 00000002

        _logger->hdump("unprotected header", bin_unprotected_header, 16, 3);

        pos = 0;
        packet.read(&bin_unprotected_header[0], bin_unprotected_header.size(), pos);
        packet.dump(&bs);

        _logger->writeln("dump packet");
        _logger->writeln(bs);

        /**
         *
         * RFC 9001 5.4.3.  AES-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    mask = AES-ECB(hp_key, sample)
         *
         * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    counter = sample[0..3]
         *    nonce = sample[4..15]
         *    mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
         *
         * RFC 9001 A.2.
         *  sample = d1b1c98dd7689fb8ec11d242b123dc9b
         *  mask = AES-ECB(hp, sample)[0..4]
         *       = 437b9aec36
         */

        const char* hp = "9f50449e04a0e810283a1e9933adedd2";
        const char* sample = "d1b1c98dd7689fb8ec11d242b123dc9b";
        binary_t bin_hp = base16_decode_rfc(hp);
        binary_t bin_sample = base16_decode_rfc(sample);
        binary_t bin_mask;

        crypt_context_t* handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&handle, "aes-128-ecb", bin_hp, binary_t());
        crypt.encrypt(handle, bin_sample, bin_mask);
        crypt.close(handle);

        bin_mask.resize(5);  // [0..4]
        _logger->hdump("hp", bin_hp, 16, 3);
        _logger->hdump("sample", bin_sample, 16, 3);
        _logger->hdump("mask", bin_mask, 16, 3);
        _test_case.assert(bin_mask == base16_decode("437b9aec36"), __FUNCTION__, "RFC 9001 A.2. mask");

        /**
         * RFC 9001 5.4.1.  Header Protection Application
         *
         *  mask = header_protection(hp_key, sample)
         *
         *  pn_length = (packet[0] & 0x03) + 1
         *  if (packet[0] & 0x80) == 0x80:
         *     # Long header: 4 bits masked
         *     packet[0] ^= mask[0] & 0x0f
         *  else:
         *     # Short header: 5 bits masked
         *     packet[0] ^= mask[0] & 0x1f
         *
         *  # pn_offset is the start of the Packet Number field.
         *  packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
         *
         *                  Figure 6: Header Protection Pseudocode
         *
         * RFC 9001 A.2.
         *  header[0] ^= mask[0] & 0x0f
         *          = c0
         *  header[18..21] ^= mask[1..4]
         *          = 7b9aec34
         *  header = c000000001088394c8f03e5157080000449e7b9aec34
         */

        byte_t header0 = bin_unprotected_header[0];
        if (header0 & 0x80) {
            header0 ^= bin_mask[0] & 0x0f;
        } else {
            header0 ^= bin_mask[0] & 0x1f;
        }
        bin_unprotected_header[0] = header0;

        // pn_offset 0x12
        // see quic_packet_initial::read
        // see payload::offset_of("pn")
        auto pn_offset = 0x12;
        auto pnl = packet.get_pn_length();
        for (auto i = 0; i < pnl; i++) {
            auto b = bin_unprotected_header[pn_offset + i];
            b ^= bin_mask[1 + i];
            bin_unprotected_header[pn_offset + i] = b;
        }
        _logger->hdump("header", bin_unprotected_header, 16, 3);
        _test_case.assert(bin_unprotected_header == base16_decode("c000000001088394c8f03e5157080000449e7b9aec34"), __FUNCTION__, "RFC 9001 A.2.");

        const char* result =
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

        binary_t bin_result = base16_decode_rfc(result);

        // TODO
        // 1 result packet
        // 2 protected packet number

        // quic_packet_initial initial;
        // pos = 0;
        // initial.read(&bin_result[0], bin_result.size(), pos);
        // initial.dump(&bs);
        // _logger->writeln(bs);
    }
}

void test_rfc_9001_a3() {
    _test_case.begin("RFC 9001 A.3.  Server Initial");
    //
}

void test_rfc_9001_a4() {
    _test_case.begin("RFC 9001 A.4.  Retry");
    //
}

void test_rfc_9001_a5() {
    _test_case.begin("RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet");
    //
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    openssl_startup();

    // studying ...

    test_rfc_9000_a1();
    test_rfc_9000_a2();
    test_rfc_9000_a3();

    test_rfc_9001_section4();

    // RFC 9001 5.  Packet Protection
    // RFC 9001 Appendix A.  Sample Packet Protection

    test_rfc_9001_a1();
    test_rfc_9001_a2();
    test_rfc_9001_a3();
    test_rfc_9001_a4();
    test_rfc_9001_a5();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
