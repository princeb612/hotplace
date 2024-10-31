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

#include <math.h>
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

/**
 * @brief   RFC 9000
 *            16.  Variable-Length Integer Encoding
 *              Table 4: Summary of Integer Encodings
 *            17.1.  Packet Number Encoding and Decoding
 *            A.1.  Sample Variable-Length Integer Decoding
 *              Figure 45: Sample Variable-Length Integer Decoding Algorithm
 */
return_t read_variant_int(const byte_t* stream, size_t size, size_t& pos, uint64& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || 0 == size || (pos > size)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        value = 0;
        byte_t v = stream[pos++];
        auto prefix = v >> 6;
        auto length = 1 << prefix;
        v &= 0x3f;
        value = v;
        for (auto i = 0; i < length - 1; i++) {
            value = (value << 8) + stream[pos++];
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t write_variant_int(uint64 value, binary_t& bin) {
    return_t ret = errorcode_t::success;
    byte_t prefix = 0;
    __try2 {
        if (value > 0x3fffffffffffffff) {
            // Packet numbers are integers in the range 0 to 2^62-1 (Section 12.3).
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (value > 0x3fffffff) {
            prefix = 3;
        } else if (value > 0x3fff) {
            prefix = 2;
        } else if (value > 0x3f) {
            prefix = 1;
        }

        byte_t v = prefix << 6;
        byte_t length = 1 << prefix;
        auto i = hton64(value);
        byte_t* begin = (byte_t*)&i + sizeof(uint64) - length;

        begin[0] |= v;
        bin.insert(bin.end(), begin, begin + length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_rfc_9000_a1() {
    _test_case.begin("RFC 9000 A.1.  Sample Variable-Length Integer Decoding");

    auto lambda_read = [&](const char* input, uint64 expect) -> void {
        binary_t bin = base16_decode_rfc(input);
        size_t pos = 0;
        uint64 value = 0;
        read_variant_int(&bin[0], bin.size(), pos, value);
        _logger->writeln("read_variant_int %s -> %I64i");
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
        write_variant_int(value, bin_value);
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

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.2.  Sample Packet Number Encoding Algorithm
 *              Figure 46: Sample Packet Number Encoding Algorithm
 */
return_t encode_packet_number(uint64 full_pn, uint64 largest_acked, uint64& represent, uint8& nbits) {
    return_t ret = errorcode_t::success;
    uint64 num_unacked = 0;
    __try2 {
        represent = 0;
        nbits = 0;

        if (0 == largest_acked) {
            num_unacked = full_pn + 1;
        } else {
            num_unacked = full_pn - largest_acked;
        }

        uint64 min_bits = (log(num_unacked) / log(2)) + 1;
        uint8 num_bytes = ceil(min_bits / 8);

        // represent at leat twice
        represent = num_unacked << 1;
        nbits = (log(represent) / log(2)) + 1;
    }
    __finally2 {
        // do nothing
    }
    return ret;
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

/**
 * @brief   RFC 9000
 *            17.1.  Packet Number Encoding and Decoding
 *            A.3.  Sample Packet Number Decoding Algorithm
 *              Figure 47: Sample Packet Number Decoding Algorithm
 */
return_t decode_packet_number(uint64 largest_pn, uint64 truncated_pn, uint8 pn_nbits, uint64& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        value = 0;
        auto expected_pn = largest_pn + 1;
        auto pn_win = 1 << pn_nbits;
        auto pn_hwin = pn_win / 2;
        auto pn_mask = pn_win - 1;
        auto candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
        if ((candidate_pn <= expected_pn - pn_hwin) && (candidate_pn < 0x400000000000000 - pn_win)) {
            value = candidate_pn + pn_win;
        } else if ((candidate_pn > expected_pn + pn_hwin) && (candidate_pn >= pn_win)) {
            value = candidate_pn - pn_win;
        } else {
            value = candidate_pn;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
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

// RFC 9001 5.  Packet Protection
// RFC 9001 Appendix A.  Sample Packet Protection
//  Destination Connection ID of 0x8394c8f03e515708

void test_rfc_9001_a1() {
    _test_case.begin("RFC 9001 A.1.  Keys");
    openssl_kdf kdf;

    const char* initial_salt = "0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    const char* client_in = "00200f746c73313320636c69656e7420696e00";
    const char* server_in = "00200f746c7331332073657276657220696e00";
    const char* quic_key = "00100e746c7331332071756963206b657900";
    const char* quic_iv = "000c0d746c733133207175696320697600";
    const char* quic_hp = "00100d746c733133207175696320687000";
    // initial_secret = HKDF-Extract(initial_salt, cid), cid unknown
    const char* initial_secret = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";
    const char* client_initial_secret = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
    const char* server_initial_secret = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";

    binary_t bin_initial_salt = base16_decode_rfc(initial_salt);
    binary_t bin_client_in = base16_decode_rfc(client_in);
    binary_t bin_server_in = base16_decode_rfc(server_in);
    binary_t bin_quic_key = base16_decode_rfc(quic_key);
    binary_t bin_quic_iv = base16_decode_rfc(quic_iv);
    binary_t bin_quic_hp = base16_decode_rfc(quic_hp);
    binary_t bin_initial_secret = base16_decode_rfc(initial_secret);
    binary_t bin_client_initial_secret = base16_decode_rfc(client_initial_secret);
    binary_t bin_server_initial_secret = base16_decode_rfc(server_initial_secret);

    _logger->hdump("initial_secret", bin_initial_secret);
    _logger->hdump("initial_salt", bin_initial_salt);
    _logger->hdump("client_in", bin_client_in);
    _logger->hdump("server_in", bin_server_in);
    _logger->hdump("bin_quic_key", bin_quic_key);
    _logger->hdump("bin_quic_iv", bin_quic_iv);
    _logger->hdump("bin_quic_hp", bin_quic_hp);

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
        _test_case.assert(bin_computed1 == bin_expect, __FUNCTION__, item.text);
        _test_case.assert(bin_computed2 == bin_expect, __FUNCTION__, item.text);
    }
}

void test_rfc_9001_a2() {
    _test_case.begin("RFC 9001 A.2.  Client Initial");

    const char* crypto_and_padding_frame_payload =
        "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a 00080006001d00170018001000070005"
        "04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408 050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000"
        "75300901100f088394c8f03e51570806 048000ffff";

    // RFC 9001 A.2
    // RFC 9000 19.6.  CRYPTO Frames
    // RFC 9000 19.1.  PADDING Frames
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
