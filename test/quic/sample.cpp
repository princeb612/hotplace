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
#include <sdk/net/http/http3/qpack.hpp>
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
    _test_case.begin("A.1.  Sample Variable-Length Integer Decoding");

    auto lambda_read = [&](const char* input, uint64 expect) -> void {
        binary_t bin = base16_decode_rfc(input);
        size_t pos = 0;
        uint64 value = 0;
        read_variant_int(&bin[0], bin.size(), pos, value);
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
    _test_case.begin("A.2.  Sample Packet Number Encoding Algorithm");
    auto lambda = [&](uint64 full_pn, uint64 largest_acked, uint64 expect_represent, uint8 expect_nbits) -> void {
        uint64 represent = 0;
        uint8 nbits = 0;
        encode_packet_number(full_pn, largest_acked, represent, nbits);
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
        _logger->writeln("%I64i %x", value, value);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_rfc_9000_a3() {
    _test_case.begin("A.3.  Sample Packet Number Decoding Algorithm");
    uint64 value = 0;
    decode_packet_number(0xa82f30ea, 0x9b32, 16, value);
    _test_case.assert(0xa82f9b32 == value, __FUNCTION__, "RFC 9000 A.3.");
}

void test_quic_packet() {
    auto lambda = [&](quic_packet_t type) -> void {
        // dummy
        quic_packet packet(type);
        binary_t bin;
        packet.set_version(0x01020304);
        packet.set_dcid(str2bin("destination connection id"));
        packet.set_scid(str2bin("source connection id"));
        packet.write(bin);
        basic_stream bs;
        packet.dump(&bs);
        _logger->dump(bin);
        _logger->writeln(bs);

        bs.clear();

        _logger->writeln("reparse");
        binary_t bin2;
        size_t pos = 0;
        quic_packet packet2;
        packet2.read(&bin[0], bin.size(), pos);
        packet2.write(bin2);
        packet2.dump(&bs);
        _logger->dump(bin);
        _logger->writeln(bs);

        _test_case.assert(bin == bin2, __FUNCTION__, "quic packet");
    };

    lambda(quic_packet_version_negotiation);
    lambda(quic_packet_initial);
    lambda(quic_packet_0_rtt);
    lambda(quic_packet_handshake);
    lambda(quic_packet_retry);
    lambda(quic_packet_1_rtt);
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
    test_quic_packet();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
