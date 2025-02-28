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

void test_rfc_9000_a1() {
    _test_case.begin("RFC 9000 A.1.  Sample Variable-Length Integer Decoding");

    auto lambda_read = [&](const char* input, uint64 expect) -> void {
        binary_t bin = base16_decode_rfc(input);
        size_t pos = 0;
        uint64 value = 0;
        quic_read_vle_int(&bin[0], bin.size(), pos, value);
        _logger->writeln(R"(> decode/read %s -> %I64i (0x%I64x))", input, value, value);
        _test_case.assert(expect == value, __FUNCTION__, R"(RFC 9000 A.1. expect "%s" -> %I64i)", input, expect);
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

    lambda_read("0x17", 0x17);                // 23 prefix 0
    lambda_read("0x4017", 0x17);              // 23 prefix 1
    lambda_read("0x80000017", 0x17);          // 23 prefix 2
    lambda_read("0xc000000000000017", 0x17);  // 23 prefix 3

    auto lambda_write = [&](uint64 value, const char* expect) -> void {
        binary_t bin_value;
        binary_t bin_expect;
        bin_expect = base16_decode_rfc(expect);
        quic_write_vle_int(value, bin_value);
        _logger->writeln("> encode/write %I64i -> %s", value, base16_encode(bin_value).c_str());
        _test_case.assert(bin_value == bin_expect, __FUNCTION__, R"(RFC 9000 A.1. %I64i -> "%s")", value, expect);
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

    auto lambda_write2 = [&](uint64 value, uint8 prefix, const char* expect) -> void {
        binary_t bin_value;
        binary_t bin_expect;
        bin_expect = base16_decode_rfc(expect);
        quic_write_vle_int(value, prefix, bin_value);
        _logger->writeln("> encode/write %I64i -> %s", value, base16_encode(bin_value).c_str());
        _test_case.assert(bin_value == bin_expect, __FUNCTION__, R"(RFC 9000 A.1. %I64i -> "%s")", value, expect);
    };

    lambda_write2(0x17, 0, "0x17");                // 23 prefix 0
    lambda_write2(0x17, 1, "0x4017");              // 23 prefix 1
    lambda_write2(0x17, 2, "0x80000017");          // 23 prefix 2
    lambda_write2(0x17, 3, "0xc000000000000017");  // 23 prefix 3
}

void test_rfc_9000_a2() {
    _test_case.begin("RFC 9000 A.2.  Sample Packet Number Encoding Algorithm");
    auto lambda = [&](uint64 full_pn, uint64 largest_acked, uint64 expect_represent, uint8 expect_nbits) -> void {
        uint64 represent = 0;
        uint8 nbits = 0;
        encode_packet_number(full_pn, largest_acked, represent, nbits);
        _logger->writeln("> full_pn %I64i largest_acked %I64i -> expect_represent %I64i expect_nbits %i", full_pn, largest_acked, represent, nbits);
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
