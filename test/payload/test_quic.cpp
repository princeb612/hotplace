/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *  see HTTP/2 Frame
 */

#include "sample.hpp"

void test_quic_integer() {
    _test_case.begin("proof of concept payload_encoded");
    const char* expect =
        "3B 52 46 43 20 39 30 30 30 20 51 55 49 43 3A 20"  // ;RFC 9000 QUIC:
        "41 20 55 44 50 2D 42 61 73 65 64 20 4D 75 6C 74"  // A UDP-Based Mult
        "69 70 6C 65 78 65 64 20 61 6E 64 20 53 65 63 75"  // iplexed and Secu
        "72 65 20 54 72 61 6E 73 70 6F 72 74 25 31 36 2E"  // re Transport%16.
        "20 20 56 61 72 69 61 62 6C 65 2D 4C 65 6E 67 74"  //   Variable-Lengt
        "68 20 49 6E 74 65 67 65 72 20 45 6E 63 6F 64 69"  // h Integer Encodi
        "6E 67 -- -- -- -- -- -- -- -- -- -- -- -- -- --"  // ng
        ;
    binary_t bin_expect = std::move(base16_decode_rfc(expect));

    // step.1 a variable length integer + set_reference_value
    {
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded(59), "len1") << new payload_member("RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport", "var1")
            << new payload_member(new quic_encoded(37), "len2") << new payload_member("16.  Variable-Length Integer Encoding", "var2");
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write");

        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded(uint64(0)), "len1") << new payload_member(binary_t(), "var1")
            << new payload_member(new quic_encoded(uint64(0)), "len2") << new payload_member(binary_t(), "var2");
        pl2.set_reference_value("var1", "len1");  // length of "var1" is value of "len1"
        pl2.set_reference_value("var2", "len2");  // length of "var2" is value of "len2"
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read");
        size_t len1 = pl2.select("len1")->get_payload_encoded()->value();
        _test_case.assert(59 == len1, __FUNCTION__, "QUIC variable length integer #get_length %zi", len1);
        size_t len2 = pl2.select("len2")->get_payload_encoded()->value();
        _test_case.assert(37 == len2, __FUNCTION__, "QUIC variable length integer #get_length %zi", len2);
    }

    // step.1 encode a variable length integer + data
    {
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded("RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport"), "var1")
            << new payload_member(new quic_encoded("16.  Variable-Length Integer Encoding"), "var2");
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write");

        // step.2 decode a variable length integer + data
        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded, "var1") << new payload_member(new quic_encoded, "var2");
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read");
    }

    // step.4 zero-length
    {
        const char* expect_zero_length = "00";
        binary_t bin_expect_zero_length = std::move(base16_decode_rfc(expect_zero_length));
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded(""));
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect_zero_length, __FUNCTION__, "zero-length #write");

        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded(binary_t()));
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect_zero_length, __FUNCTION__, "zero-length #read");
    }

    {
        constexpr char constexpr_input[] = "input";
        constexpr char input[] = "05 01 02 03 04 05";
        constexpr char data[] = "01 02 03 04 05";
        binary_t bin_input = std::move(base16_decode_rfc(input));
        payload pl;
        pl << new payload_member(new quic_encoded(binary_t()), constexpr_input);
        size_t pos = 0;
        pl.read(&bin_input[0], bin_input.size(), pos);
        binary_t bin_data;
        auto encoded = pl.select(constexpr_input)->get_payload_encoded();
        auto value = encoded->value();
        encoded->get_variant().to_binary(bin_data);
        _test_case.assert(5 == value, __FUNCTION__, "opaque #1");
        _logger->hdump("dump", bin_data);
        _test_case.assert(bin_data == base16_decode_rfc(data), __FUNCTION__, "opaque #2");
    }

    // integer
    auto test_lambda = [&](uint64 value, const char* expect) -> void {
        binary_t bin_expect = std::move(base16_decode_rfc(expect));
        payload pl1;
        binary_t bin1;

        pl1 << new payload_member(new quic_encoded(value));
        pl1.write(bin1);

        _logger->hdump("> dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write %I64i -> %s", value, base16_encode(bin1).c_str());

        payload pl2;
        binary_t bin2;

        pl2 << new payload_member(new quic_encoded(uint64(0)));
        pl2.read(bin1);
        pl2.write(bin2);

        _logger->hdump("> dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read %I64i -> %s", value, base16_encode(bin2).c_str());
    };

    // RFC 9000 A.1
    test_lambda(151288809941952652, "0xc2197c5eff14e88c");
    test_lambda(494878333, "0x9d7f3e7d");
    test_lambda(15293, "0x7bbd");

    test_lambda(0x00, "0x00");
    test_lambda(0x3f, "0x3f");
    test_lambda(0x40, "0x4040");
    test_lambda(0x3fff, "0x7fff");
    test_lambda(0x4000, "0x80004000");
    test_lambda(0x3fffffff, "0xbfffffff");
    test_lambda(0x40000000, "0xc000000040000000");
    test_lambda(0x3fffffffffffffff, "0xffffffffffffffff");
}
