/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_base16() {
    return_t ret = errorcode_t::success;
    constexpr char text[] = R"(0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'",<.>/\?)";
    std::string encoded;

    base16_encode((byte_t*)text, strlen(text), encoded);
    binary_t decoded;
    ret = base16_decode(encoded, decoded);

    {
        test_case_notimecheck notimecheck(_test_case);

        _logger->writeln("input : %s", text);
        _logger->writeln("encode: %s", encoded.c_str());
        _logger->hdump("dump decoded", decoded);
    }

    bool test = false;
    test = (strlen(text) == decoded.size());
    _test_case.assert(test, __FUNCTION__, "b16");
}

void test_base16_func() {
    return_t ret = errorcode_t::success;
    constexpr byte_t text[] = "still a man hears what he wants to hear and disregards the rest";

    /* return_t base16_encode (const byte_t* source, size_t size, char* buf, size_t* buflen) */
    size_t size = 0;
    std::vector<char> buf;
    base16_encode(text, RTL_NUMBER_OF(text), nullptr, &size);
    buf.resize(size);
    ret = base16_encode(text, RTL_NUMBER_OF(text), &buf[0], &size);
    _logger->dump(&buf[0], buf.size());
    _test_case.test(ret, __FUNCTION__, "case1");

    /* return_t base16_encode (const byte_t* source, size_t size, std::string& outpart) */
    std::string strbuf;
    ret = base16_encode(text, RTL_NUMBER_OF(text), strbuf);
    _logger->dump(strbuf);
    _test_case.test(ret, __FUNCTION__, "case2");

    /* return_t base16_encode (const byte_t* source, size_t size, stream_t* stream) */
    basic_stream streambuf;
    ret = base16_encode(text, RTL_NUMBER_OF(text), &streambuf);
    _logger->dump(streambuf);
    _test_case.test(ret, __FUNCTION__, "case3");
}

void test_base16_decode() {
    return_t ret = errorcode_t::success;
    std::string encoded("0x000102030405060708090a0b0c0d0e0f808182838485868788898a8b8c8d8e8f");

    binary_t decoded;

    ret = base16_decode(encoded, decoded);

    {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        dump_memory(&decoded[0], decoded.size(), &bs);
        _logger->writeln("%s", bs.c_str());
    }

    bool test = false;
    test = ((encoded.size() / 2) == decoded.size());
    _test_case.test(ret, __FUNCTION__, "b16");
}

void test_base16_oddsize() {
    const char* test = "0cef3f4babe6f9875e5db28c27d6a197d607c3641a90f10c2cc2cb302ba658aa151dc76c507488b99f4b3c8bb404fb5c852f959273f412cbdd5e713c5e3f0e67f94";
    binary_t bin_test = std::move(base16_decode(test));

    {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        dump_memory(bin_test, &bs);
        _logger->writeln("%s", bs.c_str());
    }

    _test_case.assert(66 == bin_test.size(), __FUNCTION__, "odd size");
}

void do_dump_base16_rfc(const char* text, const char* input) {
    basic_stream bs;

    std::string encoded = std::move(base16_encode_rfc(input));
    binary_t decoded = std::move(base16_decode(encoded));
    dump_memory(decoded, &bs, 16, 4);
    _logger->writeln("%s\n  input   %s\n  encoded %s\n  decoded\n%s", text, input, encoded.c_str(), bs.c_str());
}

void test_base16_rfc() {
    _test_case.begin("base16_rfc");

    constexpr char expr1[] = "[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]";  // e3 c5 75 fc 2 db e9 44 b4 e1 4d db
    constexpr char expr2[] = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
    constexpr char expr3[] =
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f";

    do_dump_base16_rfc("case1", expr1);
    do_dump_base16_rfc("case2", expr2);
    do_dump_base16_rfc("case3", expr3);
}
