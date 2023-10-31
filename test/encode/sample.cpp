/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <fstream>
#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void test_base16() {
    return_t ret = errorcode_t::success;
    constexpr char text[] = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'\",<.>/\?";
    std::string encoded;

    base16_encode((byte_t*)text, strlen(text), encoded);
    binary_t decoded;
    ret = base16_decode(encoded, decoded);

    {
        test_case_notimecheck notimecheck(_test_case);

        printf("input : %s\n", text);
        printf("encode: %s\n", encoded.c_str());
        basic_stream bs;
        dump_memory(&decoded[0], decoded.size(), &bs);
        printf("dump decoded\n%s\n", bs.c_str());
    }

    bool test = false;
    test = (strlen(text) == decoded.size());
    _test_case.assert(test, __FUNCTION__, "b16");
}

void test_base16_func() {
    return_t ret = errorcode_t::success;
    constexpr byte_t text[] = "still a man hears what he wants to hear and disregards the rest";
    basic_stream bs;

    /* return_t base16_encode (const byte_t* source, size_t size, char* buf, size_t* buflen) */
    size_t size = 0;
    std::vector<char> buf;

    base16_encode(text, RTL_NUMBER_OF(text), nullptr, &size);
    buf.resize(size);
    ret = base16_encode(text, RTL_NUMBER_OF(text), &buf[0], &size);
    dump_memory((byte_t*)&buf[0], buf.size(), &bs);
    std::cout << bs.c_str() << std::endl;
    _test_case.test(ret, __FUNCTION__, "case1");

    /* return_t base16_encode (const byte_t* source, size_t size, std::string& outpart) */
    std::string strbuf;
    ret = base16_encode(text, RTL_NUMBER_OF(text), strbuf);
    dump_memory(strbuf, &bs);
    std::cout << bs.c_str() << std::endl;
    _test_case.test(ret, __FUNCTION__, "case2");

    /* return_t base16_encode (const byte_t* source, size_t size, stream_t* stream) */
    basic_stream streambuf;
    ret = base16_encode(text, RTL_NUMBER_OF(text), &streambuf);
    dump_memory(streambuf.data(), streambuf.size(), &bs);
    std::cout << bs.c_str() << std::endl;
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
        printf("%s\n", bs.c_str());
    }

    bool test = false;
    test = ((encoded.size() / 2) == decoded.size());
    _test_case.test(ret, __FUNCTION__, "b16");
}

void test_base16_oddsize() {
    const char* test = "0cef3f4babe6f9875e5db28c27d6a197d607c3641a90f10c2cc2cb302ba658aa151dc76c507488b99f4b3c8bb404fb5c852f959273f412cbdd5e713c5e3f0e67f94";
    binary_t bin_test = base16_decode(test);

    {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        dump_memory(bin_test, &bs);
        printf("%s\n", bs.c_str());
    }

    _test_case.assert(66 == bin_test.size(), __FUNCTION__, "odd size");
}

void test_base64_routine(const char* source, size_t source_size, int encoding) {
    return_t ret = errorcode_t::success;
    basic_stream bs;
    std::string encoded_b64;
    binary_t decoded_b64;

    _test_case.reset_time();
    base64_encode((byte_t*)source, source_size, encoded_b64, encoding);
    base64_decode(encoded_b64, decoded_b64, encoding);
    _test_case.assert(0 == memcmp(source, &decoded_b64[0], source_size), __FUNCTION__, "base64_decode");

    {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory((byte_t*)source, source_size, &bs);
        printf("input\n%s\n", bs.c_str());
        dump_memory((byte_t*)&encoded_b64[0], encoded_b64.size(), &bs);
        printf("encoded\n%.*s\n", (int)bs.size(), bs.c_str());
        dump_memory(&decoded_b64[0], decoded_b64.size(), &bs);
        printf("decoded\n%.*s\n", (int)bs.size(), bs.c_str());
    }
}

void test_base64() {
    constexpr char lyrics[] = "still a man hears what he wants to hear and disregards the rest";
    size_t len = strlen(lyrics);

    test_base64_routine(lyrics, len, base64_encoding_t::base64_encoding);
    test_base64_routine(lyrics, len, base64_encoding_t::base64url_encoding);
}

enum {
    decode_b64u = 1,
    decode_b64 = 2,
    encode_plaintext = 3,
    decode_b16 = 4,
};
typedef struct _OPTION {
    int mode;
    std::string content;
    std::string filename;

    _OPTION() : mode(0) {}
    void set(int m, char* param) {
        mode = m;
        if (param) {
            content = param;
        }
    }
    void setfile(char* param) {
        if (param) {
            filename = param;
        }
    }
} OPTION;

void whatsthis(int argc, char** argv) {
    return_t ret = errorcode_t::success;
    cmdline_t<OPTION> cmdline;

    cmdline << cmdarg_t<OPTION>("-b64u", "decode base64url", [&](OPTION& o, char* param) -> void { o.set(decode_b64u, param); }).preced().optional()
            << cmdarg_t<OPTION>("-b64", "decode base64", [&](OPTION& o, char* param) -> void { o.set(decode_b64, param); }).preced().optional()
            << cmdarg_t<OPTION>("-t", "plaintext", [&](OPTION& o, char* param) -> void { o.set(encode_plaintext, param); }).preced().optional()
            << cmdarg_t<OPTION>("-b16", "decode base16", [&](OPTION& o, char* param) -> void { o.set(decode_b16, param); }).preced().optional()
            << cmdarg_t<OPTION>("-out", "write to file", [&](OPTION& o, char* param) -> void { o.setfile(param); }).preced().optional();
    ret = cmdline.parse(argc, argv);

    OPTION o = cmdline.value();
    if (o.mode && errorcode_t::success == ret) {
        basic_stream bs;
        basic_stream additional;
        binary_t what;
        binary_t temp;
        switch (o.mode) {
            case decode_b64u:
                what = base64_decode(o.content, base64_encoding_t::base64url_encoding);
                break;
            case decode_b64:
                what = base64_decode(o.content, base64_encoding_t::base64_encoding);
                break;
            case encode_plaintext:
                what = convert(o.content);
                base16_encode(o.content, temp);
                additional << "> b16\n  " << convert(temp).c_str() << "\n";
                additional << "> b64\n  " << base64_encode(o.content).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(o.content, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case decode_b16:
                what = base16_decode(o.content);
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
        }

        if (encode_plaintext == o.mode) {
            dump_memory(convert(o.content), &bs, 16, 2);
        } else {
            dump_memory(what, &bs, 16, 2);
        }

        if (o.filename.size() && o.content.size()) {
            std::ofstream file(o.filename.c_str(), std::ios::trunc);
            file.write((const char*)&what[0], what.size());
            file.close();
        }

        std::cout << "what u want to know" << std::endl << "< " << o.content << std::endl << bs.c_str() << std::endl;
        if (additional.size()) {
            std::cout << additional.c_str() << std::endl;
        }
    } else {
        cmdline.help();
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _test_case.begin("b16 encoding");
    test_base16();
    test_base16_func();
    test_base16_decode();
    test_base16_oddsize();

    _test_case.begin("b64 encoding");
    test_base64();

    _test_case.report(5);
    whatsthis(argc, argv);
    return _test_case.result();
}
