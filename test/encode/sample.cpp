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
t_shared_instance<logger> _logger;
return_t _cmdret = errorcode_t::success;

enum {
    decode_b64u = 1,
    decode_b64 = 2,
    decode_b16 = 3,
    encode_plaintext = 4,
    encode_b16_rfc = 5,
};
typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    int mode;
    std::string content;
    std::string filename;

    _OPTION() : verbose(0), log(0), time(0), mode(0) {}
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
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

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
    binary_t bin_test = base16_decode(test);

    {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        dump_memory(bin_test, &bs);
        _logger->writeln("%s", bs.c_str());
    }

    _test_case.assert(66 == bin_test.size(), __FUNCTION__, "odd size");
}

void dump_base16_rfc(const char* text, const char* input) {
    basic_stream bs;

    std::string encoded = base16_encode_rfc(input);
    binary_t decoded = base16_decode(encoded);
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

    dump_base16_rfc("case1", expr1);
    dump_base16_rfc("case2", expr2);
    dump_base16_rfc("case3", expr3);
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
        _logger->writeln("input\n%s", bs.c_str());
        dump_memory((byte_t*)&encoded_b64[0], encoded_b64.size(), &bs);
        _logger->writeln("encoded\n%.*s", (int)bs.size(), bs.c_str());
        dump_memory(&decoded_b64[0], decoded_b64.size(), &bs);
        _logger->writeln("decoded\n%.*s", (int)bs.size(), bs.c_str());
    }
}

void test_base64() {
    constexpr char lyrics[] = "still a man hears what he wants to hear and disregards the rest";
    size_t len = strlen(lyrics);

    test_base64_routine(lyrics, len, base64_encoding_t::base64_encoding);
    test_base64_routine(lyrics, len, base64_encoding_t::base64url_encoding);
}

void whatsthis() {
    return_t ret = errorcode_t::success;

    // $ ./test-encode -b64u AQIDBAU
    //  what u want to know
    //  < AQIDBAU
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=

    // $ ./test-encode -b64 AQIDBAU=
    //  what u want to know
    //  < AQIDBAU=
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64u
    //    AQIDBAU

    //  $ ./test-encode -rfc "[1,2 , 3, 4, 5]"
    //  what u want to know
    //  < [1,2 , 3, 4, 5]
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=
    //  > b64url
    //    AQIDBAU

    //  ./test-encode -rfc "01:02 : 03:04:05"
    //  what u want to know
    //  < 01:02 : 03:04:05
    //    00000000 : 01 02 03 04 05 -- -- -- -- -- -- -- -- -- -- -- | .....
    //  > b16
    //    0102030405
    //  > b64
    //    AQIDBAU=
    //  > b64url
    //    AQIDBAU

    //
    //  $ echo AQIDBAU= | base64 -d | xxd
    //  00000000: 0102 0304 05                             .....

    const OPTION o = _cmdline->value();
    if (o.mode && errorcode_t::success == _cmdret) {
        basic_stream bs;
        basic_stream additional;
        binary_t what;
        binary_t temp;
        std::string stemp;
        switch (o.mode) {
            case decode_b64u:
                what = base64_decode(o.content, base64_encoding_t::base64url_encoding);
                additional << "> b16\n  " << base16_encode(what).c_str() << "\n";
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                break;
            case decode_b64:
                what = base64_decode(o.content, base64_encoding_t::base64_encoding);
                additional << "> b16\n  " << base16_encode(what).c_str() << "\n";
                additional << "> b64u\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case encode_plaintext:
                what = str2bin(o.content);
                base16_encode(o.content, temp);
                additional << "> b16\n  " << bin2str(temp).c_str() << "\n";
                additional << "> b64\n  " << base64_encode(o.content).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(o.content, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case decode_b16:
                what = base16_decode(o.content);
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
            case encode_b16_rfc:
                stemp = base16_encode_rfc(o.content);
                what = base16_decode(stemp);
                additional << "> b16\n  " << stemp.c_str() << "\n";
                additional << "> b64\n  " << base64_encode(what).c_str() << "\n";
                additional << "> b64url\n  " << base64_encode(what, base64_encoding_t::base64url_encoding).c_str() << "\n";
                break;
        }

        if (encode_plaintext == o.mode) {
            dump_memory(str2bin(o.content), &bs, 16, 2);
        } else {
            dump_memory(what, &bs, 16, 2);
        }

        if (o.filename.size() && o.content.size()) {
            std::ofstream file(o.filename.c_str(), std::ios::trunc);
            file.write((const char*)&what[0], what.size());
            file.close();
        }

        basic_stream dbs;
        dbs << "what u want to know"
            << "\n"
            << "< " << o.content << "\n"
            << bs;
        _logger->consoleln(dbs);

        if (additional.size()) {
            _logger->consoleln(additional);
        }
    } else {
        _cmdline->help();
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);

    constexpr char constexpr_helpmsg_rfc[] = R"(encode base16 from rfc style expression ex. "[1,2,3,4,5]" or "01:02:03:04:05" or "01 02 03 04 05")";

    (*_cmdline) << t_cmdarg_t<OPTION>("-b64u", "decode base64url", [](OPTION& o, char* param) -> void { o.set(decode_b64u, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-b64", "decode base64", [](OPTION& o, char* param) -> void { o.set(decode_b64, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-b16", "decode base16", [](OPTION& o, char* param) -> void { o.set(decode_b16, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-t", "plaintext", [](OPTION& o, char* param) -> void { o.set(encode_plaintext, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-rfc", constexpr_helpmsg_rfc, [](OPTION& o, char* param) -> void { o.set(encode_b16_rfc, param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-out", "write to file", [](OPTION& o, char* param) -> void { o.setfile(param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();

    _cmdret = _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    _test_case.begin("b16 encoding");
    test_base16();
    test_base16_func();
    test_base16_decode();
    test_base16_oddsize();
    test_base16_rfc();

    _test_case.begin("b64 encoding");
    test_base64();

    _logger->flush();

    _test_case.report(5);
    whatsthis();
    return _test_case.result();
}
