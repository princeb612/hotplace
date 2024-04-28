/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver
 *
 * Revision History
 * Date         Name                Description
 */

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;
using namespace hotplace::net;

test_case _test_case;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;

void cprint(const char* text, ...) {
    console_color _concolor;

    std::cout << _concolor.turnon().set_fgcolor(console_color_t::cyan);
    va_list ap;
    va_start(ap, text);
    vprintf(text, ap);
    va_end(ap);
    std::cout << _concolor.turnoff() << std::endl;
}

void test_rfc7541_c_1_routine(uint8 prefix, size_t i, const char* expect, const char* text) {
    OPTION& option = cmdline->value();

    hpack hp;
    binary_t bin;
    basic_stream bs;
    size_t value = 0;
    size_t pos = 0;

    hp.encode_int(bin, 0x00, prefix, i);
    hp.decode_int(&bin[0], pos, prefix, value);

    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
        printf("decode %u\n", value);
    }

    bool test = false;
    test = (expect && (i == value));
    if (test) {
        binary_t bin_expect = base16_decode_rfc(expect);
        test = (test && (bin == bin_expect));
    }
    _test_case.assert(test, __FUNCTION__, text);
}

void test_rfc7541_c_1() {
    _test_case.begin("RFC 7541 HPACK C.1. Integer Representation Examples");
    OPTION& option = cmdline->value();

    test_rfc7541_c_1_routine(5, 10, "0a", "RFC 7541 C.1.1. Example 1: Encoding 10 Using a 5-Bit Prefix");
    test_rfc7541_c_1_routine(5, 1337, "1f9a0a", "RFC 7541 C.1.2. Example 2: Encoding 1337 Using a 5-Bit Prefix");
    test_rfc7541_c_1_routine(8, 42, "2a", "RFC 7541 C.1.3. Example 3: Encoding 42 Starting at an Octet Boundary");
}

void test_rfc7541_c_2() {
    _test_case.begin("RFC 7541 HPACK C.2. Header Field Representation Examples");
    OPTION& option = cmdline->value();

    hpack hp;

    binary_t bin;
    basic_stream bs;
    // C.2.1.  Literal Header Field with Indexing
    // "custom-key: custom-header"
    bin.clear();
    hp.encode_header(bin, "custom-key", "custom-header", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect1 =
        "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 "
        "746f 6d2d 6865 6164 6572                ";
    _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "RFC 7541 C.2.1 Literal Header Field with Indexing");

    // C.2.2.  Literal Header Field without Indexing
    // :path: /sample/path
    bin.clear();
    hp.encode_header(bin, ":path", "/sample/path", hpack_wo_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect2 = "040c 2f73 616d 706c 652f 7061 7468";
    _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "RFC 7541 C.2.2 Literal Header Field without Indexing");
    // C.2.3.  Literal Header Field Never Indexed
    // password: secret
    bin.clear();
    hp.encode_header(bin, "password", "secret", hpack_never_indexed);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect3 =
        "1008 7061 7373 776f 7264 0673 6563 7265 "
        "74                                      ";
    _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "RFC 7541 C.2.3 Literal Header Field Never Indexed");
    // C.2.4.  Indexed Header Field
    bin.clear();
    hp.encode_header(bin, ":method", "GET");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect4 = "82";
    _test_case.assert(bin == base16_decode_rfc(expect4), __FUNCTION__, "RFC 7541 C.2.4 Indexed Header Field");
}

// C.3.  Request Examples without Huffman Coding
void test_rfc7541_c_3() {
    _test_case.begin("RFC 7541 HPACK C.3. Request Examples without Huffman Coding");
    OPTION& option = cmdline->value();

    hpack hp;
    binary_t bin;
    basic_stream bs;
    // C.3.1.  First Request
    // :method: GET
    // :scheme: http
    // :path: /
    // :authority: www.example.com
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "http");
    hp.encode_header(bin, ":path", "/");
    hp.encode_header(bin, ":authority", "www.example.com", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect1 =
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 "
        "2e63 6f6d                               ";
    _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "RFC 7541 C.3.1 First Request");

    // [  1] (s =  57) :authority: www.example.com
    //       Table size:  57

    // C.3.2.  Second Request

    bin.clear();
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "http");
    hp.encode_header(bin, ":path", "/");
    hp.encode_header(bin, ":authority", "www.example.com", hpack_indexing);
    hp.encode_header(bin, "cache-control", "no-cache", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect2 = "8286 84be 5808 6e6f 2d63 6163 6865";
    _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "RFC 7541 C.3.2 Second Request");

    // [  1] (s =  53) cache-control: no-cache
    // [  2] (s =  57) :authority: www.example.com
    //       Table size: 110

    // C.3.3.  Third Request

    bin.clear();
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "https");
    hp.encode_header(bin, ":path", "/index.html");
    hp.encode_header(bin, ":authority", "www.example.com");
    hp.encode_header(bin, "custom-key", "custom-value", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect3 =
        "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 "
        "0c63 7573 746f 6d2d 7661 6c75 65        ";
    _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "RFC 7541 C.3.3 Third Request");

    // [  1] (s =  54) custom-key: custom-value
    // [  2] (s =  53) cache-control: no-cache
    // [  3] (s =  57) :authority: www.example.com
    //       Table size: 164
}

void test_huffman_codes_routine(huffman_coding* obj, const char* sample, const char* expect, const char* text) {
    if (obj && sample && expect && text) {
        OPTION& option = cmdline->value();

        return_t ret = errorcode_t::success;
        basic_stream bs;
        binary_t bin;

        obj->encode(&bs, (byte_t*)sample, strlen(sample));
        if (option.verbose) {
            printf("%s\n", bs.c_str());
        }

        obj->encode(bin, (byte_t*)sample, strlen(sample));
        if (option.verbose) {
            dump_memory(bin, &bs);
            printf("%s\n", bs.c_str());
        }

        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "%s encode", text);

        bs.clear();
        ret = obj->decode(&bs, &bin[0], bin.size());
        if (option.verbose) {
            printf("%s\n", bs.c_str());
        }

        _test_case.assert(((errorcode_t::success == ret) && (bs == basic_stream(sample))), __FUNCTION__, "%s decode", text);
    }
}

void test_huffman_codes() {
    _test_case.begin("RFC 7541 Appendix B. Huffman Code");

    huffman_coding huff;
    huff.imports(_h2hcodes);  // RFC 7541 Appendix B. Huffman Code

    struct huffman_coding_testvector {
        const char* sample;
        const char* expect;
        const char* text;
    } vector[] = {
        {"www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff", "data#1"},  // RFC 7541 C.4.1
        {"no-cache", "a8eb 1064 9cbf", "data#2"},                        // RFC 7541 C.4.2
        {"custom-key", "25a8 49e9 5ba9 7d7f", "data#3"},                 // RFC 7541 C.4.3
        {"custom-value", "25a8 49e9 5bb8 e8b4 bf", "data#4"},            // RFC 7541 C.4.3

        {"still a man hears what he wants to hear and disregards the rest",
         "424d450a0d4a4752939476214f138d2a4e553c0ea4a1449d49ca3b141d5229219161661d922144ce552c2a13", "data#5"},
    };
    for (size_t i = 0; i < RTL_NUMBER_OF(vector); i++) {
        huffman_coding_testvector* item = vector + i;
        test_huffman_codes_routine(&huff, item->sample, item->expect, item->text);
    }
}

// C.4.  Request Examples with Huffman Coding
void test_rfc7541_c_4() {
    _test_case.begin("RFC 7541 HPACK C.4. Request Examples with Huffman Coding");
    OPTION& option = cmdline->value();

    hpack hp;

    binary_t bin;
    basic_stream bs;

    // C.4.1.  First Request
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "http");
    hp.encode_header(bin, ":path", "/");
    hp.encode_header(bin, ":authority", "www.example.com", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect1 =
        "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 "
        "ff                                      ";
    _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "RFC 7541 C.4.1 First Request");
    // C.4.2.  Second Request
    bin.clear();
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "http");
    hp.encode_header(bin, ":path", "/");
    hp.encode_header(bin, ":authority", "www.example.com", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "cache-control", "no-cache", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect2 = "8286 84be 5886 a8eb 1064 9cbf";
    _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "RFC 7541 C.4.2 Second Request");
    // C.4.3.  Third Request
    bin.clear();
    hp.encode_header(bin, ":method", "GET");
    hp.encode_header(bin, ":scheme", "https");
    hp.encode_header(bin, ":path", "/index.html");
    hp.encode_header(bin, ":authority", "www.example.com", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "custom-key", "custom-value", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect3 =
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 "
        "a849 e95b b8e8 b4bf                     ";
    _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "RFC 7541 C.4.3 Third Request");
}

// C.5.  Response Examples without Huffman Coding
void test_rfc7541_c_5() {
    _test_case.begin("RFC 7541 HPACK C.5. Response Examples without Huffman Coding");
    OPTION& option = cmdline->value();

    hpack hp;

    binary_t bin;
    basic_stream bs;

    // C.5.1.  First Response
    hp.encode_header(bin, ":status", "302", hpack_indexing);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:21 GMT", hpack_indexing);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect1 =
        "4803 3330 3258 0770 7269 7661 7465 611d "
        "4d6f 6e2c 2032 3120 4f63 7420 3230 3133 "
        "2032 303a 3133 3a32 3120 474d 546e 1768 "
        "7474 7073 3a2f 2f77 7777 2e65 7861 6d70 "
        "6c65 2e63 6f6d                          ";
    _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "RFC 7541 C.5.1 First Response");
    // C.5.2.  Second Response
    bin.clear();
    hp.encode_header(bin, ":status", "307", hpack_indexing);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:21 GMT", hpack_indexing);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect2 = "4803 3330 37c1 c0bf";
    _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "RFC 7541 C.5.2 Second Response");
    // C.5.3.  Third Response
    bin.clear();
    hp.encode_header(bin, ":status", "200", hpack_indexing);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:22 GMT", hpack_indexing);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing);
    hp.encode_header(bin, "content-encoding", "gzip", hpack_indexing);
    hp.encode_header(bin, "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", hpack_indexing);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect3 =
        "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 "
        "3230 3133 2032 303a 3133 3a32 3220 474d "
        "54c0 5a04 677a 6970 7738 666f 6f3d 4153 "
        "444a 4b48 514b 425a 584f 5157 454f 5049 "
        "5541 5851 5745 4f49 553b 206d 6178 2d61 "
        "6765 3d33 3630 303b 2076 6572 7369 6f6e "
        "3d31                                    ";
    _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "RFC 7541 C.5.3 Third Response");
}

// C.6.  Response Examples with Huffman Coding
void test_rfc7541_c_6() {
    _test_case.begin("RFC 7541 HPACK C.6. Response Examples with Huffman Coding");
    OPTION& option = cmdline->value();

    hpack hp;

    binary_t bin;
    basic_stream bs;

    // C.6.1.  First Response
    hp.encode_header(bin, ":status", "302", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:21 GMT", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect1 =
        "4882 6402 5885 aec3 771a 4b61 96d0 7abe "
        "9410 54d4 44a8 2005 9504 0b81 66e0 82a6 "
        "2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 "
        "e9ae 82ae 43d3                          ";
    _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "RFC 7541 C.6.1 First Response");
    // C.6.2.  Second Response
    bin.clear();
    hp.encode_header(bin, ":status", "307", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:21 GMT", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect2 = "4883 640e ffc1 c0bf";
    _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "RFC 7541 C.6.2 Second Response");
    // C.6.3.  Third Response
    bin.clear();
    hp.encode_header(bin, ":status", "200", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "cache-control", "private", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "date", "Mon, 21 Oct 2013 20:13:22 GMT", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "location", "https://www.example.com", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "content-encoding", "gzip", hpack_indexing | hpack_huffman);
    hp.encode_header(bin, "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", hpack_indexing | hpack_huffman);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    const char* expect3 =
        "88c1 6196 d07a be94 1054 d444 a820 0595 "
        "040b 8166 e084 a62d 1bff c05a 839b d9ab "
        "77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b "
        "3960 d5af 2708 7f36 72c1 ab27 0fb5 291f "
        "9587 3160 65c0 03ed 4ee5 b106 3d50 07   ";
    _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "RFC 7541 C.6.3 Third Response");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    cmdline.make_share(new cmdline_t<OPTION>);

    *cmdline << cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();

    cmdline->parse(argc, argv);
    OPTION& option = cmdline->value();

    // HPACK
    test_rfc7541_c_1();
    test_rfc7541_c_2();
    test_rfc7541_c_3();
    test_huffman_codes();
    test_rfc7541_c_4();
    test_rfc7541_c_5();
    test_rfc7541_c_6();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
