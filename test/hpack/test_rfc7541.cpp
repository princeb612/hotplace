/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @remarks
 *      RFC 7541 HPACK: Header Compression for HTTP/2
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

t_shared_instance<hpack_encoder> encoder;

unsigned int count_evict_encoder = 0;
unsigned int count_evict_decoder = 0;

void debug_hpack_encoder(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_encoder++;
    }
};

void debug_hpack_decoder(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_decoder++;
    }
};

void do_test_rfc7541_c_1_routine(uint8 prefix, size_t i, const char* expect, const char* text) {
    const OPTION& option = _cmdline->value();

    binary_t bin;
    basic_stream bs;
    size_t value = 0;
    size_t pos = 0;

    encoder->encode_int(bin, 0x00, prefix, i);
    encoder->decode_int(&bin[0], pos, 0x00, prefix, value);

    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", bin, 16, 2);
        _logger->writeln("decode %zi", value);
    }

    uint8 test = 0;
    test = (expect && (i == value));
    if (test) {
        binary_t bin_expect = std::move(base16_decode_rfc(expect));
        test = (test && (bin == bin_expect));
    }
    _test_case.assert(test, __FUNCTION__, text);
}

void test_rfc7541_c_1() {
    _test_case.begin("RFC 7541 HPACK C.1. Integer Representation Examples");
    const OPTION& option = _cmdline->value();

    do_test_rfc7541_c_1_routine(5, 10, "0a", "RFC 7541 C.1.1. Example 1: Encoding 10 Using a 5-Bit Prefix");
    do_test_rfc7541_c_1_routine(5, 1337, "1f9a0a", "RFC 7541 C.1.2. Example 2: Encoding 1337 Using a 5-Bit Prefix");
    do_test_rfc7541_c_1_routine(8, 42, "2a", "RFC 7541 C.1.3. Example 3: Encoding 42 Starting at an Octet Boundary");
}

void test_rfc7541_c_2() {
    _test_case.begin("RFC 7541 HPACK C.2. Header Field Representation Examples");
    const OPTION& option = _cmdline->value();

    binary_t bin;
    basic_stream bs;

    size_t pos = 0;
    std::string name;
    std::string value;

    // C.2.1.  Literal Header Field with Indexing
    // "custom-key: custom-header"
    {
        hpack_dynamic_table hpack_dyntable;  // dynamic table
        bin.clear();
        encoder->encode_header(&hpack_dyntable, bin, "custom-key", "custom-header", hpack_indexing);
        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            _logger->hdump("encode", bin, 16, 2);
        }

        const char* text1 = "RFC 7541 C.2.1 Literal Header Field with Indexing";
        const char* expect1 =
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 "
            "746f 6d2d 6865 6164 6572                ";
        // 00000000 : 40 0A 63 75 73 74 6F 6D 2D 6B 65 79 0D 63 75 73 | @.custom-key.cus
        // 00000010 : 74 6F 6D 2D 68 65 61 64 65 72 -- -- -- -- -- -- | tom-header
        _test_case.assert(bin == base16_decode_rfc(expect1), __FUNCTION__, "%s #encode", text1);

        pos = 0;
        encoder->decode_header(&hpack_dyntable, &bin[0], bin.size(), pos, name, value);

        hpack_dyntable.dump("dynamic table", dump_hpack_session_routine);
        _test_case.assert(1 == hpack_dyntable.get_entries(), __FUNCTION__, "%s #entry size", text1);
        _test_case.assert(55 == hpack_dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text1);
        _test_case.assert(("custom-key" == name) && ("custom-header" == value), __FUNCTION__, "%s #decode", text1);
    }

    // C.2.2.  Literal Header Field without Indexing
    // :path: /sample/path
    {
        hpack_dynamic_table hpack_dyntable;  // dynamic table
        bin.clear();
        encoder->encode_header(&hpack_dyntable, bin, ":path", "/sample/path", hpack_wo_indexing);
        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            _logger->hdump("encode", bin, 16, 2);
        }

        const char* text2 = "RFC 7541 C.2.2 Literal Header Field without Indexing";
        const char* expect2 = "040c 2f73 616d 706c 652f 7061 7468";
        // 00000000 : 04 0C 2F 73 61 6D 70 6C 65 2F 70 61 74 68 -- -- | ../sample/path
        _test_case.assert(bin == base16_decode_rfc(expect2), __FUNCTION__, "%s #encode", text2);

        pos = 0;
        encoder->decode_header(&hpack_dyntable, &bin[0], bin.size(), pos, name, value);

        hpack_dyntable.dump("dynamic table", dump_hpack_session_routine);
        _test_case.assert(0 == hpack_dyntable.get_entries(), __FUNCTION__, "%s #entry size", text2);
        _test_case.assert(0 == hpack_dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text2);
        _test_case.assert((":path" == name) && ("/sample/path" == value), __FUNCTION__, "%s #decode", text2);
    }

    // C.2.3.  Literal Header Field Never Indexed
    // password: secret
    {
        hpack_dynamic_table hpack_dyntable;  // dynamic table
        bin.clear();
        encoder->encode_header(&hpack_dyntable, bin, "password", "secret", hpack_never_indexed);
        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            dump_memory(bin, &bs, 16, 2);
            _logger->hdump("encode", bin, 16, 2);
        }

        const char* text3 = "RFC 7541 C.2.3 Literal Header Field Never Indexed";
        const char* expect3 =
            "1008 7061 7373 776f 7264 0673 6563 7265 "
            "74                                      ";
        // 00000000 : 10 08 70 61 73 73 77 6F 72 64 06 73 65 63 72 65 | ..password.secre
        // 00000010 : 74 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | t
        _test_case.assert(bin == base16_decode_rfc(expect3), __FUNCTION__, "%s #encode", text3);

        hpack_dyntable.dump("dynamic table", dump_hpack_session_routine);
        _test_case.assert(0 == hpack_dyntable.get_entries(), __FUNCTION__, "%s #entry size", text3);
        _test_case.assert(0 == hpack_dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text3);

        pos = 0;
        encoder->decode_header(&hpack_dyntable, &bin[0], bin.size(), pos, name, value);

        _test_case.assert(("password" == name) && ("secret" == value), __FUNCTION__, "%s #decode", text3);
    }

    // C.2.4.  Indexed Header Field
    {
        hpack_dynamic_table hpack_dyntable;  // dynamic table
        bin.clear();
        encoder->encode_header(&hpack_dyntable, bin, ":method", "GET");
        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            _logger->hdump("encode", bin, 16, 2);
        }

        const char* text4 = "RFC 7541 C.2.4 Indexed Header Field";
        const char* expect4 = "82";
        // 00000000 : 82 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
        _test_case.assert(bin == base16_decode_rfc(expect4), __FUNCTION__, "%s #encode", text4);

        hpack_dyntable.dump("dynamic table", dump_hpack_session_routine);
        _test_case.assert(0 == hpack_dyntable.get_entries(), __FUNCTION__, "%s #entry size", text4);
        _test_case.assert(0 == hpack_dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text4);

        pos = 0;
        encoder->decode_header(&hpack_dyntable, &bin[0], bin.size(), pos, name, value);

        _test_case.assert((":method" == name) && ("GET" == value), __FUNCTION__, "%s #decode", text4);
    }
}

void do_decode(const binary_t& bin, hpack_dynamic_table* hpack_dyntable, hpack_dynamic_table* session2) {
    const OPTION& option = _cmdline->value();

    hpack_stream hp;
    std::string name;
    std::string value;
    size_t pos = 0;

    if (option.verbose) {
        _logger->writeln("> decode");
    }

    hp.set_session(hpack_dyntable);
    while (pos < bin.size()) {
        hp.decode_header(&bin[0], bin.size(), pos, name, value);
        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);
            _logger->writeln("  > %s: %s", name.c_str(), value.c_str());
        }
    }
    hp.commit();
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        hpack_dyntable->dump("dynamic table (receiver)", dump_hpack_session_routine);
        session2->dump("dynamic table (sender)", dump_hpack_session_routine);
        fflush(stdout);
    }
}

// C.3.  Request Examples without Huffman Coding
void test_rfc7541_c_3() {
    _test_case.begin("RFC 7541 HPACK C.3. Request Examples without Huffman Coding");
    const OPTION& option = _cmdline->value();

    hpack_stream hp;
    hpack_dynamic_table session_encoder;  // dynamic table
    hpack_dynamic_table session_decoder;  // dynamic table
    basic_stream bs;

    // C.3.1.  First Request
    // :method: GET
    // :scheme: http
    // :path: /
    // :authority: www.example.com
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .begin()
        .encode_header(":method", "GET")
        .encode_header(":scheme", "http")
        .encode_header(":path", "/")
        .encode_header(":authority", "www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump_memory(hp.get_binary(), &bs, 16, 2);
        _logger->writeln("encode\n%s", bs.c_str());
    }

    constexpr char text1[] = "RFC 7541 C.3.1 First Request";
    const char* expect1 =
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 "
        "2e63 6f6d                               ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect1), __FUNCTION__, "%s #encode", text1);

    // [  1] (s =  57) :authority: www.example.com
    //       Table size:  57

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text1);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(1 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(57 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);

    // C.3.2.  Second Request
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .begin()
        .encode_header(":method", "GET")
        .encode_header(":scheme", "http")
        .encode_header(":path", "/")
        .encode_header(":authority", "www.example.com")
        .encode_header("cache-control", "no-cache");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump_memory(hp.get_binary(), &bs, 16, 2);
        _logger->writeln("encode\n%s", bs.c_str());
    }

    constexpr char text2[] = "RFC 7541 C.3.2 Second Request";
    const char* expect2 = "8286 84be 5808 6e6f 2d63 6163 6865";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect2), __FUNCTION__, "%s #encode", text2);

    // [  1] (s =  53) cache-control: no-cache
    // [  2] (s =  57) :authority: www.example.com
    //       Table size: 110

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text2);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(2 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(110 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);

    // C.3.3.  Third Request
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .begin()
        .encode_header(":method", "GET")
        .encode_header(":scheme", "https")
        .encode_header(":path", "/index.html")
        .encode_header(":authority", "www.example.com")
        .encode_header("custom-key", "custom-value");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text3[] = "RFC 7541 C.3.3 Third Request";
    const char* expect3 =
        "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 "
        "0c63 7573 746f 6d2d 7661 6c75 65        ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect3), __FUNCTION__, "%s #encode", text3);

    // [  1] (s =  54) custom-key: custom-value
    // [  2] (s =  53) cache-control: no-cache
    // [  3] (s =  57) :authority: www.example.com
    //       Table size: 164

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text3);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(3 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(164 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
}

// C.4.  Request Examples with Huffman Coding
void test_rfc7541_c_4() {
    _test_case.begin("RFC 7541 HPACK C.4. Request Examples with Huffman Coding");
    const OPTION& option = _cmdline->value();

    hpack_stream hp;
    hpack_dynamic_table session_encoder;  // dynamic table
    hpack_dynamic_table session_decoder;  // dynamic table
    basic_stream bs;

    // C.4.1.  First Request
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .encode_header(":method", "GET")
        .encode_header(":scheme", "http")
        .encode_header(":path", "/")
        .encode_header(":authority", "www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text1[] = "RFC 7541 C.4.1 First Request";
    const char* expect1 =
        "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 "
        "ff                                      ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect1), __FUNCTION__, "%s #encode", text1);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text1);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(1 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(57 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);

    // C.4.2.  Second Request
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .begin()
        .encode_header(":method", "GET")
        .encode_header(":scheme", "http")
        .encode_header(":path", "/")
        .encode_header(":authority", "www.example.com")
        .encode_header("cache-control", "no-cache");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text2[] = "RFC 7541 C.4.2 Second Request";
    const char* expect2 = "8286 84be 5886 a8eb 1064 9cbf";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect2), __FUNCTION__, "%s #encode", text2);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text2);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(2 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text2);
    _test_case.assert(110 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);

    // C.4.3.  Third Request
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .begin()
        .encode_header(":method", "GET")
        .encode_header(":scheme", "https")
        .encode_header(":path", "/index.html")
        .encode_header(":authority", "www.example.com")
        .encode_header("custom-key", "custom-value");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text3[] = "RFC 7541 C.4.3 Third Request";
    const char* expect3 =
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 "
        "a849 e95b b8e8 b4bf                     ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect3), __FUNCTION__, "%s #encode", text3);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text3);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(3 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text3);
    _test_case.assert(164 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
}

// C.5.  Response Examples without Huffman Coding
void test_rfc7541_c_5() {
    _test_case.begin("RFC 7541 HPACK C.5. Response Examples without Huffman Coding");
    const OPTION& option = _cmdline->value();

    hpack_stream hp;
    hpack_dynamic_table session_encoder;  // dynamic table
    hpack_dynamic_table session_decoder;  // dynamic table
    basic_stream bs;

    // C.5.  Response Examples without Huffman Coding
    // The HTTP/2 setting parameter SETTINGS_HEADER_TABLE_SIZE is set to the value of 256 octets
    session_encoder.set_capacity(256);
    session_decoder.set_capacity(256);
    count_evict_encoder = 0;
    count_evict_decoder = 0;
    session_encoder.set_debug_hook(debug_hpack_encoder);
    session_decoder.set_debug_hook(debug_hpack_decoder);

    // C.5.1.  First Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .encode_header(":status", "302")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:21 GMT")
        .encode_header("location", "https://www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text1[] = "RFC 7541 C.5.1 First Response";
    const char* expect1 =
        "4803 3330 3258 0770 7269 7661 7465 611d "
        "4d6f 6e2c 2032 3120 4f63 7420 3230 3133 "
        "2032 303a 3133 3a32 3120 474d 546e 1768 "
        "7474 7073 3a2f 2f77 7777 2e65 7861 6d70 "
        "6c65 2e63 6f6d                          ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect1), __FUNCTION__, "%s #encode", text1);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text1);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(222 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);

    // C.5.2.  Second Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .begin()
        .encode_header(":status", "307")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:21 GMT")
        .encode_header("location", "https://www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text2[] = "RFC 7541 C.5.2 Second Response";
    const char* expect2 = "4803 3330 37c1 c0bf";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect2), __FUNCTION__, "%s #encode", text2);
    _test_case.assert(1 == count_evict_encoder, __FUNCTION__, "%s #check eviction %u", text2, count_evict_encoder);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text2);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text2);
    _test_case.assert(222 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);
    _test_case.assert(1 == count_evict_decoder, __FUNCTION__, "%s #check eviction %u", text2, count_evict_decoder);

    // C.5.3.  Third Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing)
        .begin()
        .encode_header(":status", "200")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:22 GMT")
        .encode_header("location", "https://www.example.com")
        .encode_header("content-encoding", "gzip")
        .encode_header("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text3[] = "RFC 7541 C.5.3 Third Response";
    const char* expect3 =
        "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 "
        "3230 3133 2032 303a 3133 3a32 3220 474d "
        "54c0 5a04 677a 6970 7738 666f 6f3d 4153 "
        "444a 4b48 514b 425a 584f 5157 454f 5049 "
        "5541 5851 5745 4f49 553b 206d 6178 2d61 "
        "6765 3d33 3630 303b 2076 6572 7369 6f6e "
        "3d31                                    ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect3), __FUNCTION__, "%s #encode", text3);
    _test_case.assert(5 == count_evict_encoder, __FUNCTION__, "%s #check eviction %u", text3, count_evict_encoder);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text3);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(3 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text3);
    _test_case.assert(215 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
    _test_case.assert(5 == count_evict_decoder, __FUNCTION__, "%s #check eviction %u", text3, count_evict_decoder);
}

// C.6.  Response Examples with Huffman Coding
void test_rfc7541_c_6() {
    _test_case.begin("RFC 7541 HPACK C.6. Response Examples with Huffman Coding");
    const OPTION& option = _cmdline->value();

    hpack_stream hp;
    hpack_dynamic_table session_encoder;  // dynamic table
    hpack_dynamic_table session_decoder;  // dynamic table
    basic_stream bs;

    // C.6.  Response Examples with Huffman Coding
    // The HTTP/2 setting parameter SETTINGS_HEADER_TABLE_SIZE is set to the value of 256 octets
    session_encoder.set_capacity(256);
    session_decoder.set_capacity(256);
    count_evict_encoder = 0;
    count_evict_decoder = 0;
    session_encoder.set_debug_hook(debug_hpack_encoder);
    session_decoder.set_debug_hook(debug_hpack_decoder);

    // C.6.1.  First Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .begin()
        .encode_header(":status", "302")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:21 GMT")
        .encode_header("location", "https://www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text1[] = "RFC 7541 C.6.1 First Response";
    const char* expect1 =
        "4882 6402 5885 aec3 771a 4b61 96d0 7abe "
        "9410 54d4 44a8 2005 9504 0b81 66e0 82a6 "
        "2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 "
        "e9ae 82ae 43d3                          ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect1), __FUNCTION__, "%s #encode", text1);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text1);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text1);
    _test_case.assert(222 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);

    // C.6.2.  Second Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .begin()
        .encode_header(":status", "307")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:21 GMT")
        .encode_header("location", "https://www.example.com");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text2[] = "RFC 7541 C.6.2 Second Response";
    const char* expect2 = "4883 640e ffc1 c0bf";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect2), __FUNCTION__, "%s #encode", text2);
    _test_case.assert(1 == count_evict_encoder, __FUNCTION__, "%s #check eviction %u", text2, count_evict_encoder);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text2);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text2);
    _test_case.assert(222 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);
    _test_case.assert(1 == count_evict_decoder, __FUNCTION__, "%s #check eviction %u", text2, count_evict_decoder);

    // C.6.3.  Third Response
    hp.set_session(&session_encoder)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .begin()
        .encode_header(":status", "200")
        .encode_header("cache-control", "private")
        .encode_header("date", "Mon, 21 Oct 2013 20:13:22 GMT")
        .encode_header("location", "https://www.example.com")
        .encode_header("content-encoding", "gzip")
        .encode_header("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        _logger->hdump("encode", hp.get_binary(), 16, 2);
    }

    constexpr char text3[] = "RFC 7541 C.6.3 Third Response";
    const char* expect3 =
        "88c1 6196 d07a be94 1054 d444 a820 0595 "
        "040b 8166 e084 a62d 1bff c05a 839b d9ab "
        "77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b "
        "3960 d5af 2708 7f36 72c1 ab27 0fb5 291f "
        "9587 3160 65c0 03ed 4ee5 b106 3d50 07   ";
    _test_case.assert(hp.get_binary() == base16_decode_rfc(expect3), __FUNCTION__, "%s #encode", text3);
    _test_case.assert(5 == count_evict_encoder, __FUNCTION__, "%s #check eviction %u", text3, count_evict_encoder);

    do_decode(hp.get_binary(), &session_decoder, &session_encoder);

    _test_case.assert(session_encoder == session_decoder, __FUNCTION__, "%s #decode", text3);
    session_decoder.dump("dynamic table", dump_hpack_session_routine);
    _test_case.assert(3 == session_decoder.get_entries(), __FUNCTION__, "%s #entry size", text3);
    _test_case.assert(215 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
    _test_case.assert(5 == count_evict_decoder, __FUNCTION__, "%s #check eviction %u", text3, count_evict_decoder);
}
