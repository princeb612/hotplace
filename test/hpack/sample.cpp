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
    std::string url;
    int mode;
    int connect;
    int verbose;

    _OPTION() : url("https://localhost:9000/"), mode(0), connect(0), verbose(0) {}
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

// RFC 7541 HPACK: Header Compression for HTTP/2
// C.1.  Integer Representation Examples
void hpack_encode_int(binary_t& target, uint8 prefix, int32 value, uint8 pattern = 0) {
    // RFC 7541 5.1.  Integer Representation
    if ((1 <= prefix) && (prefix <= 8)) {
        uint8 n = (1 << prefix) - 1;
        uint8 i = 0;
        if (value < n) {
            target.insert(target.end(), value | pattern);
        } else {
            target.insert(target.end(), n | pattern);
            value -= n;
            while (value >= 128) {
                i = (value % 128) + 128;
                target.insert(target.end(), i);
                value /= 128;
            }
            target.insert(target.end(), value);
        }
    }
}

void hpack_decode_int(byte_t* p, size_t& pos, uint8 prefix, uint32& value) {
    // RFC 7541 5.1.  Integer Representation
    value = 0;
    if (p && (1 <= prefix) && (prefix <= 8)) {
        uint8 n = (1 << prefix) - 1;
        uint8 b = p[pos++];
        if (b < n) {
            value = b;
        } else {
            uint32 m = 0;
            uint32 i = b;
            do {
                b = p[pos++];
                i += (b & 0x7f) << m;
                m += 7;
            } while (0x80 == (b & 0x80));
            value = i;
        }
    }
}

// RFC 7541 Figure 4: String Literal Representation
void hpack_encode_string(binary_t& target, std::string value) {
    // H(1), Len(7)
    hpack_encode_int(target, 7, value.size());
    target.insert(target.end(), value.begin(), value.end());
}

// RFC 7541 Figure 5: Indexed Header Field
void hpack_encode_index(binary_t& target, uint8 index) { hpack_encode_int(target, 7, index, 0x80); }

enum hpack_flag_t {
    hpack_indexed = 1,
    hpack_wo_index = 2,
    hpack_never_indexed = 3,
};

void hpack_encode_indexed_name(binary_t& target, hpack_flag_t flag, uint8 index, std::string const& value) {
    __try2 {
        if (hpack_indexed == flag) {
            // RFC 7541 Figure 6: Literal Header Field with Incremental Indexing -- Indexed Name
            hpack_encode_int(target, 6, index, 0x40);
        } else if (hpack_wo_index == flag) {
            // RFC 7541 Figure 8: Literal Header Field without Indexing -- Indexed Name
            hpack_encode_int(target, 4, index);
        } else if (hpack_never_indexed == flag) {
            // RFC 7541 Figure 10: Literal Header Field Never Indexed -- Indexed Name
            hpack_encode_int(target, 4, index, 0x10);
        } else {
            __leave2;
        }
        hpack_encode_int(target, 7, value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    __finally2 {
        // do nothing
    }
}

void hpack_encode_name_value(binary_t& target, hpack_flag_t flag, uint8 index, std::string const& name, std::string const& value) {
    __try2 {
        if (hpack_indexed == flag) {
            // RFC 7541 Figure 7: Literal Header Field with Incremental Indexing -- New Name
            target.insert(target.end(), 0x40);
        } else if (hpack_wo_index == flag) {
            // RFC 7541 Figure 9: Literal Header Field without Indexing -- New Name
            target.insert(target.end(), 0);
        } else if (hpack_never_indexed == flag) {
            // RFC 7541 Figure 11: Literal Header Field Never Indexed -- New Name
            target.insert(target.end(), 0x10);
        } else {
            __leave2;
        }
        hpack_encode_int(target, 7, name.size());
        target.insert(target.end(), name.begin(), name.end());
        hpack_encode_int(target, 7, value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    __finally2 {
        // do nothing
    }
}

// RFC 7541 Figure 12: Maximum Dynamic Table Size Change
void hpack_encode_dyntablesize(binary_t& target, uint8 maxsize) { hpack_encode_int(target, 5, maxsize, 0x20); }

typedef struct _http2_table_t {
    std::string value;
    uint32 index;
    _http2_table_t(uint32 i) : index(i) {}
    _http2_table_t(std::string const& v, uint32 i) : value(v), index(i) {}
} http2_table_t;
typedef std::multimap<std::string, http2_table_t> table_t;

table_t static_table;
table_t dynamic_table;
uint32 dynamic_table_entry_no = 62;

enum {
    not_matched = 1,
    key_matched = 2,
    all_matched = 3,
};

int find_table(table_t& table, std::string const& name, std::string const& value, uint32& index) {
    int state = not_matched;
    index = 0;

    table_t::iterator iter;
    table_t::iterator liter;
    table_t::iterator uiter;

    liter = table.lower_bound(name);
    uiter = table.upper_bound(name);

    for (iter = liter; iter != uiter; iter++) {
        if (iter == liter) {
            index = iter->second.index;  // :path: /sample/path
            if (iter->second.value.empty()) {
                state = key_matched;
                break;
            }
        }
        if (value == iter->second.value) {
            index = iter->second.index;
            state = all_matched;
            break;
        }
    }
    return state;
}

void hpack_encode_header(binary_t& target, std::string const& name, std::string const& value, bool doindex = true) {
    // RFC 7541 Appendix A.  Static Table Definition
    if (static_table.empty()) {
        static_table.insert(std::make_pair(":authority", http2_table_t(1)));
        static_table.insert(std::make_pair(":method", http2_table_t("GET", 2)));
        static_table.insert(std::make_pair(":method", http2_table_t("POST", 3)));
        static_table.insert(std::make_pair(":path", http2_table_t("/", 4)));
        static_table.insert(std::make_pair(":path", http2_table_t("/index.html", 5)));
        static_table.insert(std::make_pair(":scheme", http2_table_t("http", 6)));
        static_table.insert(std::make_pair(":scheme", http2_table_t("https", 7)));
        // ...
        static_table.insert(std::make_pair("cache-control", http2_table_t(24)));
        // ...
        static_table.insert(std::make_pair("www-authenticate", http2_table_t(61)));
    }

    enum {
        not_matched = 1,
        key_matched = 2,
        all_matched = 3,
    };
    int state = not_matched;

    uint32 index = 0;
    state = find_table(dynamic_table, name, value, index);
    if (not_matched == state) {
        state = find_table(static_table, name, value, index);
    }

    switch (state) {
        case all_matched:
            hpack_encode_index(target, index);
            break;
        case key_matched:
            hpack_encode_indexed_name(target, hpack_indexed, index, value);
            dynamic_table.insert(std::make_pair(name, http2_table_t(value, dynamic_table_entry_no++)));
            break;
        default:
            if (doindex) {
                hpack_encode_name_value(target, hpack_indexed, dynamic_table_entry_no++, name, value);
                dynamic_table.insert(std::make_pair(name, http2_table_t(value, dynamic_table_entry_no++)));
            } else {
                hpack_encode_indexed_name(target, hpack_wo_index, index, value);
            }
            break;
    }
}

void test_rfc7541_c_1_routine(uint8 prefix, int32 i, const char* expect, const char* text) {
    OPTION& option = cmdline->value();

    binary_t bin;
    basic_stream bs;
    uint32 value = 0;
    size_t pos = 0;

    hpack_encode_int(bin, prefix, i);
    hpack_decode_int(&bin[0], pos, prefix, value);

    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
        printf("decode %u\n", value);
    }

    bool test = false;
    test = (expect && (i == value));
    if (test) {
        binary_t bin_expect = base16_decode(expect);
        test = (test && (bin == bin_expect));
    }
    _test_case.assert(test, __FUNCTION__, text);
}

void test_rfc7541_c_1() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    test_rfc7541_c_1_routine(5, 10, "0a", "RFC 7541 C.1.1.  Example 1: Encoding 10 Using a 5-Bit Prefix");
    test_rfc7541_c_1_routine(5, 1337, "1f9a0a", "RFC 7541 C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix");
    test_rfc7541_c_1_routine(8, 42, "2a", "RFC 7541 C.1.3.  Example 3: Encoding 42 Starting at an Octet Boundary");
}

void test_rfc7541_c_2() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    binary_t bin;
    basic_stream bs;
    // C.2.1.  Literal Header Field with Indexing
    // "custom-key: custom-header"
    bin.clear();
    hpack_encode_name_value(bin, hpack_indexed, 0, "custom-key", "custom-header");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("400A637573746F6D2D6B65790D637573746F6D2D686561646572"), __FUNCTION__, "RFC 7541 C.2.1");

    // C.2.2.  Literal Header Field without Indexing
    // :path: /sample/path
    bin.clear();
    hpack_encode_header(bin, ":path", "/sample/path", false);
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("040C2F73616D706C652F70617468"), __FUNCTION__, "RFC 7541 C.2.2");
    // C.2.3.  Literal Header Field Never Indexed
    // password: secret
    bin.clear();
    hpack_encode_name_value(bin, hpack_never_indexed, 0, "password", "secret");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("100870617373776f726406736563726574"), __FUNCTION__, "RFC 7541 C.2.3");
    // C.2.4.  Indexed Header Field
    bin.clear();
    hpack_encode_header(bin, ":method", "GET");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("82"), __FUNCTION__, "RFC 7541 C.2.4");
}

// C.3.  Request Examples without Huffman Coding
void test_rfc7541_c_3() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    // reset !
    dynamic_table.clear();
    dynamic_table_entry_no = 62;

    binary_t bin;
    basic_stream bs;
    // C.3.1.  First Request
    // :method: GET
    // :scheme: http
    // :path: /
    // :authority: www.example.com
    hpack_encode_header(bin, ":method", "GET");
    hpack_encode_header(bin, ":scheme", "http");
    hpack_encode_header(bin, ":path", "/");
    hpack_encode_header(bin, ":authority", "www.example.com");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("828684410f7777772e6578616d706c652e636f6d"), __FUNCTION__, "RFC 7541 C.3.1");

    // [  1] (s =  57) :authority: www.example.com
    //       Table size:  57

    // C.3.2.  Second Request

    bin.clear();
    hpack_encode_header(bin, ":method", "GET");
    hpack_encode_header(bin, ":scheme", "http");
    hpack_encode_header(bin, ":path", "/");
    hpack_encode_header(bin, ":authority", "www.example.com");
    hpack_encode_header(bin, "cache-control", "no-cache");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("828684be58086e6f2d6361636865"), __FUNCTION__, "RFC 7541 C.3.2");

    // [  1] (s =  53) cache-control: no-cache
    // [  2] (s =  57) :authority: www.example.com
    //       Table size: 110

    // C.3.3.  Third Request

    dynamic_table.clear();
    // dynamic_table.insert(std::make_pair("cache-control", http2_table_t("no-cache", 62)));
    dynamic_table.insert(std::make_pair(":authority", http2_table_t("www.example.com", 63)));

    bin.clear();
    hpack_encode_header(bin, ":method", "GET");
    hpack_encode_header(bin, ":scheme", "https");
    hpack_encode_header(bin, ":path", "/index.html");
    hpack_encode_header(bin, ":authority", "www.example.com");
    hpack_encode_header(bin, "custom-key", "custom-value");
    if (option.verbose) {
        dump_memory(bin, &bs, 16, 2);
        printf("encode\n%s\n", bs.c_str());
    }
    _test_case.assert(bin == base16_decode("828785BF400A637573746F6D2D6B65790C637573746F6D2D76616C7565"), __FUNCTION__, "RFC 7541 C.3.3");

    // [  1] (s =  54) custom-key: custom-value
    // [  2] (s =  53) cache-control: no-cache
    // [  3] (s =  57) :authority: www.example.com
    //       Table size: 164
}

// C.4.  Request Examples with Huffman Coding
void test_rfc7541_c_4() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    binary_t bin;
    // C.4.1.  First Request
    // C.4.2.  Second Request
    // C.4.3.  Third Request
}

// C.5.  Response Examples without Huffman Coding
void test_rfc7541_c_5() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    binary_t bin;
    // C.5.1.  First Response
    // C.5.2.  Second Response
    // C.5.3.  Third Response
}

// C.6.  Response Examples with Huffman Coding
void test_rfc7541_c_6() {
    _test_case.begin("RFC 7541 HPACK");
    OPTION& option = cmdline->value();

    binary_t bin;
    // C.6.1.  First Response
    // C.6.2.  Second Response
    // C.6.3.  Third Response
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

    *cmdline << cmdarg_t<OPTION>("-c", "connect", [&](OPTION& o, char* param) -> void { o.connect = 1; }).optional()
             << cmdarg_t<OPTION>("-p", "read stream using http_protocol", [&](OPTION& o, char* param) -> void { o.mode = 1; }).optional()
             << cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
             << cmdarg_t<OPTION>("-u", "url (default https://localhost:9000/)", [&](OPTION& o, char* param) -> void { o.url = param; }).preced().optional();

    cmdline->parse(argc, argv);
    OPTION& option = cmdline->value();

    // HPACK
    test_rfc7541_c_1();
    test_rfc7541_c_2();
    test_rfc7541_c_3();
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
