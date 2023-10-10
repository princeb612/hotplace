/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <math.h>
#include <stdio.h>

#include <deque>
#include <hotplace/sdk/sdk.hpp>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void encode_test(variant_t vt, binary_t& bin, std::string expect) {
    return_t ret = errorcode_t::success;
    cbor_encode enc;
    std::string hex;

    bin.clear();
    enc.encode(bin, vt);

    if (1) {
        test_case_notimecheck notimecheck(_test_case);

        base16_encode(bin, hex);

        if (0 == stricmp(hex.c_str(), expect.c_str())) {
            // match
        } else {
            ret = errorcode_t::mismatch;
        }

        basic_stream bs;

        dump_memory(bin, &bs);
        std::cout << "encoded " << hex.c_str() << std::endl;
        std::cout << bs.c_str() << std::endl;
    }

    _test_case.test(ret, __FUNCTION__, "encoded %s expect %s", hex.c_str(), expect.c_str());
}

void cbor_test(cbor_object* root, const char* expected) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == root || nullptr == expected) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;
        binary_t bin;
        basic_stream diagnostic;
        std::string concise;

        publisher.publish(root, &diagnostic);
        publisher.publish(root, &bin);

        {
            test_case_notimecheck notimecheck(_test_case);

            base16_encode(bin, concise);

            std::cout << "diagnostic " << diagnostic.c_str() << std::endl;
            std::cout << "concise    " << concise.c_str() << std::endl;

            if (stricmp(concise.c_str(), expected)) {
                ret = errorcode_t::mismatch;
            }
        }

        _test_case.test(ret, __FUNCTION__, "concise: %s diagnostic: %s", concise.c_str(), diagnostic.c_str());
    }
    __finally2 {
        // do nothing
    }
}

void test_cbor_int(int8 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_int8(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int(int16 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_int16(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int(int32 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_int32(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int(int64 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_int64(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int(int128 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_int128(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_fp16(uint16 value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_fp16(vt, value);
    encode_test(vt, bin, expect);

    fp16_t fp16;
    fp16.storage = value;

    cbor_data* cbor = new cbor_data(fp16);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_float(float value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_float(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_double(double value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_double(vt, value);
    encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_bool(bool value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_bool(vt, value);
    encode_test(vt, bin, expect);
}

void test_cbor_simple(uint8 value, const char* expect) {
    cbor_simple* cbor = new cbor_simple(value);

    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_tstr(const char* value, const char* expect) {
    binary_t bin;
    variant_t vt;

    variant_set_str(vt, value);
    encode_test(vt, bin, expect);
}

void test_cbor_bstr(binary_t const& value, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_tstr_tag(const char* value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_bstr_tag(binary_t const& value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int_tag(int8 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int_tag(int16 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int_tag(int32 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int_tag(int64 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_int_tag(int128 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_float_tag(float value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test_cbor_double_tag(double value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(true, tag);
    cbor_test(cbor, expect);
    cbor->release();
}

void test1() {
    _test_case.begin("test1.encode uint, nint, float (RFC 7049 Table 4)");

    binary_t bin;
    variant_t vt;

    test_cbor_int(0, "00");
    test_cbor_int(1, "01");
    test_cbor_int(10, "0a");
    test_cbor_int(23, "17");
    test_cbor_int(24, "1818");
    test_cbor_int(25, "1819");
    test_cbor_int(100, "1864");
    test_cbor_int(1000, "1903e8");
    test_cbor_int(1000000, "1a000f4240");

#if defined __SIZEOF_INT128__
    test_cbor_int(1000000000000, "1b000000e8d4a51000");
    test_cbor_int(atoi128("18446744073709551615"), "1bffffffffffffffff");
    test_cbor_int(atoi128("18446744073709551616"), "c249010000000000000000");

    test_cbor_int(atoi128("-18446744073709551616"), "3bffffffffffffffff");
    test_cbor_int(atoi128("-18446744073709551617"), "c349010000000000000000");
#endif

    test_cbor_int(-1, "20");
    test_cbor_int(-10, "29");
    test_cbor_int(-100, "3863");
    test_cbor_int(-1000, "3903e7");

    test_cbor_float(0.0, "f90000");      // fa00000000
    test_cbor_double(0.0, "f90000");     // fb0000000000000000
    test_cbor_float(-0.0, "f98000");     // fa80000000
    test_cbor_double(-0.0, "f98000");    // fb8000000000000000
    test_cbor_float(1.0, "f93c00");      // fa3f800000
    test_cbor_double(1.0, "f93c00");     // fb3ff0000000000000
    test_cbor_float(1.1, "fa3f8ccccd");  // dont convert
    test_cbor_double(1.1, "fb3ff199999999999a");
    test_cbor_float(1.5, "f93e00");            // fa3fc00000
    test_cbor_double(1.5, "f93e00");           // fb3ff8000000000000
    test_cbor_float(65504.0, "f97bff");        // fa477fe000
    test_cbor_double(65504.0, "f97bff");       // fb40effc0000000000
    test_cbor_float(100000.0, "fa47c35000");   // dont convert
    test_cbor_double(100000.0, "fa47c35000");  // fb40f86a0000000000

    test_cbor_float(3.4028234663852886e+38, "fa7f7fffff");  // dont convert
    test_cbor_double(1.0e+300, "fb7e37e43c8800759c");       // dont convert

    test_cbor_float(5.960464477539063e-8, "f90001");  // fa33800000
    test_cbor_float(0.00006103515625, "f90400");      // fa38800000
    test_cbor_float(-4.0, "f9c400");                  // fac0800000
    test_cbor_float(-4.1, "fac0833333");              // dont convert
    test_cbor_double(-4.1, "fbc010666666666666");     // dont convert

    test_cbor_fp16(0x7c00, "f97c00");
    test_cbor_fp16(0x7e00, "f97e00");
    test_cbor_fp16(0xfc00, "f9fc00");

    test_cbor_float(fp32_from_binary32(0x7f800000), "fa7f800000");  // positive infinity
    test_cbor_float(fp32_from_binary32(0x7fc00000), "fa7fc00000");  // NaN
    test_cbor_float(fp32_from_binary32(0xff800000), "faff800000");  // negative infinity

    test_cbor_double(fp64_from_binary64(0x7ff0000000000000), "fb7ff0000000000000");  // positive infinity
    test_cbor_double(fp64_from_binary64(0x7ff8000000000000), "fb7ff8000000000000");  // NaN
    test_cbor_double(fp64_from_binary64(0xfff0000000000000), "fbfff0000000000000");  // negative infinity

    test_cbor_bool(false, "f4");
    test_cbor_simple(cbor_simple_t::cbor_simple_false, "f4");
    test_cbor_bool(true, "f5");
    test_cbor_simple(cbor_simple_t::cbor_simple_true, "f5");
    test_cbor_simple(cbor_simple_t::cbor_simple_null, "f6");
    test_cbor_simple(cbor_simple_t::cbor_simple_undef, "f7");
    test_cbor_simple(16, "f0");
    test_cbor_simple(24, "f818");
    test_cbor_simple(255, "f8ff");

    test_cbor_tstr_tag("2013-03-21T20:04:00Z", cbor_tag_t::cbor_tag_std_datetime, "c074323031332d30332d32315432303a30343a30305a");
    test_cbor_int_tag(1363896240, cbor_tag_t::cbor_tag_epoch_datetime, "c11a514b67b0");
    test_cbor_double_tag(1363896240.5, cbor_tag_t::cbor_tag_epoch_datetime, "c1fb41d452d9ec200000");
    test_cbor_bstr_tag(base16_decode("01020304"), cbor_tag_t::cbor_tag_base16, "d74401020304");
    test_cbor_bstr_tag(base16_decode("6449455446"), cbor_tag_t::cbor_tag_encoded, "d818456449455446");
    test_cbor_tstr_tag("http://www.example.com", cbor_tag_t::cbor_tag_uri, "d82076687474703a2f2f7777772e6578616d706c652e636f6d");

    test_cbor_bstr(base16_decode(""), "40");
    test_cbor_bstr(base16_decode("01020304"), "4401020304");

    test_cbor_tstr("", "60");
    test_cbor_tstr("a", "6161");
    test_cbor_tstr("IETF", "6449455446");
    test_cbor_tstr("\"\\", "62225c");
    test_cbor_tstr("\u00fc", "62c3bc");
    test_cbor_tstr("\u6c34", "63e6b0b4");
}

void test2() {
    _test_case.begin("test2.encode array, map (RFC 7049 Table 4)");

    {
        // []
        cbor_array* root = new cbor_array();
        cbor_test(root, "80");
        root->release();
    }
    {
        // [1,2,3]
        cbor_array* root = new cbor_array();
        *root << new cbor_data(1) << new cbor_data(2) << new cbor_data(3);
        cbor_test(root, "83010203");
        root->release();
    }
    {
        // [1,[2,3],[4,5]]
        cbor_array* root = new cbor_array();
        cbor_array* sample1 = new cbor_array();
        *sample1 << new cbor_data(2) << new cbor_data(3);
        cbor_array* sample2 = new cbor_array();
        *sample2 << new cbor_data(4) << new cbor_data(5);
        *root << new cbor_data(1) << sample1 << sample2;
        cbor_test(root, "8301820203820405");
        root->release();
    }
    {
        // [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
        cbor_array* root = new cbor_array();
        for (int i = 1; i <= 25; i++) {
            *root << new cbor_data(i);
        }
        cbor_test(root, "98190102030405060708090a0b0c0d0e0f101112131415161718181819");
        root->release();
    }
    {
        // {}
        cbor_map* root = new cbor_map();
        cbor_test(root, "a0");
        root->release();
    }
    {
        // {1:2,3:4}
        cbor_map* root = new cbor_map();
        *root << new cbor_pair(1, new cbor_data(2)) << new cbor_pair(3, new cbor_data(4));
        cbor_test(root, "a201020304");
        root->release();
    }
    {
        // {"a":1,"b":[2,3]}
        cbor_map* root = new cbor_map();
        cbor_array* sample1 = new cbor_array();
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *root << new cbor_pair("a", new cbor_data(1)) << new cbor_pair("b", sample1);
        cbor_test(root, "a26161016162820203");
        root->release();
    }
    {
        // ["a",{"b":"c"}]
        cbor_array* root = new cbor_array();
        cbor_map* sample1 = new cbor_map();
        *sample1 << new cbor_pair("b", new cbor_data("c"));
        *root << new cbor_data("a") << sample1;
        cbor_test(root, "826161a161626163");
        root->release();
    }
    {
        // {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
        cbor_map* root = new cbor_map();
        *root << new cbor_pair("a", new cbor_data("A")) << new cbor_pair("b", new cbor_data("B")) << new cbor_pair("c", new cbor_data("C"))
              << new cbor_pair("d", new cbor_data("D")) << new cbor_pair("e", new cbor_data("E"));
        cbor_test(root, "a56161614161626142616361436164614461656145");
        root->release();
    }
    {
        // (_ h'0102', h'030405')
        // 0x5f42010243030405ff
        cbor_bstrings* root = new cbor_bstrings();
        *root << base16_decode("0102") << base16_decode("030405");
        cbor_test(root, "5f42010243030405ff");
        root->release();
    }
    {
        // (_ "strea", "ming")
        // 0x7f657374726561646d696e67ff
        cbor_tstrings* root = new cbor_tstrings();
        *root << "strea"
              << "ming";
        cbor_test(root, "7f657374726561646d696e67ff");
        root->release();
    }
    {
        // [_ ]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        cbor_test(root, "9fff");
        root->release();
    }
    {
        // [_ 1,[2,3],[_ 4,5]]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        cbor_array* sample1 = new cbor_array();
        cbor_array* sample2 = new cbor_array(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *sample2 << new cbor_data(4) << new cbor_data(5);
        *root << new cbor_data(1) << sample1 << sample2;
        cbor_test(root, "9f018202039f0405ffff");
        root->release();
    }
    {
        // [_ 1,[2,3],[4,5]]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        cbor_array* sample1 = new cbor_array();
        cbor_array* sample2 = new cbor_array();
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *sample2 << new cbor_data(4) << new cbor_data(5);
        *root << new cbor_data(1) << sample1 << sample2;
        cbor_test(root, "9f01820203820405ff");
        root->release();
    }
    {
        // [1,[2,3],[_ 4,5]]
        cbor_array* root = new cbor_array();
        cbor_array* sample1 = new cbor_array();
        cbor_array* sample2 = new cbor_array(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *sample2 << new cbor_data(4) << new cbor_data(5);
        *root << new cbor_data(1) << sample1 << sample2;
        cbor_test(root, "83018202039f0405ff");
        root->release();
    }
    {
        // [1,[_ 2,3],[4,5]]
        cbor_array* root = new cbor_array();
        cbor_array* sample1 = new cbor_array(cbor_flag_t::cbor_indef);
        cbor_array* sample2 = new cbor_array();
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *sample2 << new cbor_data(4) << new cbor_data(5);
        *root << new cbor_data(1) << sample1 << sample2;
        cbor_test(root, "83019f0203ff820405");
        root->release();
    }
    {
        // [_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        for (int i = 1; i <= 25; i++) {
            *root << new cbor_data(i);
        }
        cbor_test(root, "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff");
        root->release();
    }
    {
        // {_ "a":1,"b":[_ 2,3]}
        cbor_map* root = new cbor_map(cbor_flag_t::cbor_indef);
        cbor_array* sample1 = new cbor_array(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *root << new cbor_pair("a", new cbor_data(1)) << new cbor_pair("b", sample1);
        cbor_test(root, "bf61610161629f0203ffff");
        root->release();
    }
    {
        // ["a",{_ "b":"c"}]
        cbor_array* root = new cbor_array();
        cbor_map* sample1 = new cbor_map(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_pair("b", new cbor_data("c"));
        *root << new cbor_data("a") << sample1;
        cbor_test(root, "826161bf61626163ff");
        root->release();
    }
    {
        // {_ "Fun":true,"Amt":-2}
        cbor_map* root = new cbor_map(cbor_flag_t::cbor_indef);
        *root << new cbor_pair("Fun", new cbor_data(true)) << new cbor_pair("Amt", new cbor_data(-2));
        cbor_test(root, "bf6346756ef563416d7421ff");
        root->release();
    }
}

void test_parse(const char* input, const char* diagnostic, const char* diagnostic2 = nullptr) {
    cbor_reader reader;
    cbor_reader_context_t* handle = nullptr;
    ansi_string bs;
    binary_t bin;

    reader.open(&handle);
    reader.parse(handle, input);
    reader.publish(handle, &bs);
    reader.publish(handle, &bin);
    reader.close(handle);

    bool test = false;
    {
        test_case_notimecheck notimecheck(_test_case);

        printf("diagnostic %s\n", bs.c_str());
        std::string b16;
        base16_encode(bin, b16);
        printf("cbor       %s\n", b16.c_str());

        test = (0 == stricmp(input, b16.c_str()));
    }

    bool test2 = false;
    {
        test_case_notimecheck notimecheck(_test_case);

        ansi_string bs_diagnostic;
        ansi_string bs_diagnostic2;
        bs_diagnostic = diagnostic;

        bs.replace("_ ", "__");
        bs.replace(" ", "");
        bs.replace("__", "_ ");
        bs_diagnostic.replace("_ ", "__");
        bs_diagnostic.replace(" ", "");
        bs_diagnostic.replace("__", "_ ");

        if (diagnostic2) {
            bs_diagnostic2 = diagnostic2;
            test2 = ((bs == bs_diagnostic) || (bs == bs_diagnostic2));
        } else {
            test2 = (bs == bs_diagnostic);
        }
    }

    _test_case.assert(test && test2, __FUNCTION__, "decode input %s diagnostic %s", input, diagnostic ? diagnostic : "");
}

void test3() {
    _test_case.begin("test3.parse");
    // 0
    test_parse("00", "0");
    // 1
    test_parse("01", "1");
    // 10
    test_parse("0a", "10");
    // 23
    test_parse("17", "23");
    // 24
    test_parse("1818", "24");
    // 25
    test_parse("1819", "25");
    // 100
    test_parse("1864", "100");
    // 1000
    test_parse("1903e8", "1000");
    // 1000000
    test_parse("1a000f4240", "1000000");
    // 1000000000000
    test_parse("1b000000e8d4a51000", "1000000000000");
    // 18446744073709551615
    test_parse("1bffffffffffffffff", "18446744073709551615");
    // 18446744073709551616
    test_parse("c249010000000000000000", "18446744073709551616", "2(18446744073709551616)");
    // -18446744073709551615
    test_parse("3bfffffffffffffffe", "-18446744073709551615");
    // -18446744073709551616
    test_parse("3bffffffffffffffff", "-18446744073709551616");
    // -18446744073709551617
    test_parse("c349010000000000000000", "-18446744073709551617", "3(-18446744073709551617)");
    // -1
    test_parse("20", "-1");
    // -10
    test_parse("29", "-10");
    // -100
    test_parse("3863", "-100");
    // -1000
    test_parse("3903e7", "-1000");
    // false
    test_parse("f4", "false");
    // true
    test_parse("f5", "true");
    // null
    test_parse("f6", "null");
    // undefined
    test_parse("f7", "undefined");
    // []
    test_parse("80", "[]");
    // [1,2,3]
    test_parse("83010203", "[1,2,3]");
    // [1,[2,3],[4,5]]
    test_parse("8301820203820405", "[1,[2,3],[4,5]]");
    // [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
    test_parse("98190102030405060708090a0b0c0d0e0f101112131415161718181819", "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]");
    // {}
    test_parse("a0", "{}");
    // {1:2,3:4}
    test_parse("a201020304", "{1:2,3:4}");
    // {"a":1,"b":[2,3]}
    test_parse("a26161016162820203", "{\"a\":1,\"b\":[2,3]}");
    // ["a",{"b":"c"}]
    test_parse("826161a161626163", "[\"a\",{\"b\":\"c\"}]");
    // {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
    test_parse("a56161614161626142616361436164614461656145", "{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}");
    // (_ h'0102', h'030405')
    test_parse("5f42010243030405ff", "(_ h'0102', h'030405')");
    // (_ "strea", "ming")
    test_parse("7f657374726561646d696e67ff", "(_ \"strea\", \"ming\")");
    // [_ ]
    test_parse("9fff", "[_ ]");
    // [_ 1,[2,3],[_ 4,5]]
    test_parse("9f018202039f0405ffff", "[_ 1,[2,3],[_ 4,5]]");
    // [_ 1,[2,3],[4,5]]
    test_parse("9f01820203820405ff", "[_ 1,[2,3],[4,5]]");
    // [1,[2,3],[_ 4,5]]
    test_parse("83018202039f0405ff", "[1,[2,3],[_ 4,5]]");
    // [1,[_ 2,3],[4,5]]
    test_parse("83019f0203ff820405", "[1,[_ 2,3],[4,5]]");
    // [_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
    test_parse("9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff", "[_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]");
    // {_ "a":1,"b":[_ 2,3]}
    test_parse("bf61610161629f0203ffff", "{_ \"a\":1,\"b\":[_ 2,3]}");
    // ["a",{_ "b":"c"}]
    test_parse("826161bf61626163ff", "[\"a\",{_ \"b\":\"c\"}]");
    // {_ "Fun":true,"Amt":-2}
    test_parse("bf6346756ef563416d7421ff", "{_ \"Fun\":true,\"Amt\":-2}");
}

void whatsthis(int argc, char** argv) {
    if (argc > 1) {
        binary_t what = base16_decode(argv[1]);
        basic_stream diagnostic;
        cbor_reader_context_t* handle = nullptr;
        cbor_reader reader;
        reader.open(&handle);
        reader.parse(handle, what);
        reader.publish(handle, &diagnostic);
        reader.close(handle);

        std::cout << "what u want to know" << std::endl << "< " << argv[1] << std::endl << "> " << diagnostic.c_str() << std::endl;
    }
}

int main(int argc, char** argv) {
    test1();
    test2();
    test3();
    whatsthis(argc, argv);

    _test_case.report(5);
    return _test_case.result();
}
