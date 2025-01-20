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

#include "sample.hpp"

void do_encode_test(variant& vt, binary_t& bin, std::string expect) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    cbor_encode enc;
    std::string hex;

    bin.clear();
    enc.encode(bin, vt.content());

    if (1) {
        test_case_notimecheck notimecheck(_test_case);

        base16_encode(bin, hex);

        if (hex == expect) {
            // match
        } else {
            ret = errorcode_t::mismatch;
        }

        if (option.verbose) {
            basic_stream bs;
            dump_memory(bin, &bs);
            _logger->writeln("encoded %s\n%s", hex.c_str(), bs.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "encoded %s expect %s", hex.c_str(), expect.c_str());
}

void do_cbor_test(cbor_object* root, const char* expected) {
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

            _logger->writeln("diagnostic %s\nconcise    %s", diagnostic.c_str(), concise.c_str());

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

void do_test_cbor_int(int8 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_int8(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int(int16 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_int16(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int(int32 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_int32(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int(int64 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_int64(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int(int128 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_int128(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_fp16(uint16 value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_fp16(value);
    do_encode_test(vt, bin, expect);

    fp16_t fp16;
    fp16.storage = value;

    cbor_data* cbor = new cbor_data(fp16);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_float(float value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_float(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_double(double value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_double(value);
    do_encode_test(vt, bin, expect);

    cbor_data* cbor = new cbor_data(value);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_bool(bool value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_bool(value);
    do_encode_test(vt, bin, expect);
}

void do_test_cbor_simple(uint8 value, const char* expect) {
    cbor_simple* cbor = new cbor_simple(value);

    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_tstr(const char* value, const char* expect) {
    binary_t bin;
    variant vt;

    vt.set_str(value);
    do_encode_test(vt, bin, expect);
}

void do_test_cbor_bstr(const binary_t& value, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_tstr_tag(const char* value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_bstr_tag(const binary_t& value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int_tag(int8 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int_tag(int16 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int_tag(int32 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int_tag(int64 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_int_tag(int128 value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_float_tag(float value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void do_test_cbor_double_tag(double value, cbor_tag_t tag, const char* expect) {
    cbor_data* cbor = new cbor_data(value);

    cbor->tag(tag);
    do_cbor_test(cbor, expect);
    cbor->release();
}

void test_rfc7049_table4_1() {
    _test_case.begin("test1.encode uint, nint, float (RFC 7049 Table 4)");

    binary_t bin;
    variant_t vt;

    do_test_cbor_int(0, "00");
    do_test_cbor_int(1, "01");
    do_test_cbor_int(10, "0a");
    do_test_cbor_int(23, "17");
    do_test_cbor_int(24, "1818");
    do_test_cbor_int(25, "1819");
    do_test_cbor_int(100, "1864");
    do_test_cbor_int(1000, "1903e8");
    do_test_cbor_int(1000000, "1a000f4240");

#if defined __SIZEOF_INT128__
    do_test_cbor_int(1000000000000, "1b000000e8d4a51000");
    do_test_cbor_int(atoi128("18446744073709551615"), "1bffffffffffffffff");
    do_test_cbor_int(atoi128("18446744073709551616"), "c249010000000000000000");

    do_test_cbor_int(atoi128("-18446744073709551616"), "3bffffffffffffffff");
    do_test_cbor_int(atoi128("-18446744073709551617"), "c349010000000000000000");
#endif

    do_test_cbor_int(-1, "20");
    do_test_cbor_int(-10, "29");
    do_test_cbor_int(-100, "3863");
    do_test_cbor_int(-1000, "3903e7");

    do_test_cbor_float(0.0, "f90000");      // fa00000000
    do_test_cbor_double(0.0, "f90000");     // fb0000000000000000
    do_test_cbor_float(-0.0, "f98000");     // fa80000000
    do_test_cbor_double(-0.0, "f98000");    // fb8000000000000000
    do_test_cbor_float(1.0, "f93c00");      // fa3f800000
    do_test_cbor_double(1.0, "f93c00");     // fb3ff0000000000000
    do_test_cbor_float(1.1, "fa3f8ccccd");  // dont convert
    do_test_cbor_double(1.1, "fb3ff199999999999a");
    do_test_cbor_float(1.5, "f93e00");            // fa3fc00000
    do_test_cbor_double(1.5, "f93e00");           // fb3ff8000000000000
    do_test_cbor_float(65504.0, "f97bff");        // fa477fe000
    do_test_cbor_double(65504.0, "f97bff");       // fb40effc0000000000
    do_test_cbor_float(100000.0, "fa47c35000");   // dont convert
    do_test_cbor_double(100000.0, "fa47c35000");  // fb40f86a0000000000

    do_test_cbor_float(3.4028234663852886e+38, "fa7f7fffff");  // dont convert
    do_test_cbor_double(1.0e+300, "fb7e37e43c8800759c");       // dont convert

    do_test_cbor_float(5.960464477539063e-8, "f90001");  // fa33800000
    do_test_cbor_float(0.00006103515625, "f90400");      // fa38800000
    do_test_cbor_float(-4.0, "f9c400");                  // fac0800000
    do_test_cbor_float(-4.1, "fac0833333");              // dont convert
    do_test_cbor_double(-4.1, "fbc010666666666666");     // dont convert

    do_test_cbor_fp16(0x7c00, "f97c00");
    do_test_cbor_fp16(0x7e00, "f97e00");
    do_test_cbor_fp16(0xfc00, "f9fc00");

    do_test_cbor_float(fp32_from_binary32(0x7f800000), "fa7f800000");  // positive infinity
    do_test_cbor_float(fp32_from_binary32(0x7fc00000), "fa7fc00000");  // NaN
    do_test_cbor_float(fp32_from_binary32(0xff800000), "faff800000");  // negative infinity

    do_test_cbor_double(fp64_from_binary64(0x7ff0000000000000), "fb7ff0000000000000");  // positive infinity
    do_test_cbor_double(fp64_from_binary64(0x7ff8000000000000), "fb7ff8000000000000");  // NaN
    do_test_cbor_double(fp64_from_binary64(0xfff0000000000000), "fbfff0000000000000");  // negative infinity

    do_test_cbor_bool(false, "f4");
    do_test_cbor_simple(cbor_simple_t::cbor_simple_false, "f4");
    do_test_cbor_bool(true, "f5");
    do_test_cbor_simple(cbor_simple_t::cbor_simple_true, "f5");
    do_test_cbor_simple(cbor_simple_t::cbor_simple_null, "f6");
    do_test_cbor_simple(cbor_simple_t::cbor_simple_undef, "f7");
    do_test_cbor_simple(16, "f0");
    do_test_cbor_simple(24, "f818");
    do_test_cbor_simple(255, "f8ff");

    do_test_cbor_tstr_tag("2013-03-21T20:04:00Z", cbor_tag_t::cbor_tag_std_datetime, "c074323031332d30332d32315432303a30343a30305a");
    do_test_cbor_int_tag(1363896240, cbor_tag_t::cbor_tag_epoch_datetime, "c11a514b67b0");
    do_test_cbor_double_tag(1363896240.5, cbor_tag_t::cbor_tag_epoch_datetime, "c1fb41d452d9ec200000");
    do_test_cbor_bstr_tag(base16_decode("01020304"), cbor_tag_t::cbor_tag_base16, "d74401020304");
    do_test_cbor_bstr_tag(base16_decode("6449455446"), cbor_tag_t::cbor_tag_encoded, "d818456449455446");
    do_test_cbor_tstr_tag("http://www.example.com", cbor_tag_t::cbor_tag_uri, "d82076687474703a2f2f7777772e6578616d706c652e636f6d");

    do_test_cbor_bstr(base16_decode(""), "40");
    do_test_cbor_bstr(base16_decode("01020304"), "4401020304");

    do_test_cbor_tstr("", "60");
    do_test_cbor_tstr("a", "6161");
    do_test_cbor_tstr("IETF", "6449455446");
    do_test_cbor_tstr(R"("\)", "62225c");
    do_test_cbor_tstr("\u00fc", "62c3bc");
    do_test_cbor_tstr("\u6c34", "63e6b0b4");
}

void test_rfc7049_table4_2() {
    _test_case.begin("test2.encode array, map (RFC 7049 Table 4)");

    {
        // []
        cbor_array* root = new cbor_array();
        do_cbor_test(root, "80");
        root->release();
    }
    {
        // [1,2,3]
        cbor_array* root = new cbor_array();
        *root << new cbor_data(1) << new cbor_data(2) << new cbor_data(3);
        do_cbor_test(root, "83010203");
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
        do_cbor_test(root, "8301820203820405");
        root->release();
    }
    {
        // [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
        cbor_array* root = new cbor_array();
        for (int i = 1; i <= 25; i++) {
            *root << new cbor_data(i);
        }
        do_cbor_test(root, "98190102030405060708090a0b0c0d0e0f101112131415161718181819");
        root->release();
    }
    {
        // {}
        cbor_map* root = new cbor_map();
        do_cbor_test(root, "a0");
        root->release();
    }
    {
        // {1:2,3:4}
        cbor_map* root = new cbor_map();
        *root << new cbor_pair(1, new cbor_data(2)) << new cbor_pair(3, new cbor_data(4));
        do_cbor_test(root, "a201020304");
        root->release();
    }
    {
        // {"a":1,"b":[2,3]}
        cbor_map* root = new cbor_map();
        cbor_array* sample1 = new cbor_array();
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *root << new cbor_pair("a", new cbor_data(1)) << new cbor_pair("b", sample1);
        do_cbor_test(root, "a26161016162820203");
        root->release();
    }
    {
        // ["a",{"b":"c"}]
        cbor_array* root = new cbor_array();
        cbor_map* sample1 = new cbor_map();
        *sample1 << new cbor_pair("b", new cbor_data("c"));
        *root << new cbor_data("a") << sample1;
        do_cbor_test(root, "826161a161626163");
        root->release();
    }
    {
        // {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
        cbor_map* root = new cbor_map();
        *root << new cbor_pair("a", new cbor_data("A")) << new cbor_pair("b", new cbor_data("B")) << new cbor_pair("c", new cbor_data("C"))
              << new cbor_pair("d", new cbor_data("D")) << new cbor_pair("e", new cbor_data("E"));
        do_cbor_test(root, "a56161614161626142616361436164614461656145");
        root->release();
    }
    {
        // (_ h'0102', h'030405')
        // 0x5f42010243030405ff
        cbor_bstrings* root = new cbor_bstrings();
        *root << base16_decode("0102") << base16_decode("030405");
        do_cbor_test(root, "5f42010243030405ff");
        root->release();
    }
    {
        // (_ "strea", "ming")
        // 0x7f657374726561646d696e67ff
        cbor_tstrings* root = new cbor_tstrings();
        *root << "strea"
              << "ming";
        do_cbor_test(root, "7f657374726561646d696e67ff");
        root->release();
    }
    {
        // [_ ]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        do_cbor_test(root, "9fff");
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
        do_cbor_test(root, "9f018202039f0405ffff");
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
        do_cbor_test(root, "9f01820203820405ff");
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
        do_cbor_test(root, "83018202039f0405ff");
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
        do_cbor_test(root, "83019f0203ff820405");
        root->release();
    }
    {
        // [_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
        cbor_array* root = new cbor_array(cbor_flag_t::cbor_indef);
        for (int i = 1; i <= 25; i++) {
            *root << new cbor_data(i);
        }
        do_cbor_test(root, "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff");
        root->release();
    }
    {
        // {_ "a":1,"b":[_ 2,3]}
        cbor_map* root = new cbor_map(cbor_flag_t::cbor_indef);
        cbor_array* sample1 = new cbor_array(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_data(2) << new cbor_data(3);
        *root << new cbor_pair("a", new cbor_data(1)) << new cbor_pair("b", sample1);
        do_cbor_test(root, "bf61610161629f0203ffff");
        root->release();
    }
    {
        // ["a",{_ "b":"c"}]
        cbor_array* root = new cbor_array();
        cbor_map* sample1 = new cbor_map(cbor_flag_t::cbor_indef);
        *sample1 << new cbor_pair("b", new cbor_data("c"));
        *root << new cbor_data("a") << sample1;
        do_cbor_test(root, "826161bf61626163ff");
        root->release();
    }
    {
        // {_ "Fun":true,"Amt":-2}
        cbor_map* root = new cbor_map(cbor_flag_t::cbor_indef);
        *root << new cbor_pair("Fun", new cbor_data(true)) << new cbor_pair("Amt", new cbor_data(-2));
        do_cbor_test(root, "bf6346756ef563416d7421ff");
        root->release();
    }
}
