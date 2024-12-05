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

void test_parse_routine(const char* input, const char* diagnostic, const char* diagnostic2 = nullptr) {
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

        std::string b16;
        base16_encode(bin, b16);
        _logger->writeln("diagnostic %s", bs.c_str());
        _logger->writeln("cbor       %s", b16.c_str());

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

void test_parse() {
    _test_case.begin("test3.parse");
    // 0
    test_parse_routine("00", "0");
    // 1
    test_parse_routine("01", "1");
    // 10
    test_parse_routine("0a", "10");
    // 23
    test_parse_routine("17", "23");
    // 24
    test_parse_routine("1818", "24");
    // 25
    test_parse_routine("1819", "25");
    // 100
    test_parse_routine("1864", "100");
    // 1000
    test_parse_routine("1903e8", "1000");
    // 1000000
    test_parse_routine("1a000f4240", "1000000");
    // 1000000000000
    test_parse_routine("1b000000e8d4a51000", "1000000000000");
    // 18446744073709551615
    test_parse_routine("1bffffffffffffffff", "18446744073709551615");
    // 18446744073709551616
    test_parse_routine("c249010000000000000000", "18446744073709551616", "2(18446744073709551616)");
    // -18446744073709551615
    test_parse_routine("3bfffffffffffffffe", "-18446744073709551615");
    // -18446744073709551616
    test_parse_routine("3bffffffffffffffff", "-18446744073709551616");
    // -18446744073709551617
    test_parse_routine("c349010000000000000000", "-18446744073709551617", "3(-18446744073709551617)");
    // -1
    test_parse_routine("20", "-1");
    // -10
    test_parse_routine("29", "-10");
    // -100
    test_parse_routine("3863", "-100");
    // -1000
    test_parse_routine("3903e7", "-1000");
    // false
    test_parse_routine("f4", "false");
    // true
    test_parse_routine("f5", "true");
    // null
    test_parse_routine("f6", "null");
    // undefined
    test_parse_routine("f7", "undefined");
    // []
    test_parse_routine("80", "[]");
    // [1,2,3]
    test_parse_routine("83010203", "[1,2,3]");
    // [1,[2,3],[4,5]]
    test_parse_routine("8301820203820405", "[1,[2,3],[4,5]]");
    // [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
    test_parse_routine("98190102030405060708090a0b0c0d0e0f101112131415161718181819", "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]");
    // {}
    test_parse_routine("a0", "{}");
    // {1:2,3:4}
    test_parse_routine("a201020304", "{1:2,3:4}");
    // {"a":1,"b":[2,3]}
    test_parse_routine("a26161016162820203", R"({"a":1,"b":[2,3]})");
    // ["a",{"b":"c"}]
    test_parse_routine("826161a161626163", R"(["a",{"b":"c"}])");
    // {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
    test_parse_routine("a56161614161626142616361436164614461656145", R"({"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"})");
    // (_ h'0102', h'030405')
    test_parse_routine("5f42010243030405ff", "(_ h'0102', h'030405')");
    // (_ "strea", "ming")
    test_parse_routine("7f657374726561646d696e67ff", R"((_ "strea", "ming"))");
    // [_ ]
    test_parse_routine("9fff", "[_ ]");
    // [_ 1,[2,3],[_ 4,5]]
    test_parse_routine("9f018202039f0405ffff", "[_ 1,[2,3],[_ 4,5]]");
    // [_ 1,[2,3],[4,5]]
    test_parse_routine("9f01820203820405ff", "[_ 1,[2,3],[4,5]]");
    // [1,[2,3],[_ 4,5]]
    test_parse_routine("83018202039f0405ff", "[1,[2,3],[_ 4,5]]");
    // [1,[_ 2,3],[4,5]]
    test_parse_routine("83019f0203ff820405", "[1,[_ 2,3],[4,5]]");
    // [_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
    test_parse_routine("9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff", "[_ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]");
    // {_ "a":1,"b":[_ 2,3]}
    test_parse_routine("bf61610161629f0203ffff", R"({_ "a":1,"b":[_ 2,3]})");
    // ["a",{_ "b":"c"}]
    test_parse_routine("826161bf61626163ff", R"(["a",{_ "b":"c"}])");
    // {_ "Fun":true,"Amt":-2}
    test_parse_routine("bf6346756ef563416d7421ff", R"({_ "Fun":true,"Amt":-2})");
}
