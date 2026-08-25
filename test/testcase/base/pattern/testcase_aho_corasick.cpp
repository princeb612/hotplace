/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_aho_corasick.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_aho_corasick1() {
    _test_case.begin("aho_corasick");
    t_aho_corasick<char> ac;
    ac.insert("he", 2);
    ac.insert("she", 3);
    ac.insert("hers", 4);
    ac.insert("his", 3);
    ac.build();
    const char* source = "ahishers";
    std::multimap<range_t, size_t> result;
    std::multimap<range_t, size_t> expect = {{range_t(1, 3), 3}, {range_t(3, 5), 1}, {range_t(4, 5), 0}, {range_t(4, 7), 2}};
    result = ac.search(source, strlen(source));

    _logger->writeln(R"(source "%s")", source);
    for (auto item : result) {
        size_t begin = item.first.begin;
        size_t patid = item.second;
        std::vector<char> pat;
        ac.get_pattern(patid, pat);
        _logger->writeln(R"(pos [%zi] pattern[%i] "%.*s")", begin, patid, pat.size(), pat.data());
    }
    _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm");
}

void test_aho_corasick2() {
    _test_case.begin("aho_corasick");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, size_t> expects;  // pair(pos_occurrence, id_pattern)
    } _table[] = {
        {
            // t_aho_corasick ac;
            // ac.insert("he", 2);
            // ac.insert("she", 3);
            // ac.insert("hers", 4);
            // ac.insert("his", 3);
            // ac.build();
            // const char* source = "ahishers";
            // ac.search(source, strlen(source));
            "ahishers",
            {
                {"he", 2},
                {"she", 3},
                {"hers", 4},
                {"his", 3},
            },
            // ahishers
            //  his        (1..3)[3] his
            //    she      (3..5)[1] she
            //     he      (4..5)[0] he
            //     hers    (4..7)[2] hers
            {
                {range_t(1, 3), 3},
                {range_t(3, 5), 1},
                {range_t(4, 5), 0},
                {range_t(4, 7), 2},
            },
        },

        // other cases moved into "testvector_ahocorasick.yml"
    };

    for (auto item : _table) {
        t_aho_corasick<char> ac;
        std::multimap<range_t, size_t> expect;
        std::multimap<range_t, size_t> result;

        _logger->writeln(R"(source "%s")", item.source);
        int i = 0;
        for (auto pat : item.patterns) {
            ac.insert(pat.pattern, pat.len);
            _logger->writeln(R"(pattern[%i] "%.*s")", i++, pat.len, pat.pattern);
        }

        ac.build();
        result = ac.search(item.source, strlen(item.source));

        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, item.source + range.begin);
        }

        _test_case.assert(item.expects == result, __FUNCTION__, R"(multiple pattern search "%s")", item.source);
    }
}

void test_aho_corasick3() {
    _test_case.begin("aho_corasick (token grouping, sub-pattern reduction, and repeat-rule processing)");
    bool test = false;

    t_aho_corasick_parser<uint32> ac;
    t_key_value<uint32, uint32> frequency;

    enum token_userdeined {
        token_sequencebody = token_userdefine,
        token_setbody,
        token_namednumberlist,
        token_namednumberelement,
        token_enumelement,
        token_enumerations,
        token_enumbody,
        token_sequenceofbody,
        token_setofbody,
        token_defaultval,
        token_builtintype_default,
        token_usertype_default,
        token_sequenceof_default,
        token_setof_default,
    };

    ac.set_group(token_builtintype, {token_bool, token_int, token_null, token_oid, token_real, token_utf8string, token_visiblestring});
    ac.set_group(token_class, {token_application, token_private, token_universal});
    ac.set_group(token_taggedmode, {token_implicit, token_explicit});

    ac.insert_as(token_tag, {token_lbracket, token_number, token_rbracket});                                 // * pattern 0
    ac.insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket});                    // * pattern 1
    ac.insert_as(token_tag, {token_lbracket, token_number, token_rbracket, token_taggedmode});               // * pattern 2
    ac.insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket, token_taggedmode});  // * pattern 3
    ac.insert_as(token_defaultval, {token_default, token_lbrace, token_rbrace});                             // * pattern 4
    ac.insert_as(token_builtintype_default, {token_builtintype, token_defaultval});                          //   pattern 5
    ac.insert_as(token_usertype_default, {token_usertype, token_defaultval});                                //   pattern 6
    ac.insert_as(token_taggedtype, {token_tag, token_builtintype});                                          // * pattern 7
    ac.insert_as(token_taggedtype, {token_tag, token_usertype});                                             // * pattern 8
    ac.insert_as(token_namedtype, {token_identifier, token_builtintype});                                    // * pattern 9
    ac.insert_as(token_namedtype, {token_identifier, token_builtintype_default});                            //   pattern 10
    ac.insert_as(token_namedtype, {token_identifier, token_taggedtype});                                     // * pattern 11
    ac.insert_as(token_namedtype, {token_identifier, token_usertype});                                       // * pattern 12
    ac.insert_as(token_namedtype, {token_identifier, token_usertype_default});                               //   pattern 13
    ac.repeat_as(token_element, token_comma, {token_namedtype, token_taggedtype});                           //
    ac.insert_as(token_sequencebody, {token_sequence, token_lbrace, token_element, token_rbrace});           // * pattern 14
    ac.insert_as(token_setbody, {token_set, token_lbrace, token_element, token_rbrace});                     // * pattern 15
    ac.insert_as(token_taggedtype, {token_tag, token_sequencebody});                                         // * pattern 16
    ac.insert_as(token_taggedtype, {token_tag, token_setbody});                                              // * pattern 17
    ac.insert_as(token_namednumberelement, {token_identifier, token_lparen, token_number, token_rparen});    // * pattern 18
    ac.repeat_as(token_namednumberlist, token_comma, {token_namednumberelement});                            //
    ac.insert_as(token_int, {token_int, token_lbrace, token_namednumberlist, token_rbrace});                 // * pattern 19
    ac.insert_as(token_enumbody, {token_enum, token_lbrace, token_namednumberlist, token_rbrace});           // * pattern 20
    ac.insert_as(token_namedtype, {token_identifier, token_enumbody});                                       // * pattern 21
    ac.insert_as(token_sequenceofbody, {token_sequence, token_of, token_builtintype});                       //   pattern 22
    ac.insert_as(token_sequenceofbody, {token_sequence, token_of, token_usertype});                          // * pattern 23
    ac.insert_as(token_sequenceof_default, {token_sequenceofbody, token_defaultval});                        // * pattern 24
    ac.insert_as(token_setofbody, {token_set, token_of, token_builtintype});                                 //   pattern 25
    ac.insert_as(token_setofbody, {token_set, token_of, token_usertype});                                    //   pattern 26
    ac.insert_as(token_setof_default, {token_setofbody, token_defaultval});                                  //   pattern 27
    ac.insert_as(token_namedtype, {token_identifier, token_sequenceof_default});                             //   pattern 28
    ac.insert_as(token_namedtype, {token_identifier, token_setof_default});                                  //   pattern 29
    ac.insert_as(token_taggedtype, {token_tag, token_usertype});                                             // * pattern 30
    ac.insert_as(token_taggedtype, {token_tag, token_sequenceof_default});                                   // * pattern 31
    ac.insert_as(token_taggedtype, {token_tag, token_setof_default});                                        //   pattern 32

    ac.build();

    auto lambda_test = [&ac, &frequency](const std::vector<uint32>& input, const std::multimap<range_t, size_t>& expect) -> bool {
        auto res = ac.search(input);
        for (auto& pair : res) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            frequency.access(pid, true);
            _logger->writeln("pos [%2zi..%2zi] pattern[%i]", range.begin, range.end, pid);
        }
        return (expect == res);
    };

    /**
     * Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}
     *
     * [00] line 1 type 36(lvalue) index 0 pos 0 len 5 (Type1)
     * [01] line 1 type 35(assign) index 1 pos 6 len 3 (::=)
     * [02] line 1 type 4110(sequence) index 2 pos 10 len 8 (SEQUENCE)
     * [03] line 1 type 8(lbrace) index 3 pos 19 len 1 ({)
     * [04] line 1 type 32(identifier) index 4 pos 20 len 4 (name)
     * [05] line 1 type 4122(visiblestring) index 5 pos 25 len 13 (VisibleString)
     * [06] line 1 type 21(comma) index 6 pos 38 len 1 (,)
     * [07] line 1 type 32(identifier) index 7 pos 40 len 2 (ok)
     * [08] line 1 type 4097(bool) index 8 pos 43 len 7 (BOOLEAN)
     * [09] line 1 type 9(rbrace) index 9 pos 50 len 1 (})
     */
    std::vector<uint32> input1 = {token_lvalue,        token_assign, token_sequence,   token_lbrace, token_identifier,  //
                                  token_visiblestring, token_comma,  token_identifier, token_bool,   token_rbrace};
    std::multimap<range_t, size_t> expect1 = {
        {range_t(2, 9), 14},
        {range_t(4, 5), 9},
        {range_t(7, 8), 9},
    };
    test = lambda_test(input1, expect1);
    _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");

    /**
     * Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString}
     *
     * [00] line 1 type 36(lvalue) index 20 pos 0 len 7 (Person2)
     * [01] line 1 type 35(assign) index 1 pos 8 len 3 (::=)
     * [02] line 1 type 4110(sequence) index 2 pos 12 len 8 (SEQUENCE)
     * [03] line 1 type 8(lbrace) index 3 pos 21 len 1 ({)
     * [04] line 1 type 32(identifier) index 4 pos 22 len 4 (name)
     * [05] line 1 type 6(lbracket) index 11 pos 27 len 1 ([)
     * [06] line 1 type 2(number) index 21 pos 28 len 1 (0)
     * [07] line 1 type 7(rbracket) index 14 pos 29 len 1 (])
     * [08] line 1 type 4141(implicit) index 15 pos 31 len 8 (IMPLICIT)
     * [09] line 1 type 4122(visiblestring) index 5 pos 40 len 13 (VisibleString)
     * [10] line 1 type 9(rbrace) index 9 pos 53 len 1 (})
     */
    std::vector<uint32> input2 = {token_lvalue,   token_assign, token_sequence, token_lbrace,   token_identifier,     //
                                  token_lbracket, token_number, token_rbracket, token_implicit, token_visiblestring,  //
                                  token_rbrace};
    std::multimap<range_t, size_t> expect2 = {
        {range_t(2, 10), 14}, {range_t(4, 9), 11}, {range_t(5, 7), 0}, {range_t(5, 8), 2}, {range_t(5, 9), 7},
    };
    test = lambda_test(input2, expect2);
    _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");

    /**
     * Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}
     *
     * [00] line 1 type 36(lvalue) index 0 pos 0 len 8 (Location)
     * [01] line 1 type 35(assign) index 1 pos 9 len 3 (::=)
     * [02] line 1 type 4099(int) index 2 pos 13 len 7 (INTEGER)
     * [03] line 1 type 8(lbrace) index 3 pos 21 len 1 ({)
     * [04] line 1 type 32(identifier) index 4 pos 22 len 10 (homeOffice)
     * [05] line 1 type 4(lparen) index 5 pos 32 len 1 (()
     * [06] line 1 type 2(number) index 6 pos 33 len 1 (0)
     * [07] line 1 type 5(rparen) index 7 pos 34 len 1 ())
     * [08] line 1 type 21(comma) index 8 pos 35 len 1 (,)
     * [09] line 1 type 32(identifier) index 9 pos 37 len 11 (fieldOffice)
     * [10] line 1 type 4(lparen) index 5 pos 48 len 1 (()
     * [11] line 1 type 2(number) index 10 pos 49 len 1 (1)
     * [12] line 1 type 5(rparen) index 7 pos 50 len 1 ())
     * [13] line 1 type 21(comma) index 8 pos 51 len 1 (,)
     * [14] line 1 type 32(identifier) index 11 pos 53 len 6 (roving)
     * [15] line 1 type 4(lparen) index 5 pos 59 len 1 (()
     * [16] line 1 type 2(number) index 12 pos 60 len 1 (2)
     * [17] line 1 type 5(rparen) index 7 pos 61 len 1 ())
     * [18] line 1 type 9(rbrace) index 13 pos 62 len 1 (})
     */
    std::vector<uint32> input3 = {token_lvalue, token_assign, token_int,    token_lbrace, token_identifier,  //
                                  token_lparen, token_number, token_rparen, token_comma,  token_identifier,  //
                                  token_lparen, token_number, token_rparen, token_comma,  token_identifier,  //
                                  token_lparen, token_number, token_rparen, token_rbrace};
    std::multimap<range_t, size_t> expect3 = {
        {range_t(2, 18), 19},
        {range_t(4, 7), 18},
        {range_t(9, 12), 18},
        {range_t(14, 17), 18},
    };
    test = lambda_test(input3, expect3);
    _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");

    /**
     * Person ::= SEQUENCE {name VisibleString, color ENUMERATED {red(0), green(1), blue(2)}}
     *
     * [00] line 1 type 36(lvalue) index 14 pos 0 len 6 (Person)
     * [01] line 1 type 35(assign) index 1 pos 7 len 3 (::=)
     * [02] line 1 type 4111(sequence) index 15 pos 11 len 8 (SEQUENCE)
     * [03] line 1 type 8(lbrace) index 3 pos 20 len 1 ({)
     * [04] line 1 type 32(identifier) index 16 pos 21 len 4 (name)
     * [05] line 1 type 4123(visiblestring) index 17 pos 26 len 13 (VisibleString)
     * [06] line 1 type 21(comma) index 8 pos 39 len 1 (,)
     * [07] line 1 type 32(identifier) index 18 pos 41 len 5 (color)
     * [08] line 1 type 4107(enum) index 2 pos 47 len 10 (ENUMERATED)
     * [09] line 1 type 8(lbrace) index 3 pos 58 len 1 ({)
     * [10] line 1 type 32(identifier) index 4 pos 59 len 3 (red)
     * [11] line 1 type 4(lparen) index 5 pos 62 len 1 (()
     * [12] line 1 type 2(number) index 6 pos 63 len 1 (0)
     * [13] line 1 type 5(rparen) index 7 pos 64 len 1 ())
     * [14] line 1 type 21(comma) index 8 pos 65 len 1 (,)
     * [15] line 1 type 32(identifier) index 9 pos 67 len 5 (green)
     * [16] line 1 type 4(lparen) index 5 pos 72 len 1 (()
     * [17] line 1 type 2(number) index 10 pos 73 len 1 (1)
     * [18] line 1 type 5(rparen) index 7 pos 74 len 1 ())
     * [19] line 1 type 21(comma) index 8 pos 75 len 1 (,)
     * [20] line 1 type 32(identifier) index 11 pos 77 len 4 (blue)
     * [21] line 1 type 4(lparen) index 5 pos 81 len 1 (()
     * [22] line 1 type 2(number) index 12 pos 82 len 1 (2)
     * [23] line 1 type 5(rparen) index 7 pos 83 len 1 ())
     * [24] line 1 type 9(rbrace) index 13 pos 84 len 1 (})
     * [25] line 1 type 9(rbrace) index 13 pos 85 len 1 (})
     */
    std::vector<uint32> input4 = {token_lvalue,        token_assign, token_sequence,   token_lbrace, token_identifier,  //
                                  token_visiblestring, token_comma,  token_identifier, token_enum,   token_lbrace,      //
                                  token_identifier,    token_lparen, token_number,     token_rparen, token_comma,       //
                                  token_identifier,    token_lparen, token_number,     token_rparen, token_comma,       //
                                  token_identifier,    token_lparen, token_number,     token_rparen, token_rbrace,      //
                                  token_rbrace};
    std::multimap<range_t, size_t> expect4 = {
        {range_t(2, 25), 14}, {range_t(4, 5), 9}, {range_t(7, 24), 21}, {range_t(8, 24), 20}, {range_t(10, 13), 18}, {range_t(15, 18), 18}, {range_t(20, 23), 18},
    };
    test = lambda_test(input4, expect4);
    _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");

    /**
     * PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
     *                 name Name,
     *                 title [0] VisibleString,
     *                 number EmployeeNumber,
     *                 dateOfHire [1] Date,
     *                 nameOfSpouse [2] Name,
     *                 children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}}
     *            ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
     *            Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {givenName VisibleString, initial VisibleString, familyName VisibleString}
     *            EmployeeNumber ::= [APPLICATION 2] IMPLICIT  INTEGER
     *            Date ::= [APPLICATION 3] IMPLICIT  VisibleString
     *
     * [00] line 1 type 41(usertype) index 19 pos 0 len 15 (PersonnelRecord)
     * [01] line 1 type 35(assign) index 12 pos 16 len 3 (::=)
     * [02] line 1 type 6(lbracket) index 14 pos 20 len 1 ([)
     * [03] line 1 type 4140(application) index 15 pos 21 len 11 (APPLICATION)
     * [04] line 1 type 2(number) index 20 pos 33 len 1 (0)
     * [05] line 1 type 7(rbracket) index 17 pos 34 len 1 (])
     * [06] line 1 type 4143(implicit) index 18 pos 36 len 8 (IMPLICIT)
     * [07] line 1 type 4114(set) index 21 pos 45 len 3 (SET)
     * [08] line 1 type 8(lbrace) index 4 pos 49 len 1 ({)
     * [09] line 2 type 32(identifier) index 5 pos 67 len 4 (name)
     * [10] line 2 type 41(usertype) index 22 pos 72 len 4 (Name)
     * [11] line 2 type 21(comma) index 7 pos 76 len 1 (,)
     * [12] line 3 type 32(identifier) index 23 pos 94 len 5 (title)
     * [13] line 3 type 6(lbracket) index 14 pos 100 len 1 ([)
     * [14] line 3 type 2(number) index 20 pos 101 len 1 (0)
     * [15] line 3 type 7(rbracket) index 17 pos 102 len 1 (])
     * [16] line 3 type 4124(visiblestring) index 13 pos 104 len 13 (VisibleString)
     * [17] line 3 type 21(comma) index 7 pos 117 len 1 (,)
     * [18] line 4 type 32(identifier) index 24 pos 135 len 6 (number)
     * [19] line 4 type 41(usertype) index 25 pos 142 len 14 (EmployeeNumber)
     * [20] line 4 type 21(comma) index 7 pos 156 len 1 (,)
     * [21] line 5 type 32(identifier) index 26 pos 174 len 10 (dateOfHire)
     * [22] line 5 type 6(lbracket) index 14 pos 185 len 1 ([)
     * [23] line 5 type 2(number) index 27 pos 186 len 1 (1)
     * [24] line 5 type 7(rbracket) index 17 pos 187 len 1 (])
     * [25] line 5 type 41(usertype) index 11 pos 189 len 4 (Date)
     * [26] line 5 type 21(comma) index 7 pos 193 len 1 (,)
     * [27] line 6 type 32(identifier) index 28 pos 211 len 12 (nameOfSpouse)
     * [28] line 6 type 6(lbracket) index 14 pos 224 len 1 ([)
     * [29] line 6 type 2(number) index 29 pos 225 len 1 (2)
     * [30] line 6 type 7(rbracket) index 17 pos 226 len 1 (])
     * [31] line 6 type 41(usertype) index 22 pos 228 len 4 (Name)
     * [32] line 6 type 21(comma) index 7 pos 232 len 1 (,)
     * [33] line 7 type 32(identifier) index 30 pos 250 len 8 (children)
     * [34] line 7 type 6(lbracket) index 14 pos 259 len 1 ([)
     * [35] line 7 type 2(number) index 16 pos 260 len 1 (3)
     * [36] line 7 type 7(rbracket) index 17 pos 261 len 1 (])
     * [37] line 7 type 4143(implicit) index 18 pos 263 len 8 (IMPLICIT)
     * [38] line 7 type 4112(sequence) index 3 pos 272 len 8 (SEQUENCE)
     * [39] line 7 type 4111(of) index 31 pos 281 len 2 (OF)
     * [40] line 7 type 41(usertype) index 32 pos 284 len 16 (ChildInformation)
     * [41] line 7 type 4153(default) index 33 pos 301 len 7 (DEFAULT)
     * [42] line 7 type 8(lbrace) index 4 pos 309 len 1 ({)
     * [43] line 7 type 9(rbrace) index 10 pos 310 len 1 (})
     * [44] line 7 type 9(rbrace) index 10 pos 311 len 1 (})
     * [45] line 8 type 41(usertype) index 32 pos 324 len 16 (ChildInformation)
     * [46] line 8 type 35(assign) index 12 pos 341 len 3 (::=)
     * [47] line 8 type 4114(set) index 21 pos 345 len 3 (SET)
     * [48] line 8 type 8(lbrace) index 4 pos 349 len 1 ({)
     * [49] line 8 type 32(identifier) index 5 pos 350 len 4 (name)
     * [50] line 8 type 41(usertype) index 22 pos 355 len 4 (Name)
     * [51] line 8 type 21(comma) index 7 pos 359 len 1 (,)
     * [52] line 8 type 32(identifier) index 34 pos 361 len 11 (dateOfBirth)
     * [53] line 8 type 6(lbracket) index 14 pos 373 len 1 ([)
     * [54] line 8 type 2(number) index 20 pos 374 len 1 (0)
     * [55] line 8 type 7(rbracket) index 17 pos 375 len 1 (])
     * [56] line 8 type 41(usertype) index 11 pos 377 len 4 (Date)
     * [57] line 8 type 9(rbrace) index 10 pos 381 len 1 (})
     * [58] line 9 type 41(usertype) index 22 pos 394 len 4 (Name)
     * [59] line 9 type 35(assign) index 12 pos 399 len 3 (::=)
     * [60] line 9 type 6(lbracket) index 14 pos 403 len 1 ([)
     * [61] line 9 type 4140(application) index 15 pos 404 len 11 (APPLICATION)
     * [62] line 9 type 2(number) index 27 pos 416 len 1 (1)
     * [63] line 9 type 7(rbracket) index 17 pos 417 len 1 (])
     * [64] line 9 type 4143(implicit) index 18 pos 419 len 8 (IMPLICIT)
     * [65] line 9 type 4112(sequence) index 3 pos 428 len 8 (SEQUENCE)
     * [66] line 9 type 8(lbrace) index 4 pos 437 len 1 ({)
     * [67] line 9 type 32(identifier) index 35 pos 438 len 9 (givenName)
     * [68] line 9 type 4124(visiblestring) index 13 pos 448 len 13 (VisibleString)
     * [69] line 9 type 21(comma) index 7 pos 461 len 1 (,)
     * [70] line 9 type 32(identifier) index 36 pos 463 len 7 (initial)
     * [71] line 9 type 4124(visiblestring) index 13 pos 471 len 13 (VisibleString)
     * [72] line 9 type 21(comma) index 7 pos 484 len 1 (,)
     * [73] line 9 type 32(identifier) index 37 pos 486 len 10 (familyName)
     * [74] line 9 type 4124(visiblestring) index 13 pos 497 len 13 (VisibleString)
     * [75] line 9 type 9(rbrace) index 10 pos 510 len 1 (})
     * [76] line 10 type 41(usertype) index 25 pos 523 len 14 (EmployeeNumber)
     * [77] line 10 type 35(assign) index 12 pos 538 len 3 (::=)
     * [78] line 10 type 6(lbracket) index 14 pos 542 len 1 ([)
     * [79] line 10 type 4140(application) index 15 pos 543 len 11 (APPLICATION)
     * [80] line 10 type 2(number) index 29 pos 555 len 1 (2)
     * [81] line 10 type 7(rbracket) index 17 pos 556 len 1 (])
     * [82] line 10 type 4143(implicit) index 18 pos 558 len 8 (IMPLICIT)
     * [83] line 10 type 4099(int) index 1 pos 568 len 7 (INTEGER)
     * [84] line 11 type 41(usertype) index 11 pos 587 len 4 (Date)
     * [85] line 11 type 35(assign) index 12 pos 592 len 3 (::=)
     * [86] line 11 type 6(lbracket) index 14 pos 596 len 1 ([)
     * [87] line 11 type 4140(application) index 15 pos 597 len 11 (APPLICATION)
     * [88] line 11 type 2(number) index 16 pos 609 len 1 (3)
     * [89] line 11 type 7(rbracket) index 17 pos 610 len 1 (])
     * [90] line 11 type 4143(implicit) index 18 pos 612 len 8 (IMPLICIT)
     * [91] line 11 type 4124(visiblestring) index 13 pos 622 len 13 (VisibleString)
     */
    std::vector<uint32> input5 = {token_usertype,   token_assign,        token_lbracket,    token_application,   token_number,         //
                                  token_rbracket,   token_implicit,      token_set,         token_lbrace,        token_identifier,     //
                                  token_usertype,   token_comma,         token_identifier,  token_lbracket,      token_number,         //
                                  token_rbracket,   token_visiblestring, token_comma,       token_identifier,    token_usertype,       //
                                  token_comma,      token_identifier,    token_lbracket,    token_number,        token_rbracket,       //
                                  token_usertype,   token_comma,         token_identifier,  token_lbracket,      token_number,         //
                                  token_rbracket,   token_usertype,      token_comma,       token_identifier,    token_lbracket,       //
                                  token_number,     token_rbracket,      token_implicit,    token_sequence,      token_of,             //
                                  token_usertype,   token_default,       token_lbrace,      token_rbrace,        token_rbrace,         //
                                  token_usertype,   token_assign,        token_set,         token_lbrace,        token_identifier,     //
                                  token_usertype,   token_comma,         token_identifier,  token_lbracket,      token_number,         //
                                  token_rbracket,   token_usertype,      token_rbrace,      token_usertype,      token_assign,         //
                                  token_lbracket,   token_application,   token_number,      token_rbracket,      token_implicit,       //
                                  token_sequence,   token_lbrace,        token_identifier,  token_visiblestring, token_comma,          //
                                  token_identifier, token_visiblestring, token_comma,       token_identifier,    token_visiblestring,  //
                                  token_rbrace,     token_usertype,      token_assign,      token_lbracket,      token_application,    //
                                  token_number,     token_rbracket,      token_implicit,    token_int,           token_usertype,       //
                                  token_assign,     token_lbracket,      token_application, token_number,        token_rbracket,       //
                                  token_implicit,   token_visiblestring};
    std::multimap<range_t, size_t> expect5 = {
        {range_t(2, 5), 1},    {range_t(2, 6), 3},    {range_t(2, 44), 17},  {range_t(7, 44), 15},  {range_t(9, 10), 12},  {range_t(12, 16), 11}, {range_t(13, 15), 0},
        {range_t(13, 16), 7},  {range_t(18, 19), 12}, {range_t(21, 25), 11}, {range_t(22, 24), 0},  {range_t(22, 25), 8},  {range_t(22, 25), 30}, {range_t(27, 31), 11},
        {range_t(28, 30), 0},  {range_t(28, 31), 8},  {range_t(28, 31), 30}, {range_t(33, 43), 11}, {range_t(34, 36), 0},  {range_t(34, 37), 2},  {range_t(34, 43), 31},
        {range_t(38, 40), 23}, {range_t(38, 43), 24}, {range_t(41, 43), 4},  {range_t(47, 57), 15}, {range_t(49, 50), 12}, {range_t(52, 56), 11}, {range_t(53, 55), 0},
        {range_t(53, 56), 8},  {range_t(53, 56), 30}, {range_t(60, 63), 1},  {range_t(60, 64), 3},  {range_t(60, 75), 16}, {range_t(65, 75), 14}, {range_t(67, 68), 9},
        {range_t(70, 71), 9},  {range_t(73, 74), 9},  {range_t(78, 81), 1},  {range_t(78, 82), 3},  {range_t(78, 83), 7},  {range_t(86, 89), 1},  {range_t(86, 90), 3},
        {range_t(86, 91), 7},
    };
    test = lambda_test(input5, expect5);
    _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");

    _logger->writeln("pattern frequency ... statistics for rule optimization");
    frequency.for_each([](uint32 pid, uint32 cnt) -> void { _logger->writeln("> pattern id %u : %u", pid, cnt); });
}

void testcase_aho_corasick() {
    test_aho_corasick1();
    test_aho_corasick2();
    test_aho_corasick3();
}
