/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > cmdline;

constexpr char asn1_structure[] =
    R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
            name Name,
            title [0] VisibleString,
            number EmployeeNumber,
            dateOfHire [1] Date,
            nameOfSpouse [2] Name,
            children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {} }
        ChildInformation ::= SET { name Name, dateOfBirth [0] Date}
        Name ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString}
        EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
        Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)";

constexpr char asn1_value[] =
    R"({ name {givenName "John",initial "P",familyName "Smith"},
        title "Director",
        number 51,
        dateOfHire "19710917",
        nameOfSpouse {givenName "Mary",initial "T",familyName "Smith"},
        children
            {
                {name {givenName "Ralph",initial "T",familyName "Smith"},
                        dateOfBirth "19571111"
                },
                {name {givenName "Susan",initial "B",familyName "Jones"},
                        dateOfBirth "19590717"
                }
            }
        })";

void test_dump_testdata() {
    // _test_case.begin("parse");
    // _logger->writeln(asn1_structure);
    // _logger->dump(asn1_structure, strlen(asn1_structure));
    // _logger->writeln(asn1_value);
    // _logger->dump(asn1_value, strlen(asn1_value));
}

void test_parser() {
    _test_case.begin("parse");

    parser p;
    parser::context context1;

    p.add_token("::=", token_assign).add_token("--", token_comments);
    p.parse(context1, asn1_structure, strlen(asn1_structure));

    {
        test_case_notimecheck notimecheck(_test_case);

        // dump
        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.typeof_token(desc->type).c_str(), desc->index,
                             desc->pos, desc->size, (unsigned)desc->size, desc->p);
        };

        context1.for_each(dump_handler);

        uint16 handle_token = p.get_config().get("handle_token");
        uint16 handle_quoted = p.get_config().get("handle_quoted");
        uint16 handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (1 == handle_quoted) && (1 == handle_comments), __FUNCTION__, "parse #1 (token on, comments on, quot on)");
    }
}

void test_parser_options() {
    _test_case.begin("parse");

    return_t ret = errorcode_t::success;
    parser p;
    parser::context context1;
    parser::context context2;
    parser::context context3;
    uint16 handle_token = 0;
    uint16 handle_quoted = 0;
    uint16 handle_comments = 0;

    auto dump_handler = [&](const token_description* desc) -> void {
        _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.typeof_token(desc->type).c_str(), desc->index,
                         desc->pos, desc->size, (unsigned)desc->size, desc->p);
    };

    // turn off switches and parse
    p.get_config().set("handle_comments", 0);
    ret = p.parse(context1, asn1_structure, strlen(asn1_structure));

    {
        test_case_notimecheck notimecheck(_test_case);
        context1.for_each(dump_handler);
        handle_token = p.get_config().get("handle_token");
        handle_quoted = p.get_config().get("handle_quoted");
        handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (0 == handle_comments) && (1 == handle_quoted), __FUNCTION__, "parse #2 (token on, comments off, quot on)");
    }

    p.get_config().set("handle_quoted", 0);
    ret = p.parse(context2, asn1_value, strlen(asn1_value));

    {
        test_case_notimecheck notimecheck(_test_case);
        context2.for_each(dump_handler);
        handle_token = p.get_config().get("handle_token");
        handle_quoted = p.get_config().get("handle_quoted");
        handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (0 == handle_comments) && (0 == handle_quoted), __FUNCTION__, "parse #3 (token on, comments off, quot off)");
    }

    p.get_config().set("handle_token", 0);
    ret = p.parse(context3, asn1_value, strlen(asn1_value));

    {
        test_case_notimecheck notimecheck(_test_case);
        context3.for_each(dump_handler);
        handle_token = p.get_config().get("handle_token");
        handle_quoted = p.get_config().get("handle_quoted");
        handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((0 == handle_token) && (0 == handle_comments) && (0 == handle_quoted), __FUNCTION__, "parse #4 (token off, comments off, quot off)");
    }
}

void test_parser_search() {
    _test_case.begin("parse");

    return_t ret = errorcode_t::success;
    parser p;
    parser::context context1;

    p.add_token("::=", token_assign).add_token("--", token_comments);

    // parse
    ret = p.parse(context1, asn1_structure, strlen(asn1_structure));

    {
        test_case_notimecheck notimecheck(_test_case);
        auto dump_handler = [&](const token_description* desc) -> void { _logger->writeln("index %d (%.*s)", desc->index, (unsigned)desc->size, desc->p); };
        context1.for_each(dump_handler);
        _test_case.test(ret, __FUNCTION__, "parse #5");
    }

    constexpr char pattern[] = "[APPLICATION 2] IMPLICIT INTEGER";
    constexpr char pattern2[] = "VisibleString";
    constexpr char pattern3[] = "ChildInformation";

    // strlen(asn1_structure) --> 612, strlen(pattern) --> 32
    // character search - KMP N(asn1_structure)=612, M(pattern)=32, O(612+32)
    // asn1_sequence 612 bytes
    // pattern        32 bytes
    parser::search_result cresult = p.csearch(context1, pattern, strlen(pattern));
    {
        test_case_notimecheck notimecheck(_test_case);
        // if (cresult.match) {
        //     _logger->dump(cresult.p, cresult.size);
        // }
        _test_case.assert(cresult.match, __FUNCTION__, "character search #1 search");
        _test_case.assert(0 == strncmp(pattern, cresult.p, cresult.size), __FUNCTION__, "character search #2 contents comparison");
    }
    parser::search_result cresult2 = p.csearch(context1, pattern2, strlen(pattern2), cresult.pos);
    {
        test_case_notimecheck notimecheck(_test_case);
        // if (cresult2.match) {
        //     _logger->dump(cresult2.p, cresult2.size);
        // }
        _test_case.assert(cresult2.match, __FUNCTION__, "character search #3 continuous search");
    }
    parser::search_result cresult3 = p.csearch(context1, pattern3, strlen(pattern3), 0);
    parser::search_result cresult4 = p.csearch(context1, pattern3, strlen(pattern3), cresult.pos);
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert((true == cresult3.match) && (false == cresult4.match), __FUNCTION__, "character search #4 search position");
    }

    // context1._tokens.size() --> 93, pattern._tokens.size() --> 6
    // word search - KMP N(context1)=93, M(pattern)=6, O(93+6)
    // asn1_structure 93 tokens [1 2 3 4 ... 3 4 21 6 7 33 ... 7 4 -1]
    // pattern         6 tokens [            3 4 21 6 7 33           ]
    parser::search_result wresult = p.wsearch(context1, pattern, strlen(pattern));
    {
        test_case_notimecheck notimecheck(_test_case);
        // if (wresult.match) {
        //     _logger->dump(wresult.p, wresult.size);
        // }
        _test_case.assert(wresult.match, __FUNCTION__, "word search #1 search");
        _test_case.assert(0 == strncmp(pattern, wresult.p, wresult.size), __FUNCTION__, "word search #2 contents comparison");
    }
    parser::search_result wresult2 = p.wsearch(context1, pattern2, strlen(pattern2), wresult.endidx + 1);
    {
        test_case_notimecheck notimecheck(_test_case);
        // if (wresult2.match) {
        //     _logger->dump(wresult2.p, wresult2.size);
        // }
        _test_case.assert(wresult2.match, __FUNCTION__, "word search #3 continuous search");
    }
    parser::search_result wresult3 = p.wsearch(context1, pattern3, strlen(pattern3), 0);
    parser::search_result wresult4 = p.wsearch(context1, pattern3, strlen(pattern3), wresult.endidx + 1);
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert((true == wresult3.match) && (false == wresult4.match), __FUNCTION__, "word search #4 search position");
    }
}

void test_parser_compare() {
    _test_case.begin("parse");

    parser p;
    p.add_token("::=", token_assign);

    constexpr char data1[] = "EmployeeNumber::= [APPLICATION 2] IMPLICIT INTEGER";
    constexpr char data2[] = "EmployeeNumber  ::=  [APPLICATION  2]  IMPLICIT  INTEGER";

    // compare ignoring white spaces
    // "EmployeeNumber" "::=" "[" "APPLICATION" "2" "]" "IMPLICIT" "INTEGER"

    bool test = p.compare(data1, data2);
    _test_case.assert(test, __FUNCTION__, "token/word-level compare");
}

void test_multipattern_search() {
    _test_case.begin("t_aho_corasick");

    // model
    constexpr char sample[] = R"(int a; int b = 0; bool b = true;)";

    // sketch - pattern search (wo add_pattern)
    {
        // result, expect
        // 0                        1
        // 0   12 3   4 5 67 8    9 0 1   2
        // int a; int b = 0; bool b = true; ; sample as an input
        // 0   12                           ; 0..2
        // int a;                           ; pattern1 (pattern index 0)
        //        3   4 5 67                ; 3..7
        //        int b = 0;                ; pattern2 (pattern index 1)
        //                   8    9 0 1   2 ; 8..12
        //                   bool b = true; ; pattern2 (pattern index 1)

        t_aho_corasick<int> ac;
        std::multimap<range_t, unsigned> result;
        std::multimap<range_t, unsigned> expect = {{range_t(0, 2), 0}, {range_t(3, 7), 1}, {range_t(8, 12), 1}};
        std::vector<int> pattern1 = {token_type, token_identifier, token_colon};
        std::vector<int> pattern2 = {token_type, token_identifier, token_equal, token_identifier, token_colon};

        // after parsing
        std::vector<int> sample_parsed = {
            token_type, token_identifier, token_colon,                                 // int a;
            token_type, token_identifier, token_equal, token_identifier, token_colon,  // int b = 0;
            token_type, token_identifier, token_equal, token_identifier, token_colon   // bool b = true;
        };

        ac.insert(pattern1);
        ac.insert(pattern2);
        ac.build();
        result = ac.search(sample_parsed);
        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            _logger->writeln("pos [%zi] pattern[%i]", range.begin, pid);
        }
        _test_case.assert(result == expect, __FUNCTION__, "pattern matching #1");
    }

    // sketch - pattern match (using add_pattern)
    {
        parser p;
        parser::context context;
        // input
        //  sample  : int a; int b = 0; bool b = true;
        //  tokens  : 0   12 3   4 5 67 8    9 a b   c
        //  pattern : 0      1          3
        // result/expect
        //  pattern[0] 0..2
        //  pattern[1] 3..7
        //  pattern[2] no match
        //  pattern[3] 8..12
        std::multimap<range_t, unsigned> result;
        std::multimap<range_t, unsigned> expect = {{range_t(0, 2), 0}, {range_t(3, 7), 1}, {range_t(8, 12), 3}};
        p.add_token("bool", 0x1000).add_token("int", 0x1001).add_token("true", 0x1002).add_token("false", 0x1002);
        p.parse(context, sample);
        p.add_pattern("int a;").add_pattern("int a = 0;").add_pattern("bool a;").add_pattern("bool a = true;");
        result = p.psearch(context);
        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            parser::search_result res;
            context.psearch_result(res, range);
            _logger->writeln("pos [%zi] pattern[%i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
        }
        _test_case.assert(result == expect, __FUNCTION__, "pattern matching #2");
    }
}

enum token_tag_t {
    token_userdef = 0x2000,

    token_of,
    token_default,
};

void test_patterns() {
    parser p;
    p.get_config().set("handle_lvalue_usertype", 1);

    struct asn1_token {
        const char* token;
        uint32 attr;
        uint32 tag;
    };
    struct asn1_pattern {
        int patid;
        const char* pattern;
    };

    asn1_token asn1_tokens[] = {
        {"::=", token_assign},
        {"--", token_comments},
        {"BOOLEAN", token_builtintype, token_bool},                 // BooleanType
        {"INTEGER", token_builtintype, token_int},                  // IntegerType
        {"BIT STRING", token_builtintype, token_bitstring},         // BitStringType
        {"OCTET STRING", token_builtintype, token_octstring},       // OctetStringType
        {"NULL", token_builtintype, token_null},                    // NullType, NullValue
        {"REAL", token_builtintype, token_real},                    // RealType
        {"IA5String", token_builtintype, token_ia5string},          // CharacterStringType
        {"VisibleString", token_builtintype, token_visiblestring},  // CharacterStringType
        {"SEQUENCE", token_sequence},                               // SequenceType
        {"SEQUENCE OF", token_sequenceof},                          // SequenceOfType
        {"SET", token_set},                                         // SetType
        {"SET OF", token_setof},                                    // SetOfType
        {"TRUE", token_bool, token_true},                           // BooleanValue
        {"FALSE", token_bool, token_false},                         // BooleanValue
        {"UNIVERSAL", token_class, token_universal},                // Class
        {"APPLICATION", token_class, token_application},            // Class
        {"PRIVATE", token_class, token_private},                    // Class
        {"IMPLICIT", token_taggedmode, token_implicit},             // TaggedType
        {"EXPLICIT", token_taggedmode, token_explicit},             // TaggedType
        {"$pattern_builtintype", token_builtintype},
        {"$pattern_usertype", token_usertype},
        {"$pattern_class", token_class},
        {"$pattern_sequence", token_sequence},
        {"$pattern_sequenceof", token_sequenceof},
        {"$pattern_set", token_set},
        {"$pattern_setof", token_setof},
        {"$pattern_taggedmode", token_taggedmode},
        {"$pattern_assign", token_assign},
        {"$identifier", token_identifier},
    };
    asn1_pattern asn1_patterns[] = {
        {0, "$pattern_builtintype"},
        {1, "$pattern_usertype"},
        {2, "$pattern_sequence"},
        {3, "$pattern_set"},
        {4, "$pattern_sequenceof $pattern_usertype"},
        {5, "$pattern_sequenceof $pattern_usertype DEFAULT"},
        {6, "$pattern_sequenceof $pattern_usertype DEFAULT {}"},
        {7, "{"},
        {8, ","},
        {9, "}"},
        {10, "[$pattern_class 1] $pattern_builtintype"},
        {11, "[$pattern_class 1] $pattern_usertype"},
        {12, "[$pattern_class 1] $pattern_taggedmode $pattern_builtintype"},
        {13, "[$pattern_class 1] $pattern_taggedmode $pattern_usertype"},
        {14, "[$pattern_class 1] $pattern_taggedmode $pattern_sequence"},
        {15, "[$pattern_class 1] $pattern_taggedmode $pattern_set"},
        {16, "[1] $pattern_builtintype"},
        {17, "[1] $pattern_usertype"},
        {18, "[1] $pattern_taggedmode $pattern_builtintype"},
        {19, "[1] $pattern_taggedmode $pattern_usertype"},
        {20, "[1] $pattern_taggedmode $pattern_sequence"},
        {21, "[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype"},
        {22, "[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT"},
        {23, "[1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT {}"},
        {24, "[1] $pattern_taggedmode $pattern_set"},
        {25, "$identifier $pattern_builtintype"},
        {26, "$identifier $pattern_usertype"},
        {27, "$identifier $pattern_sequence"},
        {28, "$identifier $pattern_set"},
        {29, "$identifier [$pattern_class 1] $pattern_builtintype"},
        {30, "$identifier [$pattern_class 1] $pattern_usertype"},
        {31, "$identifier [$pattern_class 1] $pattern_taggedmode $pattern_builtintype"},
        {32, "$identifier [$pattern_class 1] $pattern_taggedmode $pattern_usertype"},
        {33, "$identifier [$pattern_class 1] $pattern_taggedmode $pattern_sequence"},
        {34, "$identifier [$pattern_class 1] $pattern_taggedmode $pattern_set"},
        {35, "$identifier [1] $pattern_builtintype"},
        {36, "$identifier [1] $pattern_usertype"},
        {37, "$identifier [1] $pattern_taggedmode $pattern_builtintype"},
        {38, "$identifier [1] $pattern_taggedmode $pattern_usertype"},
        {39, "$identifier [1] $pattern_taggedmode $pattern_sequence"},
        {40, "$identifier [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype"},
        {41, "$identifier [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT"},
        {42, "$identifier [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT {}"},
        {43, "$identifier [1] $pattern_taggedmode $pattern_set"},
        {44, "$pattern_assign"},
        {45, "$identifier $pattern_assign [$pattern_class 1] $pattern_builtintype"},
        {46, "$identifier $pattern_assign [$pattern_class 1] $pattern_usertype"},
        {47, "$identifier $pattern_assign [$pattern_class 1] $pattern_taggedmode $pattern_builtintype"},
        {48, "$identifier $pattern_assign [$pattern_class 1] $pattern_taggedmode $pattern_usertype"},
        {49, "$identifier $pattern_assign [$pattern_class 1] $pattern_taggedmode $pattern_sequence"},
        {50, "$identifier $pattern_assign [$pattern_class 1] $pattern_taggedmode $pattern_set"},
        {51, "$identifier $pattern_assign [1] $pattern_builtintype"},
        {52, "$identifier $pattern_assign [1] $pattern_usertype"},
        {53, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_builtintype"},
        {54, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_usertype"},
        {55, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_sequence"},
        {56, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype"},
        {57, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT"},
        {58, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_sequenceof $pattern_usertype DEFAULT {}"},
        {59, "$identifier $pattern_assign [1] $pattern_taggedmode $pattern_set"},
    };

    for (auto item : asn1_tokens) {
        p.add_token(item.token, item.attr, item.tag);
    }
    int i = 0;
    for (auto item : asn1_patterns) {
        _logger->writeln(R"(add pattern[%2i] "%s")", i++, item.pattern);
        p.add_pattern(item.pattern);
    }

    struct testvector {
        const char* source;
    } _table[] = {
        R"(NULL)",
        R"(INTEGER)",
        R"(REAL)",
        R"(SEQUENCE {name IA5String, ok BOOLEAN })",
        R"(Date ::= VisibleString)",
        R"(Date ::= [APPLICATION 3] IMPLICIT VisibleString)",
        R"(
           PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
                name Name,
                title [0] VisibleString,
                number EmployeeNumber,
                dateOfHire [1] Date,
                nameOfSpouse [2] Name,
                children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}}
           ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
           Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {givenName VisibleString, initial VisibleString, familyName VisibleString}
           EmployeeNumber ::= [APPLICATION 2] IMPLICIT  INTEGER
           Date ::= [APPLICATION 3] IMPLICIT  VisibleString)",
    };

    for (auto item : _table) {
        _logger->setcolor(bold, cyan).colorln(item.source);

        parser::context context;
        p.parse(context, item.source);

        auto result = p.psearchex(context);
        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            parser::search_result res;
            context.psearch_result(res, range);

            _logger->writeln("pos [%zi] pattern[%2i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
        }

        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("line %zi type %d(%s) tag %i index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.typeof_token(desc->type).c_str(),
                             desc->tag, desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
        };
        context.for_each(dump_handler);
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif
    cmdline.make_share(new t_cmdline_t<OPTION>);

    *cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();

    cmdline->parse(argc, argv);
    const OPTION& option = cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test_dump_testdata();
    test_parser();
    test_parser_options();
    test_parser_search();
    test_parser_compare();
    test_multipattern_search();
    test_patterns();

    _logger->flush();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
