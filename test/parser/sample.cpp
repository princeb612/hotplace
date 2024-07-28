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
#include <sdk/nostd.hpp>
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

t_shared_instance<cmdline_t<OPTION> > cmdline;

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
    _test_case.begin("parse");
    _logger->writeln(asn1_structure);
    _logger->dump(asn1_structure, strlen(asn1_structure));
    _logger->writeln(asn1_value);
    _logger->dump(asn1_value, strlen(asn1_value));
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
        if (cresult.match) {
            _logger->dump(cresult.p, cresult.size);
        }
        _test_case.assert(cresult.match, __FUNCTION__, "character search #1 found");
        _test_case.assert(0 == strncmp(pattern, cresult.p, cresult.size), __FUNCTION__, "character search #2 contents comparison");
    }
    parser::search_result cresult2 = p.csearch(context1, pattern2, strlen(pattern2), cresult.pos);
    {
        test_case_notimecheck notimecheck(_test_case);
        if (cresult2.match) {
            _logger->dump(cresult2.p, cresult2.size);
        }
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
        if (wresult.match) {
            _logger->dump(wresult.p, wresult.size);
        }
        _test_case.assert(wresult.match, __FUNCTION__, "word search #1 found");
        _test_case.assert(0 == strncmp(pattern, wresult.p, wresult.size), __FUNCTION__, "word search #2 contents comparison");
    }
    parser::search_result wresult2 = p.wsearch(context1, pattern2, strlen(pattern2), wresult.endidx + 1);
    {
        test_case_notimecheck notimecheck(_test_case);
        if (wresult2.match) {
            _logger->dump(wresult2.p, wresult2.size);
        }
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
    _test_case.assert(test, __FUNCTION__, "compare");
}

void test_multipattern_search() {
    _test_case.begin("t_aho_corasick");

    // model
    constexpr char sample[] = R"(int a; int b = 0; bool b = true;)";

    // sketch - pattern search
    {
        t_aho_corasick<int> ac;
        std::multimap<size_t, unsigned> result;
        std::multimap<size_t, unsigned> expect = {{0, 0}, {3, 1}, {8, 1}};
        std::vector<int> pattern1 = {token_type, token_identifier, token_colon};
        std::vector<int> pattern2 = {token_type, token_identifier, token_equal, token_identifier, token_colon};
        // after parsing
        std::vector<int> sample_parsed = {
            token_type, token_identifier, token_colon,                                 // int a;
            token_type, token_identifier, token_equal, token_identifier, token_colon,  // int b = 0;
            token_type, token_identifier, token_equal, token_identifier, token_colon   // bool b = true;
        };

        ac.insert(pattern1).insert(pattern2);
        ac.build_state_machine();
        result = ac.search(sample_parsed);
        for (auto item : result) {
            // pair(pos_occurrence, id_pattern)
            _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
        }
        _test_case.assert(result == expect, __FUNCTION__, "pattern matching #1");
    }

    // sketch - pattern match
    {
        parser p;
        parser::context context;
        std::multimap<size_t, unsigned> result;
        std::multimap<size_t, unsigned> expect = {{0, 0}, {3, 1}, {8, 3}};
        p.add_token("bool", 0x1000).add_token("int", 0x1001).add_token("true", 0x1002).add_token("false", 0x1002);
        p.parse(context, sample);
        p.add_pattern("int a;").add_pattern("int a = 0;").add_pattern("bool a;").add_pattern("bool a = true;");
        result = p.psearch(context);
        // sample  : int a; int b = 0; bool b = true;
        // pattern : 0      1          3
        // tokens  : 0   12 3   4 5 67 8    9 a b   c
        for (auto item : result) {
            // pair(pos_occurrence, id_pattern)
            parser::search_result res;
            context.psearch_result(res, item.first, item.second);
            _logger->writeln("pos [%zi] pattern[%i] %.*s", item.first, item.second, (unsigned)res.size, res.p);
        }
        _test_case.assert(result == expect, __FUNCTION__, "pattern matching #2");
    }
}

void test_sub_pattern() {
    _test_case.begin("sub pattern");
    //
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif
    cmdline.make_share(new cmdline_t<OPTION>);

    *cmdline << cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();

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

    _logger->flush();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
