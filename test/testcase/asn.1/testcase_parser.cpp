/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include "sample.hpp"

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

constexpr char asn1_sample[] =
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
    // _test_case.begin("parser");
    // _logger->writeln(asn1_structure);
    // _logger->dump(asn1_structure, strlen(asn1_structure));
    // _logger->writeln(asn1_sample);
    // _logger->dump(asn1_sample, strlen(asn1_sample));
}

void test_parser_sample() {
    _test_case.begin("parser");

    asn1_parser ps;
    auto& p = ps.get_parser();
    parser_context context1;

    p.add_token("::=", token_assign).add_token("--", token_comments);
    p.parse(context1, asn1_structure, strlen(asn1_structure));

    {
        test_case_notimecheck notimecheck(_test_case);

        // dump
        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.nameof_token(desc->type).c_str(), desc->index, desc->pos,
                             desc->size, (unsigned)desc->size, desc->p);
        };

        context1.for_each(dump_handler);

        uint16 handle_token = p.get_config().get("handle_token");
        uint16 handle_quoted = p.get_config().get("handle_quoted");
        uint16 handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (1 == handle_quoted) && (1 == handle_comments), __FUNCTION__, "parse #1 (token on, comments on, quot on)");
    }
}

void test_parser_options() {
    _test_case.begin("parser");

    return_t ret = errorcode_t::success;
    asn1_parser ps;
    auto& p = ps.get_parser();
    parser_context context1;
    parser_context context2;
    parser_context context3;
    uint16 handle_token = 0;
    uint16 handle_quoted = 0;
    uint16 handle_comments = 0;

    auto dump_handler = [&](const token_description* desc) -> void {
        _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.nameof_token(desc->type).c_str(), desc->index, desc->pos,
                         desc->size, (unsigned)desc->size, desc->p);
    };

    // turn off switches and parse
    p.get_config().set(std::string("handle_comments"), 0);
    ret = p.parse(context1, asn1_structure, strlen(asn1_structure));
    _test_case.test(ret, __FUNCTION__, "parse");

    {
        test_case_notimecheck notimecheck(_test_case);
        context1.for_each(dump_handler);
        handle_token = p.get_config().get("handle_token");
        handle_quoted = p.get_config().get("handle_quoted");
        handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (0 == handle_comments) && (1 == handle_quoted), __FUNCTION__, "parse #2 (token on, comments off, quot on)");
    }

    p.get_config().set("handle_quoted", 0);
    ret = p.parse(context2, asn1_sample, strlen(asn1_sample));

    {
        test_case_notimecheck notimecheck(_test_case);
        context2.for_each(dump_handler);
        handle_token = p.get_config().get("handle_token");
        handle_quoted = p.get_config().get("handle_quoted");
        handle_comments = p.get_config().get("handle_comments");
        _test_case.assert((1 == handle_token) && (0 == handle_comments) && (0 == handle_quoted), __FUNCTION__, "parse #3 (token on, comments off, quot off)");
    }

    p.get_config().set("handle_token", 0);
    ret = p.parse(context3, asn1_sample, strlen(asn1_sample));

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
    _test_case.begin("parser");

    return_t ret = errorcode_t::success;
    asn1_parser ps;
    auto& p = ps.get_parser();
    parser_context context1;

    p.add_token("::=", token_assign).add_token("--", token_comments);

    // parse
    ret = p.parse(context1, asn1_structure, strlen(asn1_structure));

    {
        test_case_notimecheck notimecheck(_test_case);
        auto dump_handler = [&](const token_description* desc) -> void { _logger->writeln("index %d (%.*s)", desc->index, (unsigned)desc->size, desc->p); };
        context1.for_each(dump_handler);
        _test_case.test(ret, __FUNCTION__, "parse #5");
    }

    // constexpr char pattern[] = "[APPLICATION 2] IMPLICIT INTEGER";
    // constexpr char pattern2[] = "VisibleString";
    // constexpr char pattern3[] = "ChildInformation";
    //
    // // strlen(asn1_structure) --> 612, strlen(pattern) --> 32
    // // character search - KMP N(asn1_structure)=612, M(pattern)=32, O(612+32)
    // // asn1_sequence 612 bytes
    // // pattern        32 bytes
    // search_result cresult = p.csearch(context1, pattern, strlen(pattern));
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     // if (cresult.match) {
    //     //     _logger->dump(cresult.p, cresult.size);
    //     // }
    //     _test_case.assert(cresult.match, __FUNCTION__, "character search #1 search");
    //     _test_case.assert(0 == strncmp(pattern, cresult.p, cresult.size), __FUNCTION__, "character search #2 contents comparison");
    // }
    // search_result cresult2 = p.csearch(context1, pattern2, strlen(pattern2), cresult.pos);
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     // if (cresult2.match) {
    //     //     _logger->dump(cresult2.p, cresult2.size);
    //     // }
    //     _test_case.assert(cresult2.match, __FUNCTION__, "character search #3 continuous search");
    // }
    // search_result cresult3 = p.csearch(context1, pattern3, strlen(pattern3), 0);
    // search_result cresult4 = p.csearch(context1, pattern3, strlen(pattern3), cresult.pos);
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     _test_case.assert((true == cresult3.match) && (false == cresult4.match), __FUNCTION__, "character search #4 search position");
    // }
    //
    // // context1._tokens.size() --> 93, pattern._tokens.size() --> 6
    // // word search - KMP N(context1)=93, M(pattern)=6, O(93+6)
    // // asn1_structure 93 tokens [1 2 3 4 ... 3 4 21 6 7 33 ... 7 4 -1]
    // // pattern         6 tokens [            3 4 21 6 7 33           ]
    // search_result wresult = p.wsearch(context1, pattern, strlen(pattern));
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     // if (wresult.match) {
    //     //     _logger->dump(wresult.p, wresult.size);
    //     // }
    //     _test_case.assert(wresult.match, __FUNCTION__, "word search #1 search");
    //     _test_case.assert(0 == strncmp(pattern, wresult.p, wresult.size), __FUNCTION__, "word search #2 contents comparison");
    // }
    // search_result wresult2 = p.wsearch(context1, pattern2, strlen(pattern2), wresult.endidx + 1);
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     // if (wresult2.match) {
    //     //     _logger->dump(wresult2.p, wresult2.size);
    //     // }
    //     _test_case.assert(wresult2.match, __FUNCTION__, "word search #3 continuous search");
    // }
    // search_result wresult3 = p.wsearch(context1, pattern3, strlen(pattern3), 0);
    // search_result wresult4 = p.wsearch(context1, pattern3, strlen(pattern3), wresult.endidx + 1);
    // {
    //     test_case_notimecheck notimecheck(_test_case);
    //     _test_case.assert((true == wresult3.match) && (false == wresult4.match), __FUNCTION__, "word search #4 search position");
    // }
}

void test_parser_compare() {
    // _test_case.begin("parser");
    //
    // asn1_parser ps;
    // auto& p = ps.get_parser();
    //
    // p.add_token("::=", token_assign);
    //
    // constexpr char data1[] = "EmployeeNumber::= [APPLICATION 2] IMPLICIT INTEGER";
    // constexpr char data2[] = "EmployeeNumber  ::=  [APPLICATION  2]  IMPLICIT  INTEGER";
    //
    // // compare ignoring white spaces
    // // "EmployeeNumber" "::=" "[" "APPLICATION" "2" "]" "IMPLICIT" "INTEGER"
    //
    // bool test = p.compare(data1, data2);
    // _test_case.assert(test, __FUNCTION__, "token/word-level compare");
}

void test_multipattern_search() {
    // _test_case.begin("parser");
    //
    // // model
    // constexpr char sample[] = R"(int a; int b = 0; bool b = true;)";
    //
    // // sketch - pattern search (wo add_pattern)
    // {
    //     // result, expect
    //     // 0                        1
    //     // 0   12 3   4 5 67 8    9 0 1   2
    //     // int a; int b = 0; bool b = true; ; sample as an input
    //     // 0   12                           ; 0..2
    //     // int a;                           ; pattern1 (pattern index 0)
    //     //        3   4 5 67                ; 3..7
    //     //        int b = 0;                ; pattern2 (pattern index 1)
    //     //                   8    9 0 1   2 ; 8..12
    //     //                   bool b = true; ; pattern2 (pattern index 1)
    //
    //     t_aho_corasick<int> ac;
    //     std::multimap<range_t, size_t> result;
    //     std::multimap<range_t, size_t> expect = {{range_t(0, 2), 0}, {range_t(3, 7), 1}, {range_t(8, 12), 1}};
    //     std::vector<int> pattern1 = {token_type, token_word, token_colon};
    //     std::vector<int> pattern2 = {token_type, token_word, token_equal, token_word, token_colon};
    //
    //     // after parsing
    //     std::vector<int> sample_parsed = {
    //         token_type, token_word, token_colon,                           // int a;
    //         token_type, token_word, token_equal, token_word, token_colon,  // int b = 0;
    //         token_type, token_word, token_equal, token_word, token_colon   // bool b = true;
    //     };
    //
    //     ac.insert(pattern1);
    //     ac.insert(pattern2);
    //     ac.build();
    //     result = ac.search(sample_parsed);
    //     for (auto& pair : result) {
    //         // pair(pos_occurrence, id_pattern)
    //         const auto& range = pair.first;
    //         const auto& pid = pair.second;
    //         _logger->writeln("pos [%zi] pattern[%i]", range.begin, pid);
    //     }
    //     _test_case.assert(result == expect, __FUNCTION__, "pattern matching #1");
    // }
    //
    // // sketch - pattern match (using add_pattern)
    // {
    //     asn1_parser ps;
    //     auto& p = ps.get_parser();
    //
    //     parser_context context;
    //     // input
    //     //  sample  : int a; int b = 0; bool b = true;
    //     //  tokens  : 0   12 3   4 5 67 8    9 a b   c
    //     //  pattern : 0      1          3
    //     // result/expect
    //     //  pattern[0] 0..2
    //     //  pattern[1] 3..7
    //     //  pattern[2] no match
    //     //  pattern[3] 8..12
    //     std::multimap<range_t, size_t> result;
    //     std::multimap<range_t, size_t> expect = {{range_t(0, 2), 0}, {range_t(3, 7), 1}, {range_t(8, 12), 3}};
    //     p.add_token("bool", 0x1000).add_token("int", 0x1001).add_token("true", 0x1002).add_token("false", 0x1002);
    //     p.parse(context, sample);
    //     p.add_pattern("int a;").add_pattern("int a = 0;").add_pattern("bool a;").add_pattern("bool a = true;");
    //     result = p.psearch(context);
    //     for (auto& pair : result) {
    //         // pair(pos_occurrence, id_pattern)
    //         const auto& range = pair.first;
    //         const auto& pid = pair.second;
    //         search_result res;
    //         context.psearch_result(res, range);
    //         _logger->writeln("pos [%zi] pattern[%i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
    //     }
    //     _test_case.assert(result == expect, __FUNCTION__, "pattern matching #2");
    // }
}

enum token_tag_t {
    token_userdef = 0x2000,

    token_of,
    token_default,
};

void test_patterns() {
    _test_case.begin("parser");

    asn1_parser ps;
    auto& p = ps.get_parser();

    p.get_config().set("handle_lvalue_usertype", 1);

    struct testvector {
        const char* source;
    } _table[] = {
        R"(NULL)",
        R"(INTEGER)",
        R"(REAL)",
        R"(SEQUENCE {name IA5String, ok BOOLEAN })",
        R"(Date ::= VisibleString)",
        R"(Date ::= [APPLICATION 3] IMPLICIT VisibleString)",
        R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
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

        parser_context context;
        p.parse(context, item.source);

        // auto result = p.psearchex(context);
        // for (auto& pair : result) {
        //     // pair(pos_occurrence, id_pattern)
        //     const auto& range = pair.first;
        //     const auto& pid = pair.second;
        //     search_result res;
        //     context.psearch_result(res, range);
        //
        //     _logger->writeln("pos [%zi] pattern[%2i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
        // }

        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->line, desc->type, p.nameof_token(desc->type).c_str(), desc->index, desc->pos,
                             desc->size, (unsigned)desc->size, desc->p);
        };
        context.for_each(dump_handler);
    }
}

void test_asn1parser1() {
    _test_case.begin("asn1_parser");
    auto schema1 = "Type1 ::= VisibleString";
    auto schema2 = "Type2 ::= [APPLICATION 3] IMPLICIT Type1";
    auto schema3 = "Type3 ::= [2] EXPLICIT Type2";
    auto schema4 = "Type4 ::= [APPLICATION 7] IMPLICIT Type3";
    auto schema5 = "Type5 ::= [2] IMPLICIT Type2";
    auto schema6 = "Type6 ::= [2] EXPLICIT Type1";
    auto schema7 = "Type7 ::= [2] Type2";
    auto schema8 = "Type8 ::= [APPLICATION 7] IMPLICIT Type7";

    struct testvector {
        const char* schema;
        const char* expect;
    };
    // clang-format off
    struct testvector table[] = {
        {schema1, "1A 05 4A 6F 6E 65 73"},
        {schema2, "43 05 4A 6F 6E 65 73"},
        {schema3, "A2 07 43 05 4A 6F 6E 65 73"},
        {schema4, "67 07 43 05 4A 6F 6E 65 73"},
        {schema5, "82 05 4A 6F 6E 65 73"},
        {schema6, "A2 07 1A 05 4A 6F 6E 65 73"},
        {schema7, "A2 07 43 05 4A 6F 6E 65 73"},
        {schema8, "67 07 43 05 4A 6F 6E 65 73"},
    };
    // clang-format on

    asn1_runtime runtime;
    asn1_parser ps;
    auto& p = ps.get_parser();

    auto dump_handler = [&](const token_description* desc) -> void {
        _logger->writeln("> type %d(%s) index %d pos %zi len %zi (%.*s)", desc->type, p.nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size,
                         (unsigned)desc->size, desc->p);
    };
    for (const auto& entry : table) {
        parser_context ctx;
        p.parse(ctx, entry.schema);
        ctx.for_each(dump_handler);
    }
}

void test_asn1parser2() {
    _test_case.begin("asn1_parser");

#if 0
    bnf_grammar_parser parser;

    // Terminal
    bnf_symbol t_id{symbol_type::terminal, TAG_IDENTIFIER, "identifier"};
    bnf_symbol t_type{symbol_type::terminal, TAG_TYPE_NAME, "type_name"};
    bnf_symbol t_int{symbol_type::terminal, TAG_INTEGER, "INTEGER"};
    bnf_symbol t_seq{symbol_type::terminal, TAG_SEQUENCE, "SEQUENCE"};
    bnf_symbol t_assign{symbol_type::terminal, TAG_ASSIGN, "::="};
    bnf_symbol t_lbrk{symbol_type::terminal, TAG_LBRACKET, "["};
    bnf_symbol t_rbrk{symbol_type::terminal, TAG_RBRACKET, "]"};
    bnf_symbol t_lbrc{symbol_type::terminal, TAG_LBRACE, "{"};
    bnf_symbol t_rbrc{symbol_type::terminal, TAG_RBRACE, "}"};
    bnf_symbol t_comma{symbol_type::terminal, TAG_COMMA, ","};
    bnf_symbol t_app{symbol_type::terminal, TAG_CLASS_APP, "APPLICATION"};
    bnf_symbol t_priv{symbol_type::terminal, TAG_CLASS_PRIV, "PRIVATE"};
    bnf_symbol t_imp{symbol_type::terminal, TAG_IMPLICIT, "IMPLICIT"};
    bnf_symbol t_num{symbol_type::terminal, TAG_NUMBER, "number"};

    // Non-terminal
    bnf_symbol nt_builtin{symbol_type::non_terminal, 0, "BuiltinType"};
    bnf_symbol nt_userdef{symbol_type::non_terminal, 0, "UserDefinedType"};
    bnf_symbol nt_tag{symbol_type::non_terminal, 0, "Tag"};
    bnf_symbol nt_taggedtype{symbol_type::non_terminal, 0, "TaggedType"};
    bnf_symbol nt_namedtype{symbol_type::non_terminal, 0, "NamedType"};
    bnf_symbol nt_seq_elem{symbol_type::non_terminal, 0, "SequenceElement"};
    bnf_symbol nt_seq_body{symbol_type::non_terminal, 0, "SequenceBody"};
    bnf_symbol nt_seq{symbol_type::non_terminal, 0, "Sequence"};

    // Rules
    parser.add_rule({10, nt_builtin, {t_int}});
    parser.add_rule({20, nt_userdef, {t_type, t_assign, t_type}});

    // Tag
    parser.add_rule({30, nt_tag, {t_lbrk, t_num, t_rbrk}});
    parser.add_rule({31, nt_tag, {t_lbrk, t_app, t_num, t_rbrk}});
    parser.add_rule({32, nt_tag, {t_lbrk, t_priv, t_num, t_rbrk, t_imp}});

    // TaggedType ([0] INTEGER, [0] Name)
    parser.add_rule({40, nt_taggedtype, {nt_tag, t_int}});
    parser.add_rule({41, nt_taggedtype, {nt_tag, t_type}});

    // NamedType (name INTEGER, name Name)
    parser.add_rule({50, nt_namedtype, {t_id, t_int}});
    parser.add_rule({51, nt_namedtype, {t_id, t_type}});

    // SequenceElement
    parser.add_rule({60, nt_seq_elem, {nt_builtin}});
    parser.add_rule({61, nt_seq_elem, {nt_namedtype}});
    parser.add_rule({62, nt_seq_elem, {nt_taggedtype}});

    // SequenceBody (Comma 반복)
    bnf_rule seq_body_rule;
    seq_body_rule.rule_id = 70;
    seq_body_rule.lhs = nt_seq_body;
    seq_body_rule.rhs = {nt_seq_elem};
    seq_body_rule.is_repeating = true;
    seq_body_rule.delimiter = t_comma;
    parser.add_rule(seq_body_rule);

    // Sequence
    parser.add_rule({80, nt_seq, {t_seq}});
    parser.add_rule({81, nt_seq, {t_seq, t_lbrc, nt_seq_body, t_rbrc}});

    // ... (테스트 실행 동일)

    // // SequenceBody -> Z_SequenceElement (Comma 반복)
    // bnf_rule seq_body_rule;
    // seq_body_rule.rule_id = 70;
    // seq_body_rule.lhs = nt_seq_body;
    // seq_body_rule.rhs = {nt_seq_elem};
    // seq_body_rule.is_repeating = true;
    // seq_body_rule.delimiter = t_comma;
    // parser.add_rule(seq_body_rule);
    //
    // // Sequence -> SEQUENCE | SEQUENCE { Z_SequenceBody }
    // parser.add_rule({80, nt_seq, {t_seq}}); // 8번 테스트
    //
    // bnf_rule seq_block_rule;
    // seq_block_rule.rule_id = 81;
    // seq_block_rule.lhs = nt_seq;
    // seq_block_rule.rhs = {t_seq, t_lbrc, nt_seq_body, t_rbrc}; // 9번 테스트
    // parser.add_rule(seq_block_rule);

    // === 테스트 벡터 ===
    std::vector<std::pair<std::string, std::vector<bnf_token*>>> test_cases = {
        {"1. name INTEGER", {new bnf_token(TAG_IDENTIFIER, "name"), new bnf_token(TAG_INTEGER, "INTEGER")}},
        {"2. Name ::= VisibleString", {new bnf_token(TAG_TYPE_NAME, "Name"), new bnf_token(TAG_ASSIGN, "::="), new bnf_token(TAG_TYPE_NAME, "VisibleString")}},
        {"3. [0]", {new bnf_token(TAG_LBRACKET, "["), new bnf_token(TAG_NUMBER, "0"), new bnf_token(TAG_RBRACKET, "]")}},
        {"4. [APPLICATION 1]",
         {new bnf_token(TAG_LBRACKET, "["), new bnf_token(TAG_CLASS_APP, "APPLICATION"), new bnf_token(TAG_NUMBER, "1"), new bnf_token(TAG_RBRACKET, "]")}},
        {"5. [PRIVATE 5] IMPLICIT",
         {new bnf_token(TAG_LBRACKET, "["), new bnf_token(TAG_CLASS_PRIV, "PRIVATE"), new bnf_token(TAG_NUMBER, "5"), new bnf_token(TAG_RBRACKET, "]"),
          new bnf_token(TAG_IMPLICIT, "IMPLICIT")}},
        {"6. [0] INTEGER", {new bnf_token(TAG_LBRACKET, "["), new bnf_token(TAG_NUMBER, "0"), new bnf_token(TAG_RBRACKET, "]"), new bnf_token(TAG_INTEGER, "INTEGER")}},
        {"7. name Name", {new bnf_token(TAG_IDENTIFIER, "name"), new bnf_token(TAG_TYPE_NAME, "Name")}},
        {"8. SEQUENCE", {new bnf_token(TAG_SEQUENCE, "SEQUENCE")}},
        {"9. SEQUENCE { name INTEGER, [0] Name }",
         {new bnf_token(TAG_SEQUENCE, "SEQUENCE"), new bnf_token(TAG_LBRACE, "{"), new bnf_token(TAG_IDENTIFIER, "name"), new bnf_token(TAG_INTEGER, "INTEGER"),
          new bnf_token(TAG_COMMA, ","), new bnf_token(TAG_LBRACKET, "["), new bnf_token(TAG_NUMBER, "0"), new bnf_token(TAG_RBRACKET, "]"),
          new bnf_token(TAG_TYPE_NAME, "Name"), new bnf_token(TAG_RBRACE, "}")}}};

    // 파싱 실행
    for (const auto& tc : test_cases) {
        size_t consumed = 0;
        std::string matched_symbol;
        bool ok = parser.reduce_sequence(tc.second, 0, consumed, matched_symbol);

        std::cout << "Input: " << tc.first << "\n";
        if (ok && consumed == tc.second.size()) {
            std::cout << "  -> Result: SUCCESS [" << matched_symbol << "]\n";
        } else {
            std::cout << "  -> Result: FAILED\n";
        }
        std::cout << "--------------------------------------\n";

        for (auto t : tc.second) delete t;
    }
#endif
}

void testcase_parser() {
    test_dump_testdata();
    test_parser_sample();
    test_parser_options();
    test_parser_search();
    test_parser_compare();
    test_multipattern_search();
    test_patterns();
    test_asn1parser1();
    test_asn1parser2();
}
