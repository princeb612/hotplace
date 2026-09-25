/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_lexer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/test/testcase/io/sample.hpp>

#include "asn1module.hpp"

void test_lexer_options() {
    _test_case.begin("lexical analyzer");
    struct testvector {
        const char* notation;
        size_t tokens;
        uint32 first;
        int16 handle_comments;
        int16 handle_lvalue_usertype;
    } table[] = {
        {R"(Type ::= VisibleString ("A" | "B" | "C" | "D"))", 12, token_lvalue, 0, 0},             //
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 8, token_lvalue, 0},                            // "--" as comments, cf. prepare_lexer_asn1
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 6, token_lvalue, 1},                            // "-- empty SEQUENCE" as comments
        {"Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN} -- SEQUENCE", 12, token_lvalue, 0},  //
        {"Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN} -- SEQUENCE", 11, token_lvalue, 1},  // "-- SEQUENCE" as comments
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 6, token_usertype, 1, 1},                       // Type (usertype not lvalue)
        {"Name ::= VisibleString", 3, token_usertype, 1, 1},                                       // Name (usertype not lvalue)
        {"Type1 ::= SEQUENCE {name Name, ok BOOLEAN} -- SEQUENCE", 11, token_usertype, 1, 1},      // Type1, Name (usertype)
        {"Name2 ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString}", 18, token_usertype, 1, 1},
        {"Type ::= INTEGER (1..10 | 20..30)", 12, token_lvalue, 0, 0},
    };

    lexical_analyzer lexer;  // shares context to test previously defined usertype
    lexical_context context;

    for (const auto& entry : table) {
        _logger->colorln(entry.notation);

        // usertype already in dictionary, reset it first
        prepare_lexer_asn1(lexer);
        lexer.get_config().set("handle_comments", entry.handle_comments).set("handle_lvalue_usertype", entry.handle_lvalue_usertype);

        auto test = lexer.parse(context, entry.notation, strlen(entry.notation));

        uint32 cnt = 0;
        uint32 first = token_unknown;
        auto dump_handler = [&lexer, &cnt, &first](const token_description* desc) -> bool {
            if (0 == cnt) first = desc->type;
            _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lexer.nameof_token(desc->type).c_str(),
                             desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
            return true;
        };
        context.for_each(dump_handler);
        _test_case.test(test, __FUNCTION__, "parse usertype");
        _test_case.assert(entry.tokens == cnt, __FUNCTION__, "handle_comments %i handle_lvalue_usertype %i %i tokens", entry.handle_comments,
                          entry.handle_lvalue_usertype, cnt);
        _test_case.assert(entry.first == first, __FUNCTION__, "first token type %s", lexer.nameof_token(first).c_str());
    }
}

void test_lexer() {
    _test_case.begin("lexical analyzer");

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

    lexical_analyzer lexer;
    lexical_context context;

    lexer.prepare();

    _logger->colorln("basic tokens + handle_lvalue_usertype 0");
    lexer.parse(context, asn1_structure, strlen(asn1_structure));
    uint32 cnt = 0;

    auto dump_handler = [&lexer, &cnt](const token_description* desc) -> bool {
        _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lexer.nameof_token(desc->type).c_str(),
                         desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
        return true;
    };

    context.for_each(dump_handler);
    _test_case.assert(105 == cnt, __FUNCTION__, "tokenize");

    // load ASN.1 tokens
    _logger->colorln("ASN.1 tokens + handle_lvalue_usertype 1");
    prepare_lexer_asn1(lexer);
    lexer.get_config().set("handle_lvalue_usertype", 1);

    lexer.add_token("::=", token_assign).add_token("--", token_comments);
    lexer.parse(context, asn1_structure, strlen(asn1_structure));
    cnt = 0;
    context.for_each(dump_handler);
    _test_case.assert(93 == cnt, __FUNCTION__, "tokenize");
}

void testcase_lexer() {
    test_lexer_options();
    test_lexer();
}
