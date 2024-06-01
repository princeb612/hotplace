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
 *
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

#include "parser.hpp"

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

/*
 */

void test_parser() {
    constexpr char example1[] =
        R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
            Name Name,
            title [0] VisibleString,
            number EmployeeNumber,
            dateOfHire [1] Date,
            nameOfSpouse [2] Name,
            children [3] IMPLICIT
                SEQUENCE OF ChildInformation DEFAULT {} }

            ChildInformation ::= SET
                { name Name,
                dateOfBirth [0] Date}

            Name ::= [APPLICATION 1] IMPLICIT SEQUENCE
                { givenName VisibleString,
                initial VisibleString,
                familyName VisibleString}

            EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER

            Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)";

    constexpr char example2[] =
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

    constexpr char example3[] =
        R"(Name ::= SEQUENCE OF RelativeDistinguishedName

            RelativeDistinguishedName ::= SET OF AttributeTypeValue

            AttributeTypeValue ::= SEQUENCE 
            {
               type               OBJECT IDENTIFIER,
               value              ANY 
            })";
    // 1.     30 23            ; SEQUENCE (0x23 = 35 Bytes)
    // 2.     |  |  31 0f            ; SET (f Bytes)
    // 3.     |  |  |  30 0d            ; SEQUENCE (d Bytes)
    // 4.     |  |  |     06 03         ; OBJECT_ID (3 Bytes)
    // 5.     |  |  |     |  55 04 03
    // 6.     |  |  |     |     ; 2.5.4.3 Common Name (CN)
    // 7.     |  |  |     13 06         ; PRINTABLE_STRING (6 Bytes)
    // 8.     |  |  |        54 65 73 74 43 4e                    ; TestCN
    // 9.     |  |  |           ; "TestCN"
    // 10.    |  |  31 10            ; SET (10 Bytes)
    // 11.    |  |     30 0e            ; SEQUENCE (e Bytes)
    // 12.    |  |        06 03         ; OBJECT_ID (3 Bytes)
    // 13.    |  |        |  55 04 0a
    // 14.    |  |        |     ; 2.5.4.10 Organization (O)
    // 15.    |  |        13 07         ; PRINTABLE_STRING (7 Bytes)
    // 16.    |  |           54 65 73 74 4f 72 67                 ; TestOrg
    // 17.    |  |              ; "TestOrg"

    parser p;

    p.add_token("::=", parser_attr_assign)
        .add_token("--", parser_attr_comments)
        .add_token("OBJECT IDENTIFIER")
        .add_token("OCTET STRING")
        .add_token("BIT STRING")
        .add_token("SET OF")
        .add_token("SEQUENCE OF");

    parser_context context1;
    parser_context context2;
    parser_context context3;
    parser_context context4;
    parser_context context5;
    parser_context context6;
    // parse
    p.parse(context1, example1, strlen(example1));
    p.parse(context2, example2, strlen(example2));
    p.parse(context3, example3, strlen(example3));

    // turn off switches and parse
    p.get_config().set("handle_comments", 0);
    p.parse(context4, example1, strlen(example1));
    p.get_config().set("handle_quoted", 0);
    p.parse(context5, example2, strlen(example2));
    p.get_config().set("handle_token", 0);
    p.parse(context6, example3, strlen(example3));

    // learn
    // p.learn();

    // p.apply(context1);

    // dump
    auto dump_handler = [](const token_description* desc) -> void {
        printf("line %zi type %d index %d len %zi (%.*s)\n", desc->line, desc->type, desc->index, desc->size, desc->size, desc->p);
    };
    context1.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #1");
    context2.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #2");
    context3.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #3");
    context4.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #4 (comments off)");
    context5.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #5 (quot off)");
    context6.for_each(dump_handler);
    _test_case.assert(true, __FUNCTION__, "parse #6 (token off)");
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

    test_parser();

    _logger->flush();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
