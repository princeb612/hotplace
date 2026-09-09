/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_publish.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include "sample.hpp"

/**
 * GPT review
 *
 * [sandbox] The stage of experimenting with semantic construction without breaking existing parser tests.
 *
 *   ASN.1 notation
 *       │
 *       │ LALR parse
 *       ▼
 *   parse tree
 *       │
 *       │ semantic construction
 *       ▼
 *   asn1_runtime
 *       │
 *       │ schema/type lookup
 *       ▼
 *   runtime ASN.1 object
 *       │
 *       ├── encode
 *       ├── decode
 *       └── strongly typed object
 *
 * after the semantic construction experiment is completed, this will be integrated into asn1_strongly_typed/asn1_parser.
 * the resulting runtime object model can then serve as the basis for c++ source generation.
 *
 *   runtime ASN.1 object
 *       │
 *       ▼
 *   C++ generator
 *       │
 *       ▼
 *   C++ source
 */

void test_construct_babystep() {
    _test_case.begin("publish");
    /**
     *  Type1 ::= VisibleString
     *
     *  [000] line 1 type 36(usertype) index 0 pos 0 len 5 (Type1)
     *  [001] line 1 type 13(assign) index 1 pos 6 len 3 (::=)
     *  [002] line 1 type 4124(VisibleString) index 2 pos 10 len 13 (VisibleString)
     *  LALR(1) Dynamic Parsing Execution Trace
     *  state stack           token             action
     *  -----------------------------------------------------------------------------
     *  [ 0 ]                 Type1 (usertype)  shift -> State 55
     *  [ 0 55 ]              ::=               reduce -> Rule 8 (DefinedType) RHS[1]
     *  [ 0 13 ]              ::=               shift -> State 79
     *  [ 0 13 79 ]           VisibleString     shift -> State 52
     *  [ 0 13 79 52 ]        $                 reduce -> Rule 90 (SimpleType) RHS[1]
     *  [ 0 13 79 33 ]        $                 reduce -> Rule 51 (TypeBase) RHS[1]
     *  [ 0 13 79 46 ]        $                 reduce -> Rule 44 (TypeSpec) RHS[1]
     *  [ 0 13 79 126 ]       $                 reduce -> Rule 6 (Assignment) RHS[3]
     *  [ 0 3 ]               $                 reduce -> Rule 1 (Statement) RHS[1]
     *  [ 0 34 ]              $                 accept
     *  -----------------------------------------------------------------------------
     *  parse tree - re-trace
     *  [000] shift  usertype (Type1)
     *  [001] reduce DefinedType RHS [1]
     *  [002] shift  ::=
     *  [003] shift  VisibleString
     *  [004] reduce SimpleType RHS [1]
     *  [005] reduce TypeBase RHS [1]
     *  [006] reduce TypeSpec RHS [1]
     *  [007] reduce Assignment RHS [3]
     *  [008] reduce Statement RHS [1]
     *  parser tree - graph
     *  Statement
     *    Assignment
     *      DefinedType
     *        usertype (Type1)
     *      ::=
     *      TypeSpec
     *        TypeBase
     *          SimpleType
     *            VisibleString
     */
    parse_tree pt;
    pt.on_shift("usertype", "Type1");
    pt.on_reduce("DefinedType", 1);
    pt.on_shift("::=", "::=");
    pt.on_shift("VisibleString", "VisibleString");
    pt.on_reduce("SimpleType", 1);
    pt.on_reduce("TypeBase", 1);
    pt.on_reduce("TypeSpec", 1);
    pt.on_reduce("Assignment", 3);
    pt.on_reduce("Statement", 1);

    dump_parse_tree(nullptr, &pt);

    basic_stream bs;
    asn1_object* obj = nullptr;
    asn1_builder::build(&pt, &obj);
    if (obj) {
        obj->publish(&bs);
        obj->release();
    }
    _logger->writeln("parse and publish %s", bs.c_str());
    _test_case.assert(bs == "Type1 ::= VisibleString", __FUNCTION__, "first baby step");
}

void test_publish() {
    _test_case.begin("publish");

    struct testvector {
        const char* notation;
    } table[] = {
        {"Type1 ::= VisibleString"},
        {"Type2 ::= [APPLICATION 3] IMPLICIT Type1"},
        {"Type3 ::= [2] EXPLICIT Type2"},
        {"Type4 ::= [APPLICATION 7] IMPLICIT Type3"},
        {"Type5 ::= [2] IMPLICIT Type2"},
        {"Null1 ::= NULL"},
        {"Real1 ::= REAL"},
        {"Oid1 ::= OBJECT IDENTIFIER"},
        {"RelOid1 ::= RELATIVE-OID"},

        // TODO
        // - "Field"
        // - "FieldList"
        //   - sketch : asn1_unknown_container
        // - "StatementSequence"
        //   - sketch : auto container = new asn1_sequence(std::move(unknown_container));

        // {"Seq1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}"},
        // {"Outer ::= SEQUENCE {Inner SEQUENCE {name VisibleString}}"},
    };

    asn1_runtime runtime;     // automatic
    lexical_context context;  // share usertype
    auto parser = asn1_parser::get_instance();

    for (const auto& entry : table) {
        parse_tree pt;
        parser->parse(&runtime, context, entry.notation, &pt);
        dump_parse_tree(&runtime, &pt);

        {
            basic_stream bs;
            asn1_object* obj = nullptr;
            asn1_builder::build(&pt, &obj);
            if (obj) {
                obj->publish(&bs);
                obj->release();
            }
            _logger->writeln("parse and publish %s", bs.c_str());
            _test_case.assert(bs == entry.notation, __FUNCTION__, "test %s", entry.notation);
        }
    }
}

void testcase_publish() {
    test_construct_babystep();
    test_publish();
}
