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

void test_publish_babystep() {
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

void test_publish_basics() {
    _test_case.begin("publish");

    struct testvector {
        const char* notation;
    } table[] = {
        {"Type1 ::= VisibleString"},
        {"Type2 ::= [APPLICATION 3] IMPLICIT Type1"},
        {"Type3 ::= [2] EXPLICIT Type2"},
        {"Type4 ::= [APPLICATION 7] IMPLICIT Type3"},
        {"Type5 ::= [2] IMPLICIT Type2"},
        {"Int1 ::= INTEGER"},
        {"BitStr1 ::= BIT STRING"},
        {"OctStr1 ::= OCTET STRING"},
        {"Null1 ::= NULL"},
        {"Real1 ::= REAL"},
        {"Oid1 ::= OBJECT IDENTIFIER"},
        {"Oid1 ::= OBJECT IDENTIFIER"},
        {"Time1 ::= UTCTime"},
        {"Time2 ::= GeneralizedTime"},

        // - "Field"
        // - "FieldList"
        //   - sketch : asn1_unknown_container
        // - "StatementSequence"
        //   - sketch : sequence->set(std::move(*unknown_container));

        {"Seq1 ::= SEQUENCE {name VisibleString}"},
        {"Seq2 ::= SEQUENCE {name VisibleString, ok BOOLEAN}"},
        {"Numbers ::= SEQUENCE OF INTEGER"},
        {"Names ::= SEQUENCE OF VisibleString"},
        {"Outer1 ::= SEQUENCE {Inner SEQUENCE {name VisibleString}}"},
        {"Outer2 ::= SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}}"},
        {"Outer3 ::= SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}}"},

        {"Set1 ::= SET {z BOOLEAN, a INTEGER}"},
        {"IntSet ::= SET OF INTEGER"},
        {"TaggedSeq ::= [APPLICATION 10] IMPLICIT SEQUENCE {id INTEGER}"},

        // "EnumList"
        {"Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}"},
        {"Flags ::= BIT STRING {read(0), write(1), execute(2)}"},
        {"Color ::= ENUMERATED {red(0), green(1), blue(2)}"},
        {"Person ::= SEQUENCE {name VisibleString, color ENUMERATED {red(0), green(1), blue(2)}}"},

        // CHOICE
        {"Value1 ::= CHOICE {i INTEGER, s VisibleString}"},
        {"Value2 ::= [0] EXPLICIT CHOICE {i INTEGER, s VisibleString}"},
        {"Person1 ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}}"},
        {"Value ::= CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString}"},
        {"Person2 ::= SEQUENCE {firstName VisibleString, lastName VisibleString}"},

        // DEFAULT, OPTIONAL
        {"SeqOpt ::= SEQUENCE {id INTEGER, optField VisibleString OPTIONAL, defField INTEGER DEFAULT 10}"},
        // ANY
        {"Test ::= SEQUENCE {id INTEGER, data ANY}"},

        // testcase_basic2.cpp
        {"SEQUENCE {name VisibleString, ok BOOLEAN}"},
        {"SET {a INTEGER, b BOOLEAN}"},
        {"SET OF VisibleString"},
        {"long VisibleString"},
        {"MultiByteTag1 ::= [APPLICATION 128] IMPLICIT INTEGER"},
        {"MultiByteTag2 ::= [APPLICATION 201] IMPLICIT INTEGER"},
        {"SEQUENCE {}"},
        {"SEQUENCE {name [0] IMPLICIT VisibleString}"},
    };

    asn1_runtime runtime;     // automatic
    lexical_context context;  // share usertype

    for (const auto& entry : table) {
        parse_reconst_notation(&runtime, context, entry.notation);
    }
}

void test_publish_constraints() {
    _test_case.begin("publish");
    struct testvector {
        const char* notation;
    } table[] = {
        {"Type1 ::= INTEGER (1)"},
        {"Type2 ::= INTEGER (1 | 2)"},
        {"Type3 ::= INTEGER (1 | 2 | 3 | 6)"},
        // {R"(Type4 ::= VisibleString ("A" | "B" | "C" | "D"))"},  -- still bug
        {"Type5 ::= INTEGER (1..10 | 20..30)"},
        // {"Type6 ::= INTEGER ((1..100) INTERSECTION (50..200))"},  -- still bug
    };

    asn1_runtime runtime;     // automatic
    lexical_context context;  // share usertype

    for (const auto& entry : table) {
        parse_reconst_notation(&runtime, context, entry.notation);
    }
}

void testcase_publish() {
    test_publish_babystep();
    test_publish_basics();
    test_publish_constraints();  // babystep
}
