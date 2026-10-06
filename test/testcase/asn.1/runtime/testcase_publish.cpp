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

#include <hotplace/test/testcase/asn.1/sample.hpp>

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
 *       ├── Loader
 *       └── C++ generator
 */

void test_publish_babystep() {
    _test_case.begin("publish");
    /**
     *  Type1 ::= VisibleString
     *
     *  [000] line 1 type 267(usertype) index 0 pos 0 len 5 line 1 (Type1)
     *  [001] line 1 type 260(assign) index 1 pos 6 len 3 line 1 (::=)
     *  [002] line 1 type 4118(VisibleString) index 2 pos 10 len 13 line 1 (VisibleString)
     *  LALR(1) Dynamic Parsing Execution Trace
     *  state stack           token             action
     *  -------------------------------------------------------------------------------------------------------------------------------------
     *  [ 0 ]                 Type1 (usertype)  ACTION[0:usertype] shift -> State 54
     *  [ 0 54 ]              ::=               ACTION[54:::=] reduce -> Rule 8 (DefinedType) RHS[1] -> GOTO[0:DefinedType] -> state 13
     *  [ 0 13 ]              ::=               ACTION[13:::=] shift -> State 60
     *  [ 0 13 60 ]           VisibleString     ACTION[60:VisibleString] shift -> State 51
     *  [ 0 13 60 51 ]        $                 ACTION[51:$] reduce -> Rule 76 (SimpleTypeSpec) RHS[1] -> GOTO[60:SimpleTypeSpec] -> state 37
     *  [ 0 13 60 37 ]        $                 ACTION[37:$] reduce -> Rule 9 (Type) RHS[1] -> GOTO[60:Type] -> state 112
     *  [ 0 13 60 112 ]       $                 ACTION[112:$] reduce -> Rule 6 (TypeAssignment) RHS[3] -> GOTO[0:TypeAssignment] -> state 45
     *  [ 0 45 ]              $                 ACTION[45:$] reduce -> Rule 5 (Assignment) RHS[1] -> GOTO[0:Assignment] -> state 2
     *  [ 0 2 ]               $                 ACTION[2:$] reduce -> Rule 1 (Statement) RHS[1] -> GOTO[0:Statement] -> state 38
     *  [ 0 38 ]              $                 ACTION[38:$] accept
     *  -------------------------------------------------------------------------------------------------------------------------------------
     *  parse tree - re-trace
     *  [000] shift  usertype (Type1)
     *  [001] reduce DefinedType RHS [1]
     *  [002] shift  ::=
     *  [003] shift  VisibleString
     *  [004] reduce SimpleTypeSpec RHS [1]
     *  [005] reduce Type RHS [1]
     *  [006] reduce TypeAssignment RHS [3]
     *  [007] reduce Assignment RHS [1]
     *  [008] reduce Statement RHS [1]
     *  parse tree - graph
     *  Statement
     *    Assignment
     *      TypeAssignment
     *        DefinedType
     *          usertype (Type1)
     *        ::=
     *        Type
     *          SimpleTypeSpec
     *            VisibleString
     *
     */

    parse_tree pt;
    pt.on_shift("usertype", "Type1");
    pt.on_reduce("DefinedType", 1);
    pt.on_shift("::=", "::=");
    pt.on_shift("VisibleString", "VisibleString");
    pt.on_reduce("SimpleTypeSpec", 1);
    pt.on_reduce("Type", 1);
    pt.on_reduce("TypeAssignment", 3);
    pt.on_reduce("Assignment", 1);
    pt.on_reduce("Statement", 1);

    dump_parse_tree(&pt);

    basic_stream bs;
    asn1_build_resultset result;
    auto publisher = asn1_resource::get_instance()->get_publisher();
    publisher->build(&pt, result);
    if (result.object) {
        result.object->publish(&bs);
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

    asn1_runtime runtime;  // automatic, share lexical_context

    for (const auto& entry : table) {
        parse_reconst_notation(&runtime, entry.notation);
    }
}

void test_publish_constraints() {
    _test_case.begin("publish");
    struct testvector {
        const char* notation;
        const char* expect;
    } table[] = {
        {R"(Type1 ::= INTEGER (1))"},
        {R"(Type2 ::= INTEGER (1 | 2))"},
        {R"(Type3 ::= INTEGER (1 | 2 | 3 | 6))"},
        {R"(Type4 ::= VisibleString ("A" | "B" | "C" | "D"))"},
        {R"(Type5 ::= INTEGER (1..10 | 20..30))"},
        {R"(Type6 ::= INTEGER ((1..100) INTERSECTION (50..200)))"},
        {R"(Type7 ::= INTEGER (1..100 EXCEPT 50))"},
        {R"(Type8 ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25)))"},
        {R"(Type9 ::= INTEGER (1..50 EXCEPT 20..30))"},
        {R"(Type10 ::= INTEGER (ALL EXCEPT 1..10))"},
        {R"(Type11 ::= INTEGER ((1..100) INTERSECTION (10..50 | 60..90)))"},
        {R"(Type12 ::= INTEGER (1..100 EXCEPT (20 | 30 | 40)))"},
        {R"(Flags ::= BIT STRING (SIZE(8)))"},
        {R"(Oct1 ::= OCTET STRING (SIZE(16)))"},
        {R"(Temperature ::= REAL (0.0..100.0))"},
        {R"(Positive ::= REAL (0.0..MAX))"},
        {R"(Negative ::= REAL (MIN..0.0))"},
        {R"(Real1 ::= REAL (0.0..100.0 EXCEPT 50.0))"},
        {R"(Name1 ::= IA5String (SIZE(1)))"},
        {R"(Name2 ::= IA5String (SIZE(1 | 2 | 5)))"},
        {R"(Name3 ::= IA5String (SIZE(1..20)))"},
        {R"(Name4 ::= IA5String (FROM ("ABC")))"},
        {R"(Name5 ::= IA5String (FROM ("ABCDEF") SIZE(4)))"},  // FROM + SIZE
        {R"(Name6 ::= IA5String (SIZE(1..10 | 20..30)))"},
        {R"(Numbers ::= SEQUENCE SIZE(1..4) OF INTEGER)"},
        {R"(Tags ::= SET SIZE(2..4) OF IA5String)"},
        {R"(Color ::= ENUMERATED {red(0), green(1), blue(2)})"},

        {R"(Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))})"},
        {R"(PhoneNumber ::= UTF8String (PATTERN "[0-9]{3}-[0-9]{4}-[0-9]{4}"))"},

        /* struct field constraints */
        {R"(ComplexSeq ::= SEQUENCE {id INTEGER (1..MAX), code OCTET STRING (SIZE(4 | 8)), description UTF8String (SIZE(1..255) PATTERN "[a-zA-Z0-9]+") OPTIONAL})"},
        /* deep nesting */
        {R"(Nested1 ::= INTEGER (((1..10))))", R"(Nested1 ::= INTEGER (1..10))"},
        {R"(Nested2 ::= IA5String ((SIZE(1..10) INTERSECTION FROM("ABC"))))", R"(Nested2 ::= IA5String (SIZE(1..10) INTERSECTION FROM ("ABC")))"},

        {R"(TypeInclusive ::= INTEGER (0..100))"},     // [0, 100]
        {R"(TypeExclusive1 ::= INTEGER (0..<100))"},   // [0, 100)
        {R"(TypeExclusive2 ::= INTEGER (0<..100))"},   // (0, 100]
        {R"(TypeExclusive3 ::= INTEGER (0<..<100))"},  // (0, 100)
        {R"(TypeExclusive4 ::= REAL (0.0..<1.0))"},

        {R"(Name7 ::= IA5String (FROM ("A".."Z")))"},
        {R"(Name8 ::= IA5String (FROM ("A".."Z" | "a".."z" | "0".."9")))"},
        {R"(Name9 ::= IA5String (FROM ("A"<.."Z")))"},
        {R"(Name10 ::= IA5String (FROM ("A"..<"Z")))"},
        {R"(Name11 ::= IA5String (FROM ("A"<..<"Z")))"},
        {R"(Name12 ::= IA5String (FROM ("A"<..<"Z" | "a".."z")))"},
    };

    asn1_runtime runtime;     // automatic
    lexical_context context;  // share usertype

    for (const auto& entry : table) {
        parse_reconst_notation(&runtime, entry.notation, entry.expect);
    }
}

void testcase_publish() {
    test_publish_babystep();
    test_publish_basics();
    test_publish_constraints();
}
