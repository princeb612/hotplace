/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/test/testcase/io/sample.hpp>

#include "asn1_cfg_parameterized.hpp"
#include "asn1module.hpp"

/**
 * CFG ASN.1 Noation
 * - LALR(1)
 * - GLR(1)
 *
 * incubate ASN.1 parameterized, module, information object class
 * - tests related to the `module` and `information object class` have been moved to `testcase/asn.1`, where the `*.asn1` files are located.
 */

void test_lalr_asn1notation() {
    // return_t ret = errorcode_t::success;

    struct testvector {
        const char* notation;
    };

    // [NOTE] LHS is always camelcase no lowercase (cf. usertype)
    testvector table[] = {
        // Assignment
        {R"(Type1 ::= VisibleString)"},
        {R"(Type2 ::= [APPLICATION 3] IMPLICIT Type1)"},
        {R"(Type3 ::= [2] EXPLICIT Type2)"},
        {R"(Type4 ::= [APPLICATION 7] IMPLICIT Type3)"},
        {R"(Type5 ::= [2] IMPLICIT Type2)"},
        {R"(Type6 ::= [2] EXPLICIT Type1)"},
        {R"(Type7 ::= [1] EXPLICIT Type1)"},
        {R"(Type8 ::= [2] EXPLICIT Type7)"},
        {R"(Type9 ::= [3] EXPLICIT Type8)"},
        {R"(Real1 ::= REAL)"},
        {R"(Product ::= SEQUENCE {id VisibleString})"},
        {R"(Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)})"},
        {R"(Flags ::= BIT STRING {read(0), write(1), execute(2)})"},
        {R"(Flags2 ::= BIT STRING)"},
        {R"(Data ::= OCTET STRING)"},
        {R"(Oid ::= OBJECT IDENTIFIER)"},
        {R"(RelOid ::= RELATIVE-OID)"},
        {R"(Time1 ::= UTCTime)"},
        {R"(Time2 ::= GeneralizedTime)"},
        {R"(Color ::= ENUMERATED {red(0), green(1), blue(2)})"},
        {R"(Type ::= SEQUENCE {})"},
        {R"(Seq1 ::= SEQUENCE {name VisibleString, ok BOOLEAN})"},
        {R"(Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString})"},
        {R"(Person3 ::= SEQUENCE {name VisibleString, age INTEGER DEFAULT 20})"},
        {R"(Outer1 ::= SEQUENCE {inner SEQUENCE {name VisibleString}})"},
        {R"(Outer2 ::= SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}})"},
        {R"(Outer ::= SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}})"},
        {R"(Numbers ::= SEQUENCE OF INTEGER)"},
        {R"(Set1 ::= SET {z BOOLEAN, a INTEGER})"},
        {R"(Value ::= CHOICE {i INTEGER, s VisibleString})"},
        {R"(Value2 ::= CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString})"},
        {R"(Value3 ::= [0] EXPLICIT CHOICE {i INTEGER, s VisibleString})"},
        {R"(Person ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}})"},
        {R"(Test ::= SEQUENCE {id INTEGER, data ANY})"},
        {R"(OptTest ::= SEQUENCE {name VisibleString, title [0] VisibleString OPTIONAL})"},
        // Constraints
        {R"(Type ::= INTEGER (1))"},
        {R"(Type ::= INTEGER (1 | 2))"},
        {R"(Type ::= INTEGER (1 | 2 | 3 | 6))"},
        {R"(Type ::= VisibleString ("A" | "B" | "C" | "D"))"},
        {R"(Type ::= INTEGER (1..10 | 20..30))"},
        {R"(Type ::= INTEGER ((1..100) INTERSECTION (50..200)))"},
        {R"(Type ::= INTEGER (1..100 EXCEPT 50))"},
        {R"(Type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25)))"},
        {R"(Temperature ::= REAL (0.0..100.0))"},
        {R"(Positive ::= REAL (0.0..MAX))"},
        {R"(Negative ::= REAL (MIN..0.0))"},
        {R"(Type ::= REAL (0.0..100.0 EXCEPT 50.0))"},
        {R"(Name ::= IA5String (SIZE(1)))"},
        {R"(Name ::= IA5String (SIZE(1 | 2 | 5)))"},
        {R"(Name ::= IA5String (SIZE(1..20)))"},
        {R"(Type ::= INTEGER (1..50 EXCEPT 20..30))"},
        {R"(Type ::= INTEGER (ALL EXCEPT 1..10))"},
        {R"(Type ::= INTEGER (0..255))"},
        {R"(Type ::= OCTET STRING (SIZE(16)))"},
        {R"(Name ::= IA5String (FROM ("ABC")))"},
        {R"(Numbers ::= SEQUENCE SIZE(1..4) OF INTEGER)"},
        {R"(Flags ::= BIT STRING (SIZE(8)))"},
        {R"(Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))})"},
        {R"(ShortString ::= IA5String (SIZE (1..10)))"},
        {R"(ExactBuffer ::= OCTET STRING (SIZE (16)))"},
        {R"(RestrictedInt ::= INTEGER (1..100))"},
        {R"(LimitedInt ::= INTEGER (MIN..1000))"},
        {R"(MultiSize ::= OCTET STRING (SIZE (1..10, 20..30)))"},
        {R"(PhoneNumber ::= UTF8String (PATTERN "[0-9]{3}-[0-9]{4}-[0-9]{4}"))"},
        // clang-format off
        {R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {name Name, title [0] VisibleString, number EmployeeNumber, dateOfHire [1] Date, nameOfSpouse [2] Name, children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}})"},
        // clang-format on
        {R"(ChildInformation ::= SET { name Name, dateOfBirth [0] Date})"},
        {R"(Name ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString})"},
        {R"(EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER)"},
        {R"(Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)"},
        // non-assignment
        {R"(VisibleString)"},
        {R"([APPLICATION 3] IMPLICIT Type1)"},
        {R"([2] EXPLICIT Type2)"},
        {R"(REAL)"},
        {R"(SEQUENCE {id VisibleString})"},
        {R"(INTEGER {homeOffice(0), fieldOffice(1), roving(2)})"},
        {R"(BIT STRING {read(0), write(1), execute(2)})"},
        {R"(BIT STRING)"},
        {R"(OCTET STRING)"},
        {R"(OBJECT IDENTIFIER)"},
        {R"(RELATIVE-OID)"},
        {R"(UTCTime)"},
        {R"(GeneralizedTime)"},
        {R"(ENUMERATED {red(0), green(1), blue(2)})"},
        {R"(SEQUENCE {})"},
        {R"(SEQUENCE {name VisibleString, ok BOOLEAN})"},
        {R"(SEQUENCE {name [0] IMPLICIT VisibleString})"},
        {R"(SEQUENCE {name VisibleString, age INTEGER DEFAULT 20})"},
        {R"(SEQUENCE {inner SEQUENCE {name VisibleString}})"},
        {R"(SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}})"},
        {R"(SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}})"},
        {R"(SEQUENCE OF INTEGER)"},
        {R"(SET {z BOOLEAN, a INTEGER})"},
        {R"(CHOICE {i INTEGER, s VisibleString})"},
        {R"(CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString})"},
        {R"([0] EXPLICIT CHOICE {i INTEGER, s VisibleString})"},
        {R"(SEQUENCE {id CHOICE {num INTEGER, name VisibleString}})"},
        {R"(SEQUENCE {id INTEGER, data ANY})"},
        {R"(SEQUENCE {name VisibleString, title [0] VisibleString OPTIONAL})"},
        {R"(SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))})"},
        {R"([APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString})"},
        //
        {R"(SET OF INTEGER)"},
        {R"(Names ::= SET OF VisibleString)"},
        {R"(SET OF VisibleString)"},
        {R"(Numbers ::= SET OF INTEGER)"},
        //
        {R"(name VisibleString)"},
        {R"([APPLICATION 30])"},
    };

    auto lambda_test = [&table](parser_t& parser) -> void {
        for (const auto& entry : table) {
            test_asn1parser(parser, entry.notation, entry.notation);
        }
    };
    _test_case.begin("LALR(1) parser - ASN.1 for Notation");
    auto& p1 = get_lalr1_parser_asn1_notation_by_build();
    _test_case.assert(p1.ready(), __FUNCTION__, "LALR(1) parser build table for Notation");
    lambda_test(p1);
    _test_case.begin("LALR(1) parser - ASN.1 for Notation (imported)");
    auto& p2 = get_lalr1_parser_asn1_notation_by_import();
    _test_case.assert(p2.ready(), __FUNCTION__, "LALR(1) parser import table for Notation");
    lambda_test(p2);
    _test_case.begin("GLR parser - ASN.1 for All-in-One");
    auto& p3 = get_glr_parser_asn1_by_build();
    _test_case.assert(p3.ready(), __FUNCTION__, "GLR parser build table for Notation, Module, Parameterized, Information Object Class");
    lambda_test(p3);
    _test_case.begin("GLR parser - ASN.1 for All-in-One (imported)");
    auto& p4 = get_glr_parser_asn1_by_import();
    _test_case.assert(p4.ready(), __FUNCTION__, "GLR parser import table for Notation, Module, Parameterized, Information Object Class");
    lambda_test(p4);
}

void test_lalr_asn1parameterized() {
    // return_t ret = errorcode_t::success;

    enum test_flag_t : uint16 {
        item_asn1param = 1 << 0,
        item_asn1ioc = 1 << 1,
    };
    struct testvector {
        uint16 flag;
        const char* notation;
    };

    testvector table[] = {
        // parameterized assignment
        {item_asn1param | item_asn1ioc, R"(Envelope {TypeParam} ::= SEQUENCE {version INTEGER, payload TypeParam})"},
        {item_asn1param | item_asn1ioc, R"(KeyValuePair {KeyType, ValueType} ::= SEQUENCE {key KeyType, value ValueType})"},
        {item_asn1param | item_asn1ioc,
         R"(BoundedArray {ElementType, INTEGER : MaxSize} ::= SEQUENCE {length INTEGER (0..MaxSize), elements SEQUENCE (SIZE(1..MaxSize)) OF ElementType})"},

        // parameterized type reference
        {item_asn1param | item_asn1ioc, R"(IntegerEnvelope ::= Envelope {INTEGER})"},
        {item_asn1param | item_asn1ioc, R"(OctetEnvelope ::= Envelope {OCTET STRING})"},
        {item_asn1param | item_asn1ioc, R"(StringToIntMap ::= KeyValuePair {UTF8String, INTEGER})"},
        {item_asn1param | item_asn1ioc, R"(NestedMap ::= KeyValuePair {UTF8String, KeyValuePair {INTEGER, OCTET STRING}})"},
        {item_asn1param | item_asn1ioc, R"(SmallIntArray ::= BoundedArray {INTEGER, 10})"},
        {item_asn1param | item_asn1ioc, R"(LargeStringArray ::= BoundedArray {PrintableString, 256})"},

        // information object class
        {item_asn1ioc, R"(CAPABILITY-SET ::= CLASS {&id INTEGER UNIQUE, &Type} WITH SYNTAX {&Type IDENTIFIED BY &id})"},
        {item_asn1ioc,
         R"(GenericMessage {CAPABILITY-SET : SupportedSet} ::= SEQUENCE {messageId CAPABILITY-SET.&id ({SupportedSet}), content CAPABILITY-SET.&Type ({SupportedSet}{@messageId})})"},
        {item_asn1ioc, R"(MyMessage ::= GenericMessage {MyCapabilitySet})"},
    };

    auto lambda_test = [&table](test_flag_t flag, parser_t& parser) -> void {
        for (const auto& entry : table) {
            if (entry.flag & flag) test_asn1parser(parser, entry.notation, entry.notation);
        }
    };
    _test_case.begin("GLR parser - ASN.1 for parametersized");
    auto& p1 = get_glr_parser_asn1_paramerized_by_build();
    _test_case.assert(p1.ready(), __FUNCTION__, "LALR(1) parser build table for Parameterized");
    lambda_test(item_asn1param, p1);
    _test_case.begin("GLR parser - ASN.1 All-in-One");
    auto& p2 = get_glr_parser_asn1_by_build();
    _test_case.assert(p2.ready(), __FUNCTION__, "GLR parser build table for Notation, Module, Parameterized, Information Object Class");
    lambda_test(item_asn1ioc, p2);
}

void testcase_parser() {
    test_lalr_asn1notation();
    test_lalr_asn1parameterized();
}
