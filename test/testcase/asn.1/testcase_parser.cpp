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

void test_asn1parser() {
    _test_case.begin("asn1_parser");

    struct testvector {
        const char* notation;
    };

    testvector table[] = {
        // Assignment
        {R"(Type1 ::= VisibleString)"},
        {R"(Type2 ::= [APPLICATION 3] IMPLICIT Type1)"},
        {R"(Type3 ::= [2] EXPLICIT Type2)"},
        {R"(Type1 ::= REAL)"},
        {R"(Product ::= SEQUENCE {id VisibleString})"},
        {R"(Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)})"},
        {R"(Flags ::= BIT STRING {read(0), write(1), execute(2)})"},
        {R"(Flags ::= BIT STRING)"},
        {R"(Data ::= OCTET STRING)"},
        {R"(Oid ::= OBJECT IDENTIFIER)"},
        {R"(RelOid ::= RELATIVE-OID)"},
        {R"(Time ::= UTCTime)"},
        {R"(Time ::= GeneralizedTime)"},
        {R"(Color ::= ENUMERATED {red(0), green(1), blue(2)})"},
        {R"(Type ::= SEQUENCE {})"},
        {R"(Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN})"},
        {R"(Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString})"},
        {R"(Person3 ::= SEQUENCE {name VisibleString, age INTEGER DEFAULT 20})"},
        {R"(Outer1 ::= SEQUENCE {inner SEQUENCE {name VisibleString}})"},
        {R"(Outer2 ::= SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}})"},
        {R"(Outer ::= SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}})"},
        {R"(Numbers ::= SEQUENCE OF INTEGER)"},
        {R"(Type1 ::= SET {z BOOLEAN, a INTEGER})"},
        {R"(Value ::= CHOICE {i INTEGER, s VisibleString})"},
        {R"(Value2 ::= CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString})"},
        {R"(Value3 ::= [0] EXPLICIT CHOICE {i INTEGER, s VisibleString})"},
        {R"(Person ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}})"},
        {R"(Test ::= SEQUENCE {id INTEGER, data ANY})"},
        {R"(OptTest ::= SEQUENCE {name VisibleString, title [0] VisibleString OPTIONAL})"},
        // Constraints
        {R"(type ::= INTEGER (1))"},
        {R"(type ::= INTEGER (1 | 2))"},
        {R"(type ::= INTEGER (1 | 2 | 3 | 6))"},
        {R"(type ::= VisibleString ("A" | "B" | "C" | "D"))"},
        {R"(type ::= INTEGER (1..10 | 20..30))"},
        {R"(type ::= INTEGER ((1..100) INTERSECTION (50..200)))"},
        {R"(type ::= INTEGER (1..100 EXCEPT 50))"},
        {R"(type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25)))"},
        {R"(temperature ::= REAL (0.0..100.0))"},
        {R"(positive ::= REAL (0.0..MAX))"},
        {R"(negative ::= REAL (MIN..0.0))"},
        {R"(type ::= REAL (0.0..100.0 EXCEPT 50.0))"},
        {R"(name ::= IA5String (SIZE(1)))"},
        {R"(name ::= IA5String (SIZE(1 | 2 | 5)))"},
        {R"(name ::= IA5String (SIZE(1..20)))"},
        {R"(type ::= INTEGER (1..50 EXCEPT 20..30))"},
        {R"(type ::= INTEGER (ALL EXCEPT 1..10))"},
        {R"(type ::= INTEGER (0..255))"},
        {R"(type ::= OCTET STRING (SIZE(16)))"},
        {R"(name ::= IA5String (FROM ("ABC")))"},
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
    };

    auto asn1p = asn1_parser::get_instance();
    for (const auto& item : table) {
        asn1_runtime runtime;
        auto test = asn1p->parse(&runtime, item.notation);
        _test_case.test(test, __FUNCTION__, "%s", item.notation);
    }
}

void testcase_parser() { test_asn1parser(); }
