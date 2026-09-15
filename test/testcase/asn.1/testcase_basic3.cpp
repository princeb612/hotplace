/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_basic3.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

struct testvector {
    const char* schema;
    asn1_object* obj;
    const char* stream;
};

static void testcode_strongly_typed(asn1_runtime& runtime, const testvector& entry) {
    auto name = entry.obj->get_name();
    binary_t bin_stream = base16_decode_rfc(entry.stream);

    // read byte stream
    auto stream = bin_stream.data();
    auto size = bin_stream.size();
    size_t pos = 0;
    runtime.read(name, stream, size, pos);

    // runtime publish ASN.1 notation and DER
    basic_stream bs_notation;
    runtime.notation(name, &bs_notation);
    binary_t bin_der;
    runtime.publish(name, &bin_der);

    // dump
    _logger->write([&](basic_stream& bs) -> void {
        valist va;
        va << bs_notation << bin_stream << bin_der;
        bs.vaprintln("notation   {1}", va);
        bs.vaprintln("expect     {2:x}", va);
        bs.vaprintln("re-encoded {3:x}", va);
    });

    // comparision
    _test_case.assert(bs_notation == entry.schema, __FUNCTION__, "schema %s", entry.schema);
    _test_case.assert(bin_stream == bin_der, __FUNCTION__, "DER    %s", entry.schema);
}

void test_decode_strongly_typed1() {
    _test_case.begin("stronly-typed");

    auto schema1 = "Type1 ::= VisibleString";
    auto type1 = asn1_referenced_type::define("Type1", new asn1_visiblestring);
    auto schema2 = "Type2 ::= [APPLICATION 3] IMPLICIT Type1";
    auto type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, asn1_referenced_type::refer("Type1")));
    auto schema3 = "Type3 ::= [2] EXPLICIT Type2";
    auto type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, asn1_referenced_type::refer("Type2")));
    auto schema4 = "Type4 ::= [APPLICATION 7] IMPLICIT Type3";
    auto type4 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, asn1_referenced_type::refer("Type3")));
    auto schema5 = "Type5 ::= [2] IMPLICIT Type2";
    auto type5 = asn1_referenced_type::define("Type5", new asn1_tagged_type(asn1_class_context, 2, asn1_implicit, asn1_referenced_type::refer("Type2")));
    auto schema6 = "Type6 ::= [2] EXPLICIT Type1";
    auto type6 = asn1_referenced_type::define("Type6", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, asn1_referenced_type::refer("Type1")));
    auto schema7 = "Type7 ::= [2] Type2";
    auto type7 = asn1_referenced_type::define("Type7", new asn1_tagged_type(asn1_class_context, 2, asn1_automatic, asn1_referenced_type::refer("Type2")));
    auto schema8 = "Type8 ::= [APPLICATION 7] IMPLICIT Type7";
    auto type8 = asn1_referenced_type::define("Type8", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, asn1_referenced_type::refer("Type7")));

    // reconstruct sematic asn1_object* from ASN.1 notation
    asn1_runtime runtime;
    runtime.add_schema(schema1);
    runtime.add_schema(schema2);
    runtime.add_schema(schema3);
    runtime.add_schema(schema4);
    runtime.add_schema(schema5);
    runtime.add_schema(schema6);
    runtime.add_schema(schema7);
    runtime.add_schema(schema8);

    // clang-format off
    struct testvector table[] = {
        {schema1, type1, "1A 05 4A 6F 6E 65 73"},
        {schema2, type2, "43 05 4A 6F 6E 65 73"},
        {schema3, type3, "A2 07 43 05 4A 6F 6E 65 73"},
        {schema4, type4, "67 07 43 05 4A 6F 6E 65 73"},
        {schema5, type5, "82 05 4A 6F 6E 65 73"},
        {schema6, type6, "A2 07 1A 05 4A 6F 6E 65 73"},
        {schema7, type7, "A2 07 43 05 4A 6F 6E 65 73"},
        {schema8, type8, "67 07 43 05 4A 6F 6E 65 73"},
    };
    // clang-format on

    for (const auto& entry : table) {
        testcode_strongly_typed(runtime, entry);
        entry.obj->release();
    }
}

void test_decode_strongly_typed2() {
    _test_case.begin("stronly-typed");

    auto schema1 = "Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}";
    auto type1 = asn1_referenced_type::define("Type1", new asn1_sequence({{"name", asn1_entity_visiblestring}, {"ok", asn1_entity_boolean}}));
    auto schema2 = "Type2 ::= [APPLICATION 5] IMPLICIT Type1";
    auto type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 5, asn1_implicit, asn1_referenced_type::refer("Type1")));

    // clang-format off
    struct testvector table[] = {
        {schema1, type1, "30 0A 1A 05 4A 6F 6E 65 73 01 01 FF"},
        {schema2, type2, "65 0A 1A 05 4A 6F 6E 65 73 01 01 FF"},
    };
    // clang-format on

    asn1_runtime runtime;
    runtime.add_schema(schema1);
    runtime.add_schema(schema2);

    for (const auto& entry : table) {
        testcode_strongly_typed(runtime, entry);
        entry.obj->release();
    }
}

void test_resolve_dependencies() {
    _test_case.begin("resolve reference dependencies");

    /*
    reference dependency
      PersonnelRecord (Name, EmployeeNumber, Date, Name, ChildInformation)
      ChildInformation (Name, Date)
      Name
      EmployeeNumber
      Date

    resolve
      Name, EmployeeNumber, Date -> ChildInformation -> PersonnelRecord
      */

    const char* item1 =
        R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {name Name, title [0] VisibleString, number EmployeeNumber, dateOfHire [1] Date, nameOfSpouse [2] Name, children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}})";
    const char* item2 = R"(ChildInformation ::= SET {name Name, dateOfBirth [0] Date})";
    const char* item3 = R"(Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {givenName VisibleString, initial VisibleString, familyName VisibleString})";
    const char* item4 = R"(EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER)";
    const char* item5 = R"(Date ::= [APPLICATION 3] IMPLICIT VisibleString)";

    asn1_runtime runtime;
    runtime << item1 << item2 << item3 << item4 << item5;

    basic_stream bs;
    runtime.notation(&bs);
    _logger->writeln(bs);

    bs.clear();
    runtime.notation("PersonnelRecord", &bs);
    _test_case.assert(bs == item1, __FUNCTION__, "notation PersonnelRecord");

    std::list<std::string> names;
    runtime.resolve(names);

    auto lambda_print = [](const std::list<std::string>& names) -> void {
        auto lambda = [](typename std::list<std::string>::const_iterator it, basic_stream& dbs) -> void { dbs << *it; };

        basic_stream dumps;
        dumps << "resolved order : ";
        print(names, dumps, lambda);
        _logger->writeln(dumps);
    };

    lambda_print(names);

    std::list<std::string> expect = {"Date", "EmployeeNumber", "Name", "ChildInformation", "PersonnelRecord"};
    _test_case.assert(names == expect, __FUNCTION__, "resolve");

    runtime.resolve("ChildInformation", names);
    lambda_print(names);
    std::list<std::string> expect_childinfo = {"Date", "Name", "ChildInformation"};
    _test_case.assert(names == expect_childinfo, __FUNCTION__, "resolve ChildInformation");

    runtime.resolve("PersonnelRecord", names);
    lambda_print(names);
    _test_case.assert(names == expect, __FUNCTION__, "resolve PersonnelRecord");

    bool test = false;
    test = runtime.is_resolvable();
    _test_case.assert(test, __FUNCTION__, "is_resolvable");
    test = runtime.is_resolvable("ChildInformation");
    _test_case.assert(test, __FUNCTION__, "is_resolvable(ChildInformation)");
    test = runtime.is_resolvable("PersonnelRecord");
    _test_case.assert(test, __FUNCTION__, "is_resolvable(PersonnelRecord)");

    const char* item6 = R"(ChildInformation2 ::= SET {name Name2, dateOfBirth [0] Date2})";
    runtime << item6;
    test = runtime.is_resolvable();
    _test_case.nassert(test, __FUNCTION__, "unresolved references exist");
    test = runtime.is_resolvable("ChildInformation2");
    _test_case.nassert(test, __FUNCTION__, "unresolved references exist");
    test = runtime.is_resolvable("ChildInformation");
    _test_case.assert(test, __FUNCTION__, "resolved references");

    runtime.resolve("ChildInformation", names);
    lambda_print(names);
    _test_case.assert(names == expect_childinfo, __FUNCTION__, "resolve ChildInformation");
}

void testcase_basic3() {
    test_decode_strongly_typed1();
    test_decode_strongly_typed2();

    test_resolve_dependencies();
}
