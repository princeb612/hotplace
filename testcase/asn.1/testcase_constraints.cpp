/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_constraints.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_testvector_constraints() {
    _test_case.begin("ASN.1 constraints");

    struct testvector {
        const char* text;
        asn1_object* object;
        const char* notation;
    } table[] = {
        {"single value",
         asn1_referenced_type::define(
             "type",  //
             asn1_builder::build(asn1_entity_integer, [&](asn1_builtin_type* builtin) -> void { builtin->set_constraints(new asn1_constraints_single_value(1)); })),
         "type ::= INTEGER (1)"},
        {"single value",
         asn1_referenced_type::define("type", asn1_builder::build(asn1_entity_integer,
                                                                  [&](asn1_builtin_type* builtin) -> void {
                                                                      builtin->set_constraints(new asn1_constraints_union(new asn1_constraints_single_value(1),
                                                                                                                          new asn1_constraints_single_value(2)));
                                                                  })),
         "type ::= INTEGER (1 | 2)"},
        {"single value",
         asn1_referenced_type::define(
             "type",  //
             asn1_builder::build(asn1_entity_integer, [&](asn1_builtin_type* builtin) -> void { builtin->set_constraints(new asn1_constraints_union({1, 2, 3, 6})); })),
         "type ::= INTEGER (1 | 2 | 3 | 6)"},
        {"range",
         asn1_referenced_type::define("type", asn1_builder::build(asn1_entity_integer,
                                                                  [&](asn1_builtin_type* builtin) -> void {
                                                                      builtin->set_constraints(new asn1_constraints_union(new asn1_constraints_range(1, 10),
                                                                                                                          new asn1_constraints_range(20, 30)));
                                                                  })),
         "type ::= INTEGER (1..10 | 20..30)"},
        {"range",
         asn1_referenced_type::define("type", asn1_builder::build(asn1_entity_integer,
                                                                  [&](asn1_builtin_type* builtin) -> void {
                                                                      builtin->set_constraints(new asn1_constraints_intersection(new asn1_constraints_range(1, 100),
                                                                                                                                 new asn1_constraints_range(50, 200)));
                                                                  })),
         "type ::= INTEGER ((1..100) INTERSECTION (50..200))"},  // 50..100
        {"range",
         asn1_referenced_type::define("type", asn1_builder::build(asn1_entity_integer,
                                                                  [&](asn1_builtin_type* builtin) -> void {
                                                                      builtin->set_constraints(new asn1_constraints_except(new asn1_constraints_range(1, 100),
                                                                                                                           new asn1_constraints_single_value(50)));
                                                                  })),
         "type ::= INTEGER (1..100 EXCEPT 50)"},  // 1..49 | 51..100
        {"range",
         asn1_referenced_type::define(
             "type", asn1_builder::build(asn1_entity_integer,
                                         [&](asn1_builtin_type* builtin) -> void {
                                             builtin->set_constraints(new asn1_constraints_except(
                                                 new asn1_constraints_union(new asn1_constraints_range(1, 10), new asn1_constraints_range(20, 30)),
                                                 new asn1_constraints_union(new asn1_constraints_single_value(5), new asn1_constraints_single_value(25))));
                                         })),
         "type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25))"},  // 1..4 | 6..10 | 20..24 | 26..30
        {"size",
         asn1_referenced_type::define(
             "name",  //
             asn1_builder::build(asn1_entity_ia5string, [&](asn1_builtin_type* builtin) -> void { builtin->set_constraints(new asn1_constraints_size(1, 20)); })),
         "name ::= IA5String (SIZE(1..20))"},
    };

    for (const auto& item : table) {
        auto type = item.object;
        auto expect = item.notation;

        basic_stream bs;
        binary_t bin;

        type->publish(&bs);
        _logger->writeln(bs);
        _test_case.assert(bs == expect, __FUNCTION__, "%s : %s", item.text, item.notation);

        type->release();
    }
}

void testcase_constraints() { test_testvector_constraints(); }
