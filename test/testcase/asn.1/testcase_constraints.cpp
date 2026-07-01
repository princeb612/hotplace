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

using asn1_constraint_except_f = asn1_constraint_except<double>;
using asn1_constraint_range_f = asn1_constraint_range<double>;
using asn1_constraint_size_f = asn1_constraint_size<double>;
using asn1_constraint_single_value_f = asn1_constraint_single_value<double>;
using asn1_constraint_union_f = asn1_constraint_union<double>;
using asn1_constraint_all_except_i = asn1_constraint_all_except<int64>;
using asn1_constraint_except_i = asn1_constraint_except<int64>;
using asn1_constraint_intersection_i = asn1_constraint_intersection<int64>;
using asn1_constraint_range_i = asn1_constraint_range<int64>;
using asn1_constraint_size_i = asn1_constraint_size<int64>;
using asn1_constraint_single_value_i = asn1_constraint_single_value<int64>;
using asn1_constraint_union_i = asn1_constraint_union<int64>;
using asn1_constraint_union_s = asn1_constraint_union<std::string>;

void test_testvector_constraints() {
    _test_case.begin("ASN.1 constraints");

    // clang-format off
    auto cons_single_type1 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_single_value_i(1));
                        }));
    auto cons_single_type2 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_union_i(
                                        new asn1_constraint_single_value_i(1),
                                        new asn1_constraint_single_value_i(2)));
                        }));
    auto cons_single_type3 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_union_i({1, 2, 3, 6}));
                        }));
    auto cons_single_type4 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_visiblestring,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_union_s({"A", "B", "C", "D"}));
                        }));
    auto cons_range_type1 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_union_i(
                                        new asn1_constraint_range_i(1, 10),
                                        new asn1_constraint_range_i(20, 30)));
                        }));
    // 50..100
    auto cons_range_type2 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_intersection_i(
                                        new asn1_constraint_range_i(1, 100),
                                        new asn1_constraint_range_i(50, 200)));
                        }));
    // 1..49 | 51..100
    auto cons_range_type3 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_except_i(
                                        new asn1_constraint_range_i(1, 100),
                                        new asn1_constraint_single_value_i(50)));
                        }));
    // 1..4 | 6..10 | 20..24 | 26..30
    auto cons_range_type4 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_except_i(
                                    new asn1_constraint_union_i(
                                        new asn1_constraint_range_i(1, 10),
                                        new asn1_constraint_range_i(20, 30)),
                                    new asn1_constraint_union_i(
                                        new asn1_constraint_single_value_i(5),
                                        new asn1_constraint_single_value_i(25))));
                        }));
    auto cons_range_type5 =
        asn1_referenced_type::define("temperature",
            asn1_builder::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(0.0, 100.0));
                        }));
    auto cons_range_type6 =
        asn1_referenced_type::define("positive",
            asn1_builder::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(0.0, range_type_t::maxvalue));
                        }));
    auto cons_range_type7 =
        asn1_referenced_type::define("negative",
            asn1_builder::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(range_type_t::minvalue, 0.0));
                        }));
    auto cons_range_type8 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_except_f(
                                    new asn1_constraint_range_f(0.0, 100.0),
                                    new asn1_constraint_single_value_f(50.0)));
                        }));
    auto cons_size_type1 =
        asn1_referenced_type::define("name",
            asn1_builder::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_size_i(
                                        new asn1_constraint_single_value_i(1)));
                        }));
    auto cons_size_type2 =
        asn1_referenced_type::define("name",
            asn1_builder::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_size_i(
                                        new asn1_constraint_union_i({1, 2, 5})));
                        }));
    auto cons_size_type3 =
        asn1_referenced_type::define("name",
            asn1_builder::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_size_i(
                                        new asn1_constraint_range_i(1, 20)));
                        }));
    auto cons_except_type1 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_except_i(
                                        new asn1_constraint_range_i(1, 50),
                                        new asn1_constraint_range_i(20, 30)));
                        }));
    auto cons_allexcept_type1 =
        asn1_referenced_type::define("type",
            asn1_builder::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                    new asn1_constraint_all_except_i(
                                        new asn1_constraint_range_i(1, 10)));
                        }));
    // clang-format on

    enum testvector_flag_t : uint8 {
        flag_value_int1,
        flag_value_int2,
        flag_value_int5,
        flag_value_int15,
        flag_value_int50,
        flag_value_int100,
        flag_value_a,
        flag_value_string20,
        flag_value_string30,
        flag_value_float0,
        flag_value_float50,
        flag_value_floatm1,
    };

    struct testvector {
        const char* text;
        asn1_object* object;
        const char* notation;
        bool expect;
        testvector_flag_t flag;
    } table[] = {
        {"single value", cons_single_type1, "type ::= INTEGER (1)", true, flag_value_int1},
        {"single value", cons_single_type2, "type ::= INTEGER (1 | 2)", false, flag_value_int5},
        {"single value", cons_single_type3, "type ::= INTEGER (1 | 2 | 3 | 6)", true, flag_value_int2},
        {"single value", cons_single_type4, R"(type ::= VisibleString ("A" | "B" | "C" | "D"))", true, flag_value_a},
        {"range", cons_range_type1, "type ::= INTEGER (1..10 | 20..30)", true, flag_value_int5},
        {"range", cons_range_type1->clone(), "type ::= INTEGER (1..10 | 20..30)", false, flag_value_int15},
        {"range", cons_range_type2, "type ::= INTEGER ((1..100) INTERSECTION (50..200))", false, flag_value_int15},
        {"range", cons_range_type2->clone(), "type ::= INTEGER ((1..100) INTERSECTION (50..200))", true, flag_value_int50},
        {"range", cons_range_type2->clone(), "type ::= INTEGER ((1..100) INTERSECTION (50..200))", true, flag_value_int100},
        {"range", cons_range_type3, "type ::= INTEGER (1..100 EXCEPT 50)", true, flag_value_int100},
        {"range", cons_range_type3->clone(), "type ::= INTEGER (1..100 EXCEPT 50)", false, flag_value_int50},
        {"range", cons_range_type4, "type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25))", true, flag_value_int2},
        {"range", cons_range_type4->clone(), "type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25))", false, flag_value_int5},
        {"range", cons_range_type5, "temperature ::= REAL (0.0..100.0)", true, flag_value_float0},
        {"range", cons_range_type5->clone(), "temperature ::= REAL (0.0..100.0)", true, flag_value_floatm1},
        {"range", cons_range_type6, "positive ::= REAL (0.0..MAX)", true, flag_value_float0},
        {"range", cons_range_type7, "negative ::= REAL (MIN..0.0)", true, flag_value_float0},
        {"range", cons_range_type8, "type ::= REAL (0.0..100.0 EXCEPT 50.0)", true, flag_value_float0},
        {"range", cons_range_type8->clone(), "type ::= REAL (0.0..100.0 EXCEPT 50.0)", false, flag_value_float50},
        {"size", cons_size_type1, "name ::= IA5String (SIZE(1))", true, flag_value_string20},
        {"size", cons_size_type2, "name ::= IA5String (SIZE(1 | 2 | 5))", true, flag_value_string20},
        {"size", cons_size_type3, "name ::= IA5String (SIZE(1..20))", true, flag_value_string20},
        {"except", cons_except_type1, "type ::= INTEGER (1..50 EXCEPT 20..30)", true, flag_value_int5},
        {"all except", cons_allexcept_type1, "type ::= INTEGER (ALL EXCEPT 1..10)", true, flag_value_int50},
    };

    for (const auto& item : table) {
        auto type = item.object;
        auto expect = item.notation;

        basic_stream bs;
        binary_t bin;

        type->publish(&bs);
        _logger->writeln(bs);
        _test_case.assert(bs == expect, __FUNCTION__, "%s : %s", item.text, item.notation);

        auto value = type->instantiate();

        switch (item.flag) {
            case flag_value_int1:
                (*value).set(1);
                break;
            case flag_value_int2:
                (*value).set(2);
                break;
            case flag_value_int5:
                (*value).set(5);
                break;
            case flag_value_int15:
                (*value).set(15);
                break;
            case flag_value_int50:
                (*value).set(50);
                break;
            case flag_value_int100:
                (*value).set(100);
                break;
            case flag_value_a:
                (*value).set("A");
                break;
            case flag_value_string20:
                (*value).set("ABCDEFGHIJKLMNOPQRST");
                break;
            case flag_value_string30:
                (*value).set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcd");
                break;
            case flag_value_float0:
                (*value).set(0.0);
                break;
            case flag_value_float50:
                (*value).set(50.0);
                break;
            case flag_value_floatm1:
                (*value).set(-1.0);
                break;
        }

        // value->validate

        value->release();
        type->release();
    }
}

void testcase_constraints() { test_testvector_constraints(); }
