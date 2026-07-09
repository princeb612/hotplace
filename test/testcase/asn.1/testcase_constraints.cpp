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

    // clang-format off
    auto cons_single_type1 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_single_value_i(1));
                        }));
    auto cons_single_type2 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_union_i(
                                    new asn1_constraint_single_value_i(1),
                                    new asn1_constraint_single_value_i(2)));
                        }));
    auto cons_single_type3 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_union_i({1, 2, 3, 6}));
                        }));
    auto cons_single_type4 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_visiblestring,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_union_s({"A", "B", "C", "D"}));
                        }));
    auto cons_range_type1 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_union_i(
                                    new asn1_constraint_range_i(1, 10),
                                    new asn1_constraint_range_i(20, 30)));
                        }));
    // 50..100
    auto cons_range_type2 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_intersection_i(
                                    new asn1_constraint_range_i(1, 100),
                                    new asn1_constraint_range_i(50, 200)));
                        }));
    // 1..49 | 51..100
    auto cons_range_type3 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_except_i(
                                    new asn1_constraint_range_i(1, 100),
                                    new asn1_constraint_single_value_i(50)));
                        }));
    // 1..4 | 6..10 | 20..24 | 26..30
    auto cons_range_type4 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
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
            asn1_builtin_type::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(0.0, 100.0));
                        }));
    auto cons_range_type6 =
        asn1_referenced_type::define("positive",
            asn1_builtin_type::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(0.0, range_type_t::maxvalue));
                        }));
    auto cons_range_type7 =
        asn1_referenced_type::define("negative",
            asn1_builtin_type::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_f(range_type_t::minvalue, 0.0));
                        }));
    auto cons_range_type8 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_real,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_except_f(
                                    new asn1_constraint_range_f(0.0, 100.0),
                                    new asn1_constraint_single_value_f(50.0)));
                        }));
    auto cons_size_type1 =
        asn1_referenced_type::define("name",
            asn1_builtin_type::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_single_value_i(1)));
                        }));
    auto cons_size_type2 =
        asn1_referenced_type::define("name",
            asn1_builtin_type::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_union_i({1, 2, 5})));
                        }));
    auto cons_size_type3 =
        asn1_referenced_type::define("name",
            asn1_builtin_type::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_range_i(1, 20)));
                        }));
    auto cons_except_type1 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_except_i(
                                    new asn1_constraint_range_i(1, 50),
                                    new asn1_constraint_range_i(20, 30)));
                        }));
    auto cons_allexcept_type1 =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_all_except_i(
                                    new asn1_constraint_range_i(1, 10)));
                        }));

    auto cons_integer_range =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_i(0, 255));
                        }));
    auto cons_octstring_size =
        asn1_referenced_type::define("type",
            asn1_builtin_type::build(asn1_entity_octstring,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_single_value_i(16)));
                        }));
    auto cons_ie5string_alphabet =
        asn1_referenced_type::define("name",
            asn1_builtin_type::build(asn1_entity_ia5string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_from_s(
                                    new asn1_constraint_single_value_s("ABC")));
                        }));
    auto cons_sequence_of_range =
        asn1_referenced_type::define("Numbers",
            asn1_type::build(new asn1_sequence_of(asn1_entity_integer),
                        [&](asn1_type* object) -> void {
                            object->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_range_i(1, 4)));
                        }));
    auto cons_bitstring = asn1_referenced_type::define("Flags",
            asn1_builtin_type::build(asn1_entity_bitstring,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_single_value_i(8)));
                        }));
    auto cons_enum = asn1_referenced_type::define("Color",
            new asn1_enum({{"red", 0}, {"green", 1}, {"blue", 2}}));
    auto cons_nested = asn1_referenced_type::define("Person",
            new asn1_sequence({
                asn1_builtin_type::build("age", asn1_entity_integer,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_range_i(0, 120));
                }),
                asn1_builtin_type::build("name", asn1_entity_utf8string,
                        [&](asn1_builtin_type* builtin) -> void {
                            builtin->get_constraints().add(
                                new asn1_constraint_size_i(
                                    new asn1_constraint_range_i(1, 20)));
                })
            }));
    // clang-format on

    enum testvector_flag_t : uint8 {
        flag_value_int0,
        flag_value_int1,
        flag_value_int2,
        flag_value_int5,
        flag_value_int15,
        flag_value_int50,
        flag_value_int100,
        flag_value_int255,
        flag_value_int256,
        flag_value_intm1,
        flag_value_a,
        flag_value_abc,
        flag_value_abcd,
        flag_value_octstring16,
        flag_value_octstring32,
        flag_value_string16,
        flag_value_string20,
        flag_value_string30,
        flag_value_float0,
        flag_value_float50,
        flag_value_floatm1,
        flag_seqof_int3,
        flag_seqof_int5,
        flag_value_bitstring8,
        flag_value_bitstring16,
        flag_value_red,
        flag_value_green,
        flag_value_blue,
        flag_value_yellow,
        flag_value_nested30_short,
        flag_value_nested130_short,
        flag_value_nested30_long,
        flag_value_nested30_empty,
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
        {"range", cons_range_type5->clone(), "temperature ::= REAL (0.0..100.0)", false, flag_value_floatm1},
        {"range", cons_range_type6, "positive ::= REAL (0.0..MAX)", true, flag_value_float0},
        {"range", cons_range_type7, "negative ::= REAL (MIN..0.0)", true, flag_value_float0},
        {"range", cons_range_type8, "type ::= REAL (0.0..100.0 EXCEPT 50.0)", true, flag_value_float0},
        {"range", cons_range_type8->clone(), "type ::= REAL (0.0..100.0 EXCEPT 50.0)", false, flag_value_float50},
        {"size", cons_size_type1, "name ::= IA5String (SIZE(1))", true, flag_value_a},
        {"size", cons_size_type2, "name ::= IA5String (SIZE(1 | 2 | 5))", false, flag_value_string20},
        {"size", cons_size_type3, "name ::= IA5String (SIZE(1..20))", true, flag_value_string20},
        {"except", cons_except_type1, "type ::= INTEGER (1..50 EXCEPT 20..30)", true, flag_value_int5},
        {"all except", cons_allexcept_type1, "type ::= INTEGER (ALL EXCEPT 1..10)", true, flag_value_int50},
        {"all except", cons_allexcept_type1->clone(), "type ::= INTEGER (ALL EXCEPT 1..10)", false, flag_value_int1},
        {"integer range", cons_integer_range, "type ::= INTEGER (0..255)", true, flag_value_int0},
        {"integer range", cons_integer_range->clone(), "type ::= INTEGER (0..255)", true, flag_value_int255},
        {"integer range", cons_integer_range->clone(), "type ::= INTEGER (0..255)", false, flag_value_int256},
        {"integer range", cons_integer_range->clone(), "type ::= INTEGER (0..255)", false, flag_value_intm1},
        {"oct string size", cons_octstring_size, "type ::= OCTET STRING (SIZE(16))", true, flag_value_octstring16},
        {"oct string size", cons_octstring_size->clone(), "type ::= OCTET STRING (SIZE(16))", false, flag_value_octstring32},
        {"oct string size", cons_octstring_size->clone(), "type ::= OCTET STRING (SIZE(16))", false, flag_value_string16},
        {"alphabet constraint", cons_ie5string_alphabet, R"(name ::= IA5String (FROM ("ABC")))", true, flag_value_a},
        {"alphabet constraint", cons_ie5string_alphabet->clone(), R"(name ::= IA5String (FROM ("ABC")))", true, flag_value_abc},
        {"alphabet constraint", cons_ie5string_alphabet->clone(), R"(name ::= IA5String (FROM ("ABC")))", false, flag_value_abcd},
        {"size range", cons_sequence_of_range, "Numbers ::= SEQUENCE SIZE(1..4) OF INTEGER", true, flag_seqof_int3},
        {"size range", cons_sequence_of_range->clone(), "Numbers ::= SEQUENCE SIZE(1..4) OF INTEGER", false, flag_seqof_int5},
        {"bitstring", cons_bitstring, "Flags ::= BIT STRING (SIZE(8))", true, flag_value_bitstring8},
        {"bitstring", cons_bitstring->clone(), "Flags ::= BIT STRING (SIZE(8))", false, flag_value_bitstring16},
        {"enum", cons_enum, "Color ::= ENUMERATED {red(0), green(1), blue(2)}", true, flag_value_red},
        {"enum", cons_enum->clone(), "Color ::= ENUMERATED {red(0), green(1), blue(2)}", true, flag_value_green},
        {"enum", cons_enum->clone(), "Color ::= ENUMERATED {red(0), green(1), blue(2)}", true, flag_value_blue},
        {"enum", cons_enum->clone(), "Color ::= ENUMERATED {red(0), green(1), blue(2)}", false, flag_value_yellow},
        {"nested constraint", cons_nested, "Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))}", true, flag_value_nested30_short},
        {"nested constraint", cons_nested->clone(), "Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))}", false, flag_value_nested130_short},
        {"nested constraint", cons_nested->clone(), "Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))}", false, flag_value_nested30_long},
        {"nested constraint", cons_nested->clone(), "Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))}", false, flag_value_nested30_empty},
    };

    for (const auto& item : table) {
        auto type = item.object;
        auto expect = item.notation;

        basic_stream bs;
        binary_t bin;

        type->publish(&bs);
        _logger->writeln(bs);
        _test_case.assert(bs == expect, __FUNCTION__, "notation %s : %s", item.text, item.notation);

        auto value = type->instantiate();

        switch (item.flag) {
            case flag_value_int0:
                (*value).set(0);
                break;
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
            case flag_value_int255:
                (*value).set(255);
                break;
            case flag_value_int256:
                (*value).set(256);
                break;
            case flag_value_intm1:
                (*value).set(-1);
                break;
            case flag_value_a:
                (*value).set("A");
                break;
            case flag_value_abc:
                (*value).set("ABC");
                break;
            case flag_value_abcd:
                (*value).set("ABCD");
                break;
            case flag_value_octstring16:
                (*value).set("000102030405060708090a0b0c0d0e0f");
                break;
            case flag_value_octstring32:
                (*value).set("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
                break;
            case flag_value_bitstring8:
                (*value).set("10101010");
                break;
            case flag_value_bitstring16:
                (*value).set("1010101010101010");
                break;
            case flag_value_string16:
                (*value).set("ABCDEFGHIJKLMNOP");
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
            case flag_seqof_int3:
                (*value).set({1, 2, 3});
                break;
            case flag_seqof_int5:
                (*value).set({1, 2, 3, 4, 5});
                break;
            case flag_value_red:
                (*value).set("red");
                break;
            case flag_value_green:
                (*value).set("green");
                break;
            case flag_value_blue:
                (*value).set("blue");
                break;
            case flag_value_yellow:
                (*value).set("yellow");
                break;
            case flag_value_nested30_short:
                (*value).set("age", 30).set("name", "Alice");
                break;
            case flag_value_nested130_short:
                (*value).set("age", 130).set("name", "Alice");
                break;
            case flag_value_nested30_long:
                (*value).set("age", 30).set("name", "ThisNameIsLongerThanTwentyChars");
                break;
            case flag_value_nested30_empty:
                (*value).set("age", 30).set("name", "");
                break;
        }

        bool test = type->validate(value);
        _test_case.assert(test == item.expect, __FUNCTION__, "evaluation %s : %s", item.text, item.notation);

        value->release();
        type->release();
    }
}

void testcase_constraints() { test_testvector_constraints(); }
