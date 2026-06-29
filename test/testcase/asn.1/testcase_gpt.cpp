/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_testvector_chatgpt() {
    _test_case.begin("testvector GPT");

    // Test 1 Length aggregation
    // Test 2. IMPLICIT Replace
    // Test 3. EXPLICIT Wrap
    // Test 4. IMPLICIT + EXPLICIT Chain
    // Test 5. Primitive / Constructed Bit propagation
    // Test 6. Constructed Type propagation
    // Test 7. Nested Length
    // Test 8. DER SET Ordering
    // Test 9. Long-form Length
    // Test 10. High Tag Number
    // Test 11. EXPLICIT over EXPLICIT
    // Test 12. SEQUENCE, SEQUENCE OF
    // Test 13. SEQUENCE OF INTEGER
    // Test 14. Nested SEQUENCE OF
    // Test 15. SET
    // Test 16. SET OF INTEGER
    // Test 17. SET OF VisibleString
    // Test 18. Deep Nested Length Aggregation, Tagged Builtin inside Container
    // Test 19. CHOICE
    // Test 20. Tagged CHOICE
    // Test 21. CHOICE inside SEQUENCE
    // Test 22. CHOICE with Tagged Alternatives
    // Test 23. value binding
    // Test 24. DEFAULT
    // Test 25. ENUMERATED
    // Test 26. INTEGER, Named Number List
    {
        auto case1_type1 = new asn1_sequence({{"name", asn1_entity_visiblestring}, {"ok", asn1_entity_boolean}});

        auto case2_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case2_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case2_type1->clone()));

        auto case3_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case3_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case3_type1->clone()));

        auto case4_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case4_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case4_type1->clone()));
        auto case4_type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case4_type2->clone()));
        auto case4_type4 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, case4_type3->clone()));
        auto case4_type5 = asn1_referenced_type::define("Type5", new asn1_tagged_type(asn1_class_context, 2, asn1_implicit, case4_type2->clone()));

        auto case5_type1 = asn1_referenced_type::define("Type1", asn1_entity_real);
        auto case5_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case5_type1->clone()));
        auto case5_type3 = asn1_referenced_type::define("Type1", new asn1_sequence({{"name", asn1_entity_visiblestring}, {"ok", asn1_entity_boolean}}));
        auto case5_type4 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 5, asn1_implicit, case5_type3->clone()));

        auto case6_type1 = asn1_referenced_type::define("Type1", new asn1_sequence({{"name", asn1_entity_visiblestring}}));
        auto case6_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case6_type1->clone()));

        auto case7_type1 = asn1_referenced_type::define("Outer", new asn1_sequence(new asn1_sequence("Inner", {{"name", asn1_entity_visiblestring}})));
        auto case7_type2 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case7_type3 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_context, 1, asn1_explicit, case7_type2->clone()));
        auto case7_type4 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case7_type3->clone()));
        auto case7_type5 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_context, 3, asn1_explicit, case7_type4->clone()));

        auto case8_type1 = new asn1_set({new asn1_builtin_type("a", asn1_entity_integer), new asn1_builtin_type("b", asn1_entity_boolean)});
        auto case8_type2 = new asn1_set({{"a", asn1_entity_integer}, {"b", asn1_entity_boolean}});
        auto case8_type3 = new asn1_set_of(asn1_entity_visiblestring);

        auto case9_type1 = new asn1_builtin_type("long", asn1_entity_visiblestring);
        auto case9_type2 = case9_type1->clone();
        auto case9_type3 = case9_type1->clone();
        auto case9_type4 = case9_type1->clone();
        auto case9_type5 = case9_type1->clone();

        auto case10_type1 = new asn1_tag(asn1_class_application, 31);
        auto case10_type2 = new asn1_tag(asn1_class_application, 32);
        auto case10_type3 = asn1_referenced_type::define("Type1", new asn1_tagged_type(asn1_class_application, 128, asn1_implicit, asn1_entity_integer));
        auto case10_type4 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 201, asn1_implicit, asn1_entity_integer));

        auto case11_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case11_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_context, 1, asn1_explicit, case11_type1->clone()));
        auto case11_type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case11_type2->clone()));

        auto case12_type1 = new asn1_sequence;
        auto case12_type2 = new asn1_sequence_of(asn1_entity_integer);
        auto case12_type3 = asn1_referenced_type::define("Names", new asn1_sequence_of(asn1_entity_visiblestring));

        auto case13_type1 = asn1_referenced_type::define("Numbers", new asn1_sequence_of(asn1_entity_integer));

        auto case14_type1 = asn1_referenced_type::define("Outer", new asn1_sequence(new asn1_sequence_of("names", asn1_entity_visiblestring)));

        auto case15_type1 = new asn1_set({{"z", asn1_entity_boolean}, {"a", asn1_entity_integer}});
        auto case15_type2 = new asn1_set_of(asn1_entity_integer);

        auto case16_type1 = asn1_referenced_type::define("Numbers", new asn1_set_of(asn1_entity_integer));

        auto case17_type1 = asn1_referenced_type::define("Names", new asn1_set_of(asn1_entity_visiblestring));

        auto case18_type1 =
            asn1_referenced_type::define("Outer", new asn1_sequence(new asn1_sequence("inner", new asn1_sequence("child", {{"name", asn1_entity_visiblestring}}))));
        auto case18_type2 =
            new asn1_sequence(new asn1_tagged_type("name", asn1_class_context, 0, asn1_implicit, asn1_entity_visiblestring));  // value->set("name", "Jones")

        auto case19_type1 = asn1_referenced_type::define("Value", new asn1_choice({{"i", asn1_entity_integer}, {"s", asn1_entity_visiblestring}}));
        auto case19_type2 = case19_type1->clone();

        auto case20_type1 = asn1_referenced_type::define(
            "Value", new asn1_tagged_type(asn1_class_context, 0, asn1_explicit, new asn1_choice({{"i", asn1_entity_integer}, {"s", asn1_entity_visiblestring}})));

        auto case21_type1 =
            asn1_referenced_type::define("Person", new asn1_sequence(new asn1_choice("id", {{"num", asn1_entity_integer}, {"name", asn1_entity_visiblestring}})));

        auto case22_type1 =
            asn1_referenced_type::define("Value", new asn1_choice({new asn1_tagged_type("i", asn1_class_context, 0, asn1_implicit, asn1_entity_integer),
                                                                   new asn1_tagged_type("s", asn1_class_context, 1, asn1_implicit, asn1_entity_visiblestring)}));

        auto case23_type1 = asn1_referenced_type::define("Type1", new asn1_builtin_type(asn1_entity_visiblestring));           // value->set("Jones")
        auto case23_type2 = asn1_referenced_type::define("Person", new asn1_sequence({{"name", asn1_entity_visiblestring}}));  // value->set("name", "Jones")
        auto case23_type3 = asn1_referenced_type::define(
            "Person", new asn1_sequence(new asn1_tagged_type("name", asn1_class_context, 0, asn1_implicit, asn1_entity_visiblestring)));  // value->set("name", "Jones")
        auto case23_type4 = asn1_referenced_type::define(
            "Person", new asn1_sequence({{"firstName", asn1_entity_visiblestring},
                                         {"lastName", asn1_entity_visiblestring}}));  // (*value).set("firstName", "John").set("lastName", "Smith")
        auto case23_type5 =
            asn1_referenced_type::define("Outer", new asn1_sequence(new asn1_sequence("inner", {{"name", asn1_entity_visiblestring}})));  // value->set("name", "Jones")
        auto case23_type6 = asn1_referenced_type::define(
            "Outer", new asn1_sequence(new asn1_tagged_type("inner", asn1_class_context, 0, asn1_explicit,
                                                            new asn1_sequence({{"name", asn1_entity_visiblestring}}))));  // value->set("name", "Jones")

        auto case24_type1 = asn1_referenced_type::define(
            "Person", new asn1_sequence({new asn1_builtin_type("name", asn1_entity_visiblestring), new asn1_builtin_type("age", asn1_entity_integer, 20)}));
        auto case24_type2 = case24_type1->clone();

        auto case25_type1 = asn1_referenced_type::define("Color", new asn1_enum({{"red", 0}, {"green", 1}, {"blue", 2}}));
        auto case25_type2 = asn1_referenced_type::define(
            "Person", new asn1_sequence({new asn1_builtin_type("name", asn1_entity_visiblestring), new asn1_enum("color", {{"red", 0}, {"green", 1}, {"blue", 2}})}));

        auto case26_type1 = asn1_referenced_type::define("Number", new asn1_integer);
        auto case26_type2 = asn1_referenced_type::define("Location", new asn1_integer({{"homeOffice", 0}, {"fieldOffice", 1}, {"roving", 2}}));
        auto case26_type3 = case26_type2->clone();
        auto case26_type4 = case26_type2->clone();

        auto case27_type1 = asn1_referenced_type::define("Test", new asn1_sequence({new asn1_builtin_type("id", asn1_entity_integer), new asn1_any("data")}));

        auto case28_type1 = asn1_referenced_type::define("Flags", new asn1_bitstring);
        auto case28_type2 = case28_type1->clone();
        auto case28_type3 = asn1_referenced_type::define("Flags", new asn1_bitstring({{"read", 0}, {"write", 1}, {"execute", 2}}));

        auto case29_type1 = asn1_referenced_type::define("Data", new asn1_builtin_type(asn1_entity_octstring));
        auto case29_type2 = asn1_referenced_type::define("Oid", new asn1_builtin_type(asn1_entity_oid));
        auto case29_type3 = asn1_referenced_type::define("RelOid", new asn1_builtin_type(asn1_entity_reloid));
        auto case29_type4 = case29_type3->clone();
        auto case29_type5 = case29_type3->clone();
        auto case29_type6 = case29_type3->clone();
        auto case29_type7 = case29_type3->clone();

        auto case30_type1 = asn1_referenced_type::define("Time", new asn1_builtin_type(asn1_entity_utctime));
        auto case30_type2 = asn1_referenced_type::define("Time", new asn1_builtin_type(asn1_entity_generalizedtime));

        // clang-format off
        const char* longform_string =
            R"(Somewhere over the rainbow way up high /)"
            R"(There's a land that I've heard of once in a lullaby /)"
            R"(Somewhere over the rainbow skies are blue /)"
            R"(And the dreams that you dare to dream really do come true /)"
            R"(Someday I'll wish upon a star /)"
            R"(And wake up where the clouds are far behind me /)"
            R"(Where troubles melt like lemon drops /)"
            R"(Away above the chimney tops that's where you'll find me /)"
            R"(Somewhere over the rainbow bluebirds fly /)"
            R"(Birds fly over the rainbow /)"
            R"(Why then oh why can't I? /)"
            R"(Someday I'll wish upon a star /)"
            R"(And wake up where the clouds are far behind me /)"
            R"(Where troubles melt like lemon drops /)"
            R"(Away above the chimney tops that's where you'll find me /)"
            R"(Somewhere over the rainbow skies are blue /)"
            R"(And the dreams that you dare to dream really do come true /)";
        // clang-format on

        enum testvector_flag_t : uint8 {
            flag_blank = 0,             // no data
            flag_unnamed_zero,          // 0
            flag_unnamed_string,        // "Jones"
            flag_unnamed_float,         // 1.0
            flag_longform,              // strlen > 127
            flag_value_name_ok,         // name "Jones", ok true
            flag_value_a_b,             // a 5, b true
            flag_value_a_z,             // z true, a 5
            flag_seqof_int,             // [1, 2, 3]
            flag_value_names,           // names ["Jones", "Smith"]
            flag_seqof_string,          // ["Jones", "Smith"]
            flag_setof_int,             // [5, 1, 3]
            flag_setof_string,          // ["Smith", "Jones"]
            flag_value_setof,           // ["Z", "A"]
            flag_choice_int,            // i 5
            flag_choice_string,         // s "Jones"
            flag_value_fullname,        // firstName "John", lastName "Smith"
            flag_value_innername,       // inner.name "Jones"
            flag_value_Innername,       // Inner.name "Jones"
            flag_value_innerchildname,  // inner.child.name "Jones"
            flag_value_idname,          // id.name "Jones"
            flag_value_name_age,        // name "Jones", age 30
            flag_value_green,           // Color "green"
            flag_value_namegreen,       // name "Jones", color "green"
            flag_nnl_homeoffice,        // "homeOffice"
            flag_unnamed_30,            // 30
            flag_value_der,             // id 1, data 0x1A03616263
            flag_value_bitstring,       // 10101010
            flag_value_bitstring2,      // 1011011101011
            flag_value_nbl,             // ["read", "execute"]
            flag_value_deadbeef,        // DE AD BE EF
            flag_value_oid,             // 1.2.840.113549
            flag_value_reloid,          // 8571.3.2
            flag_value_reloid2,
            flag_value_reloid3,
            flag_value_reloid4,
            flag_value_reloid5,
            flag_value_utctime,
            flag_value_generalizedtime,
        };
        struct testvector {
            asn1_object* obj;
            const char* name;
            const char* notation;
            const char* der;
            testvector_flag_t flag;
            int longform_len;  // flag_longform
        } table[] = {
            {case1_type1, "Test 1 Length aggregation", "SEQUENCE {name VisibleString, ok BOOLEAN}", "30 0A 1A 05 4A 6F 6E 65 73 01 01 FF", flag_value_name_ok},

            {case2_type1, "Test 2. IMPLICIT Replace", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case2_type2, "Test 2. IMPLICIT Replace", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 05 4A 6F 6E 65 73", flag_unnamed_string},

            {case3_type1, "Test 3. EXPLICIT Wrap", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case3_type2, "Test 3. EXPLICIT Wrap", "Type2 ::= [2] EXPLICIT Type1", "A2 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},

            {case4_type1, "Test 4. IMPLICIT + EXPLICIT Chain", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case4_type2, "Test 4. IMPLICIT + EXPLICIT Chain", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case4_type3, "Test 4. IMPLICIT + EXPLICIT Chain", "Type3 ::= [2] EXPLICIT Type2", "A2 07 43 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case4_type4, "Test 4. IMPLICIT + EXPLICIT Chain", "Type4 ::= [APPLICATION 7] IMPLICIT Type3", "67 07 43 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case4_type5, "Test 4. IMPLICIT + EXPLICIT Chain", "Type5 ::= [2] IMPLICIT Type2", "82 05 4A 6F 6E 65 73", flag_unnamed_string},

            {case5_type1, "Test 5. Primitive / Constructed Bit propagation", "Type1 ::= REAL", "09 03 80 00 01", flag_unnamed_float},
            {case5_type2, "Test 5. Primitive / Constructed Bit propagation", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 03 80 00 01", flag_unnamed_float},
            {case5_type3, "Test 5. IMPLICIT over Constructed", "Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}", "30 0A 1A 05 4A 6F 6E 65 73 01 01 FF",
             flag_value_name_ok},
            {case5_type4, "Test 5. IMPLICIT over Constructed", "Type2 ::= [APPLICATION 5] IMPLICIT Type1", "65 0A 1A 05 4A 6F 6E 65 73 01 01 FF", flag_value_name_ok},

            {case6_type1, "Test 6. Constructed Type propagation", "Type1 ::= SEQUENCE {name VisibleString}", "30 07 1A 05 4A 6F 6E 65 73", flag_value_name_ok},
            {case6_type2, "Test 6. Constructed Type propagation", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "63 07 1A 05 4A 6F 6E 65 73", flag_value_name_ok},

            {case7_type1, "Test 7. Nested Length", "Outer ::= SEQUENCE {Inner SEQUENCE {name VisibleString}}", "30 09 30 07 1A 05 4A 6F 6E 65 73", flag_value_Innername},
            {case7_type2, "Test 7. Nested Explicit Length Cascade", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case7_type3, "Test 7. Nested Explicit Length Cascade", "Type2 ::= [1] EXPLICIT Type1", "A1 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case7_type4, "Test 7. Nested Explicit Length Cascade", "Type3 ::= [2] EXPLICIT Type2", "A2 09 A1 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case7_type5, "Test 7. Nested Explicit Length Cascade", "Type4 ::= [3] EXPLICIT Type3", "A3 0B A2 09 A1 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},

            {case8_type1, "Test 8. DER SET Ordering", "SET {a INTEGER, b BOOLEAN}", "31 06 01 01 FF 02 01 05", flag_value_a_b},
            {case8_type2, "Test 8. DER SET Ordering", "SET {a INTEGER, b BOOLEAN}", "31 06 01 01 FF 02 01 05", flag_value_a_b},
            {case8_type3, "Test 8. DER SET OF Ordering", "SET OF VisibleString", "31 06 1A 01 41 1A 01 5A", flag_value_setof},

            // clang-format off
            {case9_type1, "Test 9.Long-form Length", "long VisibleString",
             "1a7f536f6d657768657265206f76657220746865207261696e626f77207761792075702068696768202f546865726527732061206c616e6420746861742049277665206865617264206f66206f6e636520696e2061206c756c6c616279202f536f6d657768657265206f76657220746865207261696e626f7720736b6965732061",
             flag_longform, 127},
            {case9_type2, "Test 9.Long-form Length", "long VisibleString",
             "1a8180536f6d657768657265206f76657220746865207261696e626f77207761792075702068696768202f546865726527732061206c616e6420746861742049277665206865617264206f66206f6e636520696e2061206c756c6c616279202f536f6d657768657265206f76657220746865207261696e626f7720736b696573206172",
             flag_longform, 128},
            {case9_type3, "Test 9.Long-form Length", "long VisibleString",
             "1a81b9536f6d657768657265206f76657220746865207261696e626f77207761792075702068696768202f546865726527732061206c616e6420746861742049277665206865617264206f66206f6e636520696e2061206c756c6c616279202f536f6d657768657265206f76657220746865207261696e626f7720736b6965732061726520626c7565202f416e642074686520647265616d73207468617420796f75206461726520746f20647265616d207265616c6c7920646f2063",
             flag_longform, 185},
            {case9_type4, "Test 9.Long-form Length", "long VisibleString",
             "1a82012c536f6d657768657265206f76657220746865207261696e626f77207761792075702068696768202f546865726527732061206c616e6420746861742049277665206865617264206f66206f6e636520696e2061206c756c6c616279202f536f6d657768657265206f76657220746865207261696e626f7720736b6965732061726520626c7565202f416e642074686520647265616d73207468617420796f75206461726520746f20647265616d207265616c6c7920646f20636f6d652074727565202f536f6d656461792049276c6c20776973682075706f6e20612073746172202f416e642077616b652075702077686572652074686520636c6f756473206172652066617220626568696e64206d65202f57686572652074726f75626c6573206d656c74206c696b65206c",
             flag_longform, 300},
            {case9_type5, "Test 9.Long-form Length", "long VisibleString",
             "1a820149536f6d657768657265206f76657220746865207261696e626f77207761792075702068696768202f546865726527732061206c616e6420746861742049277665206865617264206f66206f6e636520696e2061206c756c6c616279202f536f6d657768657265206f76657220746865207261696e626f7720736b6965732061726520626c7565202f416e642074686520647265616d73207468617420796f75206461726520746f20647265616d207265616c6c7920646f20636f6d652074727565202f536f6d656461792049276c6c20776973682075706f6e20612073746172202f416e642077616b652075702077686572652074686520636c6f756473206172652066617220626568696e64206d65202f57686572652074726f75626c6573206d656c74206c696b65206c656d6f6e2064726f7073202f417761792061626f766520746865206368",
             flag_longform, 329},
            // clang-format on

            {case10_type1, "Test 10. High Tag Number", "[APPLICATION 31]", "5f 1f"},
            {case10_type2, "Test 10. High Tag Number", "[APPLICATION 32]", "5f 20"},
            {case10_type3, "Test 10. Multi-byte Tag Number", "Type1 ::= [APPLICATION 128] IMPLICIT INTEGER", "5f 81 00 01 00", flag_unnamed_zero},
            {case10_type4, "Test 10. Multi-byte Tag Number", "Type2 ::= [APPLICATION 201] IMPLICIT INTEGER", "5f 81 49 01 00", flag_unnamed_zero},

            {case11_type1, "Test 11. EXPLICIT over EXPLICIT", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case11_type2, "Test 11. EXPLICIT over EXPLICIT", "Type2 ::= [1] EXPLICIT Type1", "A1 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case11_type3, "Test 11. EXPLICIT over EXPLICIT", "Type3 ::= [2] EXPLICIT Type2", "A2 09 A1 07 1A 05 4A 6F 6E 65 73", flag_unnamed_string},

            {case12_type1, "Test 12. Empty SEQUENCE", "SEQUENCE {}", "30 00", flag_blank},
            {case12_type2, "Test 12. Empty SEQUENCE OF", "SEQUENCE OF INTEGER", "30 00", flag_blank},
            {case12_type3, "Test 12. SEQUENCE OF", "Names ::= SEQUENCE OF VisibleString", "30 0E 1A 05 4A 6F 6E 65 73 1A 05 53 6D 69 74 68", flag_seqof_string},

            {case13_type1, "Test 13. SEQUENCE OF INTEGER", "Numbers ::= SEQUENCE OF INTEGER", "30 09 02 01 01 02 01 02 02 01 03", flag_seqof_int},

            {case14_type1, "Test 14. Nested SEQUENCE OF", "Outer ::= SEQUENCE {names SEQUENCE OF VisibleString}", "30 10 30 0E 1A 05 4A 6F 6E 65 73 1A 05 53 6D 69 74 68",
             flag_value_names},

            {case15_type1, "Test 15. SET", "SET {z BOOLEAN, a INTEGER}", "31 06 01 01 FF 02 01 05", flag_value_a_z},
            {case15_type2, "Test 15. Empty SET OF", "SET OF INTEGER", "31 00", flag_blank},

            {case16_type1, "Test 16. SET OF INTEGER", "Numbers ::= SET OF INTEGER", "31 09 02 01 01 02 01 03 02 01 05", flag_setof_int},

            {case17_type1, "Test 17. SET OF VisibleString", "Names ::= SET OF VisibleString", "31 0E 1A 05 4A 6F 6E 65 73 1A 05 53 6D 69 74 68", flag_setof_string},

            {case18_type1, "Test 18. Deep Nested Length Aggregation", "Outer ::= SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}}",
             "30 0B / 30 09 / 30 07 / 1A 05 4A 6F 6E 65 73", flag_value_innerchildname},
            {case18_type2, "Test 18. Tagged Builtin inside Container", "SEQUENCE {name [0] IMPLICIT VisibleString}", "30 07 80 05 4A 6F 6E 65 73", flag_value_name_ok},

            {case19_type1, "Test 19. CHOICE (INTEGER)", "Value ::= CHOICE {i INTEGER, s VisibleString}", "02 01 05", flag_choice_int},
            {case19_type2, "Test 19. CHOICE (VisibleString)", "Value ::= CHOICE {i INTEGER, s VisibleString}", "1A 05 4A 6F 6E 65 73", flag_choice_string},

            {case20_type1, "Test 20. Tagged CHOICE", "Value ::= [0] EXPLICIT CHOICE {i INTEGER, s VisibleString}", "A0 07 1A 05 4A 6F 6E 65 73", flag_choice_string},

            {case21_type1, "Test 21. CHOICE inside SEQUENCE", "Person ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}}", "30 07 1A 05 4A 6F 6E 65 73",
             flag_value_idname},

            {case22_type1, "Test 22. CHOICE with Tagged Alternatives", "Value ::= CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString}", "81 05 4A 6F 6E 65 73",
             flag_choice_string},

            {case23_type1, "Test 23. Primitive Root", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73", flag_unnamed_string},
            {case23_type2, "Test 23. Named Component", "Person ::= SEQUENCE {name VisibleString}", "30 07 / 1A 05 / 4A 6F 6E 65 73", flag_value_name_ok},
            {case23_type3, "Test 23. Tagged Component", "Person ::= SEQUENCE {name [0] IMPLICIT VisibleString}", "30 07 / 80 05 / 4A 6F 6E 65 73", flag_value_name_ok},
            {case23_type4, "Test 23. Multiple Components", "Person ::= SEQUENCE {firstName VisibleString, lastName VisibleString}",
             "30 0D / 1A 04 4A 6F 68 6E / 1A 05 53 6D 69 74 68", flag_value_fullname},
            {case23_type5, "Test 23. Nested Component", "Outer ::= SEQUENCE {inner SEQUENCE {name VisibleString}}", "30 09 / 30 07 / 1A 05 / 4A 6F 6E 65 73",
             flag_value_innername},
            {case23_type6, "Test 23. Tagged Nested Component", "Outer ::= SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}}",
             "30 0B / A0 09 / 30 07 / 1A 05 / 4A 6F 6E 65 73", flag_value_innername},

            {case24_type1, "Test 24. DEFAULT", "Person ::= SEQUENCE {name VisibleString, age INTEGER DEFAULT 20}", "30 0A / 1A 05 4A 6F 6E 65 73 / 02 01 14",
             flag_value_name_ok},  // set("name", "Jones")
            {case24_type2, "Test 24. DEFAULT", "Person ::= SEQUENCE {name VisibleString, age INTEGER DEFAULT 20}", "30 0A / 1A 05 4A 6F 6E 65 73 / 02 01 1e",
             flag_value_name_age},  // set("name", "Jones").set("age", 30)

            {case25_type1, "Test 25. ENUMERATED", "Color ::= ENUMERATED {red(0), green(1), blue(2)}", "0A 01 01", flag_value_green},
            {case25_type2, "Test 25. ENUMERATED", "Person ::= SEQUENCE {name VisibleString, color ENUMERATED {red(0), green(1), blue(2)}}",
             "30 0A / 1A 05 4A 6F 6E 65 73 / 0A 01 01", flag_value_namegreen},

            {case26_type1, "Test 26. INTEGER", "Number ::= INTEGER", "02 01 00", flag_unnamed_zero},
            {case26_type2, "Test 26. Named Number List", "Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}", "02 01 00", flag_nnl_homeoffice},
            {case26_type3, "Test 26. Named Number List", "Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}", "02 01 00", flag_unnamed_zero},
            {case26_type4, "Test 26. Named Number List", "Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}", "02 01 1e", flag_unnamed_30},

            {case27_type1, "Test 27. ANY", "Test ::= SEQUENCE {id INTEGER, data ANY}", "30 08 / 02 01 01 / 1A 03 61 62 63", flag_value_der},

            {case28_type1, "Test 28. BIT STRING", "Flags ::= BIT STRING", "03 02 00 AA", flag_value_bitstring},
            {case28_type2, "Test 28. BIT STRING", "Flags ::= BIT STRING", "03 03 03 B7 58", flag_value_bitstring2},
            {case28_type3, "Test 28. BIT STRING NamedBitList", "Flags ::= BIT STRING {read(0), write(1), execute(2)}", "03 02 05 A0", flag_value_nbl},

            {case29_type1, "Test 29. OCTET STRING", "Data ::= OCTET STRING", "04 04 DE AD BE EF", flag_value_deadbeef},
            {case29_type2, "Test 29. OBJECT IDENTIFIER", "Oid ::= OBJECT IDENTIFIER", "06 06 2A 86 48 86 F7 0D", flag_value_oid},
            {case29_type3, "Test 29. RELATIVE-OID", "RelOid ::= RELATIVE-OID", "0D 04 C2 7B 03 02", flag_value_reloid},
            {case29_type4, "Test 29. RELATIVE-OID", "RelOid ::= RELATIVE-OID", "0D 06 01 03 06 01 04 01", flag_value_reloid2},
            {case29_type5, "Test 29. RELATIVE-OID", "RelOid ::= RELATIVE-OID", "0D 02 81 00", flag_value_reloid3},
            {case29_type6, "Test 29. RELATIVE-OID", "RelOid ::= RELATIVE-OID", "0D 06 C2 7B 81 48 82 2C", flag_value_reloid4},
            {case29_type7, "Test 29. Empty RELATIVE-OID", "RelOid ::= RELATIVE-OID", "0D 00", flag_value_reloid5},

            {case30_type1, "Test 30. UTCTime", "Time ::= UTCTime", "17 0D 3235303130313132303030305A", flag_value_utctime},
            {case30_type2, "Test 30. GeneralizedTime", "Time ::= GeneralizedTime", "18 0F 32303235303130313132303030305A", flag_value_generalizedtime},
        };

        for (const auto& item : table) {
            basic_stream bs;
            binary_t bin;
            auto value = item.obj->instantiate();
            switch (item.flag) {
                case flag_blank:
                    break;
                case flag_unnamed_zero:
                    (*value).set(0);
                    break;
                case flag_unnamed_30:
                    (*value).set(30);
                    break;
                case flag_unnamed_string:
                    (*value).set("Jones");
                    break;
                case flag_unnamed_float:
                    (*value).set(1.0);
                    break;
                case flag_longform:
                    (*value).set("long", variant(longform_string, item.longform_len));
                    break;
                case flag_value_name_ok:
                    (*value).set("name", "Jones").set("ok", true);
                    break;
                case flag_value_a_b:
                    (*value).set("a", 5).set("b", true);
                    break;
                case flag_value_a_z:
                    (*value).set("z", true).set("a", 5);
                    break;
                case flag_seqof_int:
                    (*value).set({1, 2, 3});
                    break;
                case flag_value_names:
                    (*value).set("names", {"Jones", "Smith"});
                    break;
                case flag_seqof_string:
                    (*value).set({"Jones", "Smith"});
                    break;
                case flag_setof_int:
                    (*value).set({5, 1, 3});
                    break;
                case flag_setof_string:
                    (*value).set({"Smith", "Jones"});
                    break;
                case flag_value_setof:
                    (*value).set({"Z", "A"});
                    break;
                case flag_choice_int:
                    (*value).set("i", 5);
                    break;
                case flag_choice_string:
                    (*value).set("s", "Jones");
                    break;
                case flag_value_fullname:
                    (*value).set("firstName", "John").set("lastName", "Smith");
                    break;
                case flag_value_innername:
                    (*value).set("inner.name", "Jones");
                    break;
                case flag_value_innerchildname:
                    (*value).set("inner.child.name", "Jones");
                    break;
                case flag_value_Innername:
                    (*value).set("Inner.name", "Jones");
                    break;
                case flag_value_idname:
                    (*value).set("id.name", "Jones");
                    break;
                case flag_value_name_age:
                    (*value).set("name", "Jones").set("age", 30);
                    break;
                case flag_value_green:
                    (*value).set("green");
                    break;
                case flag_value_namegreen:
                    (*value).set("name", "Jones").set("color", "green");
                    break;
                case flag_nnl_homeoffice:
                    (*value).set("homeOffice");
                    break;
                case flag_value_der:
                    (*value).set("id", 1).set("data", base16_decode_rfc("1A 03 61 62 63"));
                    break;
                case flag_value_bitstring:
                    (*value).set("10101010");
                    break;
                case flag_value_bitstring2:
                    (*value).set("1011011101011");
                    break;
                case flag_value_nbl:
                    (*value).set("read").set("execute");
                    break;
                case flag_value_deadbeef:
                    (*value).set("DEADBEEF");
                    break;
                case flag_value_oid:
                    (*value).set("1.2.840.113549");
                    break;
                case flag_value_reloid:
                    (*value).set("8571.3.2");
                    break;
                case flag_value_reloid2:
                    (*value).set("1.3.6.1.4.1");
                    break;
                case flag_value_reloid3:
                    (*value).set("128");
                    break;
                case flag_value_reloid4:
                    (*value).set("8571.200.300");
                    break;
                case flag_value_reloid5:
                    (*value).set("");
                    break;
                case flag_value_utctime:
                    (*value).set("250101120000Z");
                    break;
                case flag_value_generalizedtime:
                    (*value).set("20250101120000Z");
                    break;
                default:
                    break;
            }

            item.obj->publish(&bs);
            value->publish(&bin);

            _logger->write([&](basic_stream& dbs) -> void {
                valist va;
                va << bs << bin;
                dbs.vaprintln("type {1}", va);
                dbs.vaprintln("DER  {2:x}", va);
            });

            _test_case.assert(bs == item.notation, __FUNCTION__, "%s : %s", item.name, item.notation);
            _test_case.assert(bin == base16_decode_rfc(item.der), __FUNCTION__, "%s : %s", item.name, item.der);

            value->release();
            item.obj->release();
        }
    }
}

void testcase_gpt() { test_testvector_chatgpt(); }
