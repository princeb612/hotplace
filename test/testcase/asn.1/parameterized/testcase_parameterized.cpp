/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parameterized.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include <hotplace/test/testcase/asn.1/sample.hpp>

// parameterization step
// [x] semantic construction (prototyping)
// [ ] instantiation
// [ ] reconstruction from notation

static const char* example_parameterized = R"(
    -- Parameterized Type (Template)
    FRAME{TypeParam, INTEGER:maxSize} ::= SEQUENCE {
        header  INTEGER,
        payload TypeParam,
        length  INTEGER (0..maxSize)
    }

    -- Parameterized Type (Instantiation)
    MyPacket ::= FRAME{ OCTET STRING, 1024 }
)";

void test_parameterized1() {
    _test_case.begin("parameterization");

    // auto modules = asn1_modules::get_instance();
    // auto module6 = modules->add("GenericContainerModule");
    // auto module7 = modules->add("TemplateModule");

    // Envelope {TypeParameter} ::= SEQUENCE {
    //     version     INTEGER,
    //     messageId   OCTET STRING (SIZE(16)),
    //     payload     TypeParameter
    // }
    auto example6_type1 = asn1_parameterized_type::define("Envelope", [](asn1_parameterized_type* templ) -> asn1_object* {
        auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
            auto seq = static_cast<asn1_sequence*>(builtin);
            (*seq) << new asn1_integer("version")  //
                   << asn1_builder::build(
                          "messageId", asn1_entity_octstring,
                          [templ](asn1_object* builtin2) -> void { builtin2->get_constraints().add(new asn1_constraint_size_i(new asn1_constraint_single_value_i(16))); })
                   << new asn1_parameter(templ, "payload", "TypeParameter");
        });
        return obj;
    });

    // ActualMessage ::= Envelope { INTEGER }
    auto example6_inst1 = example6_type1->specialize("ActualMessage", {{"INTEGER"}});

    auto example7_type1 = asn1_parameterized_type::define(
        "FRAME",  //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            (*templ).add_paramtype("TypeParam").add_paramtype("INTEGER", "maxSize");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << new asn1_integer("header") << new asn1_parameter(templ, "payload", "TypeParam")
                       << asn1_builder::build("length", asn1_entity_integer, [&](asn1_object* builtin2) -> void {
                              builtin2->get_constraints().add(new asn1_constraint_range_i(int64(0), asn1_parameter::value<int64>(templ, "INTEGER", "maxSize")));
                          });
            });
            return obj;
        });
    auto example7_inst1 = example7_type1->specialize("MyPacket", {{"OCTET STRING"}, {1024}});

    auto example7_type2 = asn1_parameterized_type::define(  //
        "HEADER",                                           //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << new asn1_integer("version")
                       << new asn1_builtin_type("priority", asn1_entity_integer, asn1_parameter::value<variant>(templ, "INTEGER", "defaultPriority"));
            });
            return obj;
        });
    auto example7_inst2 = example7_type2->specialize("ControlHeader", {{5}});

    auto example7_type3 = asn1_parameterized_type::define(  //
        "TLV-BUFFER",                                       //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            // autogen    INTEGER:maxLen, TypeParam
            // testvector TypeParam, INTEGER:maxLen
            (*templ).add_paramtype("TypeParam").add_paramtype("INTEGER", "maxLen");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << asn1_builder::build(  //
                              "allocatedLength", asn1_entity_integer,
                              [&](asn1_object* builtin2) -> void { builtin2->get_constraints().add(new asn1_constraint_range_i(0, 65535)); })  //
                       << asn1_builder::build(                                                                                                 //
                              "maxCapacity", asn1_entity_integer,
                              [&](asn1_object* builtin3) -> void {
                                  builtin3->get_constraints().add(new asn1_constraint_single_value_i(asn1_parameter::value<int64>(templ, "INTEGER", "maxLen")));
                              })  //
                       << new asn1_parameter(templ, "payload", "TypeParam");
            });
            return obj;
        });
    auto example7_inst3 = example7_type3->specialize("MyBuffer", {{"OCTET STRING"}, {2048}});

    auto example7_type4 = asn1_parameterized_type::define(  //
        "COMMAND-ENVELOPE",                                 //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            // autogen    INTEGER:msgId, TypeParam
            // testvector TypeParam, INTEGER:msgId
            (*templ).add_paramtype("TypeParam").add_paramtype("INTEGER", "msgId");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << asn1_builder::build(                   //
                              "commandId", asn1_entity_integer,  //
                              [&](asn1_object* builtin2) -> void {
                                  builtin2->get_constraints().add(new asn1_constraint_single_value_i(asn1_parameter::value<int64>(templ, "INTEGER", "msgId")));
                              })  //
                       << new asn1_builtin_type("timestamp", asn1_entity_generalizedtime) << new asn1_parameter(templ, "data", "TypeParam");
            });
            return obj;
        });
    auto example7_inst4 = example7_type4->specialize("ReadUserCmd", {{"UserReadRequest"}, {101}});

    auto example7_type5 = asn1_parameterized_type::define(  //
        "ALGORITHM-CONTAINER",                              //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            (*templ).add_paramtype("OBJECT IDENTIFIER", "algorithmOid").add_paramtype("TypeParam");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << asn1_builder::build(                 //
                              "algorithmId", asn1_entity_oid,  //
                              [&](asn1_object* builtin2) -> void {
                                  builtin2->get_constraints().add(
                                      new asn1_constraint_single_value_s(asn1_parameter::value<std::string>(templ, "OBJECT IDENTIFIER", "algorithmOid")));
                              })  //
                       << new asn1_parameter(templ, "parameters", "TypeParam");
            });
            return obj;
        });
    // 2.16.840.1.101.3.4.2 NIST Secure Hash Algorithms
    // 2.16.840.1.101.3.4.2.1 SHA-256
    // 2.16.840.1.101.3.4.2.2 SHA-384
    // 2.16.840.1.101.3.4.2.3 SHA-512
    // 2.16.840.1.101.3.4.2.4 SHA-224
    // 2.16.840.1.101.3.4.2.5 SHA-512/224
    // 2.16.840.1.101.3.4.2.6 SHA-512/256
    // 2.16.840.1.101.3.4.2.7 SHA3-224
    // 2.16.840.1.101.3.4.2.8 SHA3-256
    auto example7_inst5 = example7_type5->specialize(
        "Sha256Container", {{"{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashalgs(2) 1}"}, {"OCTET STRING"}});

    auto example7_type6 = asn1_parameterized_type::define(  //
        "SECURE-MESSAGE",                                   //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            (*templ).add_paramtype("BOOLEAN", "isEncrypted").add_paramtype("TypeParam");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << new asn1_builtin_type("flagEncrypted", asn1_entity_boolean, asn1_parameter::value<variant>(templ, "BOOLEAN", "isEncrypted"))
                       << new asn1_parameter(templ, "payload", "TypeParam");
            });
            return obj;
        });
    auto example7_inst6_1 = example7_type6->specialize("EncryptedMessage", {{true}, {"OCTET STRING"}});
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
    auto example7_inst6_2 = example7_type6->specialize("PlainMessage", {{false}, {"VisibleString"}});
#endif

    auto example7_type7 = asn1_referenced_type::define("ProtocolVersion", new asn1_enum({{"v1", 1}, {"v2", 2}, {"v3", 3}}));

    auto example7_type8 = asn1_parameterized_type::define(  //
        "HEADER-ENVELOPE",                                  //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            (*templ).add_paramtype("ProtocolVersion", "ver").add_paramtype("TypeParam");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << asn1_referenced_type::refer("version", "ProtocolVersion", asn1_parameter::value<variant>(templ, "ProtocolVersion", "ver"))
                       << new asn1_parameter(templ, "data", "TypeParam");
            });
            return obj;
        });
    auto example7_inst8 = example7_type8->specialize("V2Envelope", {{"v2"}, {"PrintableString"}});

    auto example7_type9 = asn1_parameterized_type::define(  //
        "PACKET-HEADER",                                    //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            (*templ).add_paramtype("OCTET STRING", "signature").add_paramtype("TypeParam");
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << asn1_builder::build(                 //
                              "magic", asn1_entity_octstring,  //
                              [&](asn1_object* builtin2) -> void {
                                  builtin2->get_constraints()
                                      .add(new asn1_constraint_size_i(new asn1_constraint_single_value_i(4)))
                                      .add(new asn1_constraint_single_value_i(asn1_parameter::value<int64>(templ, "OCTET STRING", "signature")));
                              })
                       << new asn1_integer("sequence") << new asn1_parameter(templ, "payload", "TypeParam");
            });
            return obj;
        });
    auto example7_inst9 = example7_type9->specialize("Pkt1Header", {{"'404B5431'H"}, {"IA5String"}});

    auto example7_type10 = asn1_parameterized_type::define(  //
        "SENSOR-DATA",                                       //
        [](asn1_parameterized_type* templ) -> asn1_object* {
            auto obj = asn1_builder::build(asn1_entity_sequence, [templ](asn1_object* builtin) -> void {
                auto seq = static_cast<asn1_sequence*>(builtin);
                (*seq) << new asn1_integer("sensorId")
                       << asn1_builder::build(               //
                              "limitVal", asn1_entity_real,  //
                              [&](asn1_object* builtin2) -> void {
                                  builtin2->get_constraints().add(new asn1_constraint_single_value_f(asn1_parameter::value<double>(templ, "REAL", "threshold")));
                              })
                       << new asn1_sequence_of("readings", asn1_entity_real);
            });
            return obj;
        });
    auto example7_inst10 = example7_type10->specialize("TemperatureSensor", {{98.6}});

    struct testvector {
        const char* text;
        asn1_object* object;
        const char* expect;
    } table[] = {
        {
            "example6_type1.asn1 #1",
            example6_type1,
            "Envelope {TypeParameter} ::= SEQUENCE {version INTEGER, messageId OCTET STRING (SIZE(16)), payload TypeParameter}",
        },
        {
            "example6_type1.asn1 #1",
            example6_inst1,
            "ActualMessage ::= Envelope {INTEGER}",
        },
        {
            "example7.asn1 #1",
            example7_type1,
            "FRAME {TypeParam, INTEGER:maxSize} ::= SEQUENCE {header INTEGER, payload TypeParam, length INTEGER (0..maxSize)}",
        },
        {
            "example7.asn1 #1",
            example7_inst1,
            "MyPacket ::= FRAME {OCTET STRING, 1024}",
        },
        {
            "example7.asn1 #2",
            example7_type2,
            "HEADER {INTEGER:defaultPriority} ::= SEQUENCE {version INTEGER, priority INTEGER DEFAULT defaultPriority}",
        },
        {
            "example7.asn1 #2",
            example7_inst2,
            "ControlHeader ::= HEADER {5}",
        },
        {
            "example7.asn1 #3",
            example7_type3,
            "TLV-BUFFER {TypeParam, INTEGER:maxLen} ::= SEQUENCE {allocatedLength INTEGER (0..65535), maxCapacity INTEGER (maxLen), payload TypeParam}",
        },
        {
            "example7.asn1 #3",
            example7_inst3,
            "MyBuffer ::= TLV-BUFFER {OCTET STRING, 2048}",
        },
        {
            "example7.asn1 #4",
            example7_type4,
            "COMMAND-ENVELOPE {TypeParam, INTEGER:msgId} ::= SEQUENCE {commandId INTEGER (msgId), timestamp GeneralizedTime, data TypeParam}",
        },
        {
            "example7.asn1 #4",
            example7_inst4,
            "ReadUserCmd ::= COMMAND-ENVELOPE {UserReadRequest, 101}",
        },
        {
            "example7.asn1 #5",
            example7_type5,
            "ALGORITHM-CONTAINER {OBJECT IDENTIFIER:algorithmOid, TypeParam} ::= SEQUENCE {algorithmId OBJECT IDENTIFIER (algorithmOid), parameters TypeParam}",
        },
        {
            "example7.asn1 #5",
            example7_inst5,
            // TODO {id(num) id(num) id} to oid
            "Sha256Container ::= "  //
            "ALGORITHM-CONTAINER {{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashalgs(2) 1}, OCTET STRING}",
        },
        {
            "example7.asn1 #6",
            example7_type6,
            "SECURE-MESSAGE {BOOLEAN:isEncrypted, TypeParam} ::= SEQUENCE {flagEncrypted BOOLEAN DEFAULT isEncrypted, payload TypeParam}",
        },
        {
            "example7.asn1 #6",
            example7_inst6_1,
            "EncryptedMessage ::= SECURE-MESSAGE {TRUE, OCTET STRING}",
        },
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
        {
            "example7.asn1 #6",
            example7_inst6_2,
            "PlainMessage ::= SECURE-MESSAGE {FALSE, VisibleString}",
        },
#endif
        {
            "example7.asn1 #7",
            example7_type7,
            "ProtocolVersion ::= ENUMERATED {v1(1), v2(2), v3(3)}",
        },
        {
            "example7.asn1 #8",
            example7_type8,
            "HEADER-ENVELOPE {ProtocolVersion:ver, TypeParam} ::= SEQUENCE {version ProtocolVersion DEFAULT ver, data TypeParam}",
        },
        {
            "example7.asn1 #8",
            example7_inst8,
            "V2Envelope ::= HEADER-ENVELOPE {v2, PrintableString}",
        },
        {
            "example7.asn1 #9",
            example7_type9,
            // (SIZE(4)) (signature)
            // (SIZE(4), signature)
            "PACKET-HEADER {OCTET STRING:signature, TypeParam} ::= SEQUENCE {magic OCTET STRING (SIZE(4), signature), sequence INTEGER, payload TypeParam}",
        },
        {
            "example7.asn1 #9",
            example7_inst9,
            "Pkt1Header ::= PACKET-HEADER {'404B5431'H, IA5String}",
        },
        {
            "example7.asn1 #10",
            example7_type10,
            "SENSOR-DATA {REAL:threshold} ::= SEQUENCE {sensorId INTEGER, limitVal REAL (threshold), readings SEQUENCE OF REAL}",
        },
        {
            "example7.asn1 #10",
            example7_inst10,
            "TemperatureSensor ::= SENSOR-DATA {98.6}",
        },
    };

    for (const auto& entry : table) {
        basic_stream bs;
        entry.object->publish(&bs);
        _logger->writeln(bs);
        _test_case.assert(bs == entry.expect, __FUNCTION__, "%s", entry.text);
        entry.object->release();
    }
}

void test_parameterized2() {
    _test_case.begin("parameterized type");

    return_t ret = errorcode_t::success;

    parse_tree pt;
    asn1_loader loader;

    // intentionally split into several stages for testing and verification.

    // step.1
    ret = loader.load(example_parameterized, strlen(example_parameterized), &pt);
    _test_case.test(ret, __FUNCTION__, "loader");

    dump_parse_tree(&pt);

    // step.2
    asn1_build_resultset result;
    auto publisher = asn1_advisor::get_instance()->get_publisher();
    ret = publisher->build(&pt, result);
    _test_case.test(ret, __FUNCTION__, "publish");
}

void test_parameterized3() {
    // parameterized value
    // example6_type1.asn1
    // example7.asn1
}

void testcase_parameterized() {
    test_parameterized1();
    // test_parameterized2();
    // test_parameterized3();
}
