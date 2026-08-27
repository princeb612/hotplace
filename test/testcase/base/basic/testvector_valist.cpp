/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_valist.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_yaml_testvector_valist() {
    _test_case.begin("valist YAML");

    auto lambda_yaml_valist_sprintf = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        auto args = example["args"];

        /**
         * [IMPORTANT] yaml-cpp negative integer value
         * auto value = static_cast<`cating_type`>(arg["value"].as<`abi_type`>)(0);
         */

        valist va;
        for (const auto& arg : args) {
            std::string type = arg["type"].as<std::string>("");
            if (type == "float") {
                va << arg["value"].as<float>();
            } else if (type == "int") {
                va << arg["value"].as<int>(0);
            } else if (type == "string") {
                va << arg["value"].as<std::string>("").c_str();
            } else if (type == "int8") {
                va << static_cast<int8>(arg["value"].as<int>(0));
            } else if (type == "uint8") {
                va << arg["value"].as<uint8>(0);
            } else if (type == "int16") {
                va << static_cast<int16>(arg["value"].as<int>(0));
            } else if (type == "uint16") {
                va << arg["value"].as<uint16>(0);
            } else if (type == "int32") {
                va << static_cast<int32>(arg["value"].as<int>(0));
            } else if (type == "uint32") {
                va << arg["value"].as<uint32>(0);
            } else if (type == "int64") {
                va << static_cast<int64>(arg["value"].as<long long>(0));
            } else if (type == "uint64") {
                va << arg["value"].as<uint64>(0);
            }
        }

        for (const auto& item : items) {
            std::string text_itm = item["item"].as<std::string>("");
            std::string text_fmt = item["format"].as<std::string>("");
            std::string text_exp = item["expect"].as<std::string>("");

            basic_stream bs;
            sprintf(&bs, text_fmt.c_str(), va);
            _logger->writeln("out %s", bs.c_str());
            _logger->writeln("exp %s", text_exp.c_str());
            _test_case.assert(bs == text_exp, __FUNCTION__, "%s format string %s", text_itm.c_str(), text_fmt.c_str());
        }
    };

    yaml_testcase test;
    test.add("VALIST", lambda_yaml_valist_sprintf).run("testvector_valist.yml");
}

void testcase_testvector_valist() { test_yaml_testvector_valist(); }
