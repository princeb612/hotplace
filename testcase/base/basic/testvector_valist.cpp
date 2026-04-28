/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_valist.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_valist() {
    _test_case.begin("valist YAML");

    auto lambda_test_valist_sprintf = [&](const YAML::Node& args, const YAML::Node& items) -> void {
        valist va;
        for (const auto& arg : args) {
            std::string type = arg["type"].as<std::string>();
            if (type == "float") {
                va << arg["value"].as<float>();
            } else if (type == "int") {
                va << arg["value"].as<int>();
            } else if (type == "string") {
                va << arg["value"].as<std::string>().c_str();
            }
        }

        for (const auto& item : items) {
            std::string text_fmt = item["format"].as<std::string>();
            std::string text_exp = item["expect"].as<std::string>();

            basic_stream bs;
            sprintf(&bs, text_fmt.c_str(), va);
            _logger->writeln("out %s", bs.c_str());
            _logger->writeln("exp %s", text_exp.c_str());
            _test_case.assert(bs == text_exp, __FUNCTION__, "format string %s", text_fmt.c_str());
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_valist.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();

            if (schema == "VALIST SPRINTF") {
                auto args = example["args"];
                auto items = example["items"];
                lambda_test_valist_sprintf(args, items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_valist() { test_yaml_testvector_valist(); }
