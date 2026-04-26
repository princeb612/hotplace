/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_capacity.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_capacity() {
    _test_case.begin("byte capacity YAML");

    YAML::Node testvector = YAML::LoadFile("./testvector_capacity.yml");
    auto examples = testvector["testvector"];

    auto lambda_test_unsigned_byte_capacity = [&](const YAML::Node& example) -> void {
        auto items = example["items"];
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                bignumber bn = item["value"].as<std::string>();
                auto expect = item["expect"].as<int>();
                auto value = bn.unsigned_byte_capacity();
                _logger->writeln("%s %s byte capacity %zi expect %i", bn.str().c_str(), bn.hex().c_str(), value, expect);
                _test_case.assert(value == expect, __FUNCTION__, "%s %s byte capacity %i", bn.str().c_str(), bn.hex().c_str(), expect);
            }
        }
    };
    auto lambda_test_signed_byte_capacity = [&](const YAML::Node& example) -> void {
        auto items = example["items"];
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                bignumber bn = item["value"].as<std::string>();
                auto expect = item["expect"].as<int>();
                auto value = bn.signed_byte_capacity();
                _logger->writeln("%s %s byte capacity %zi expect %i", bn.str().c_str(), bn.hex().c_str(), value, expect);
                _test_case.assert(value == expect, __FUNCTION__, "%s %s byte capacity %i", bn.str().c_str(), bn.hex().c_str(), expect);
            }
        }
    };

    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());
            if (text_example == "unsigned_byte_capacity") {
                lambda_test_unsigned_byte_capacity(example);
            } else if (text_example == "signed_byte_capacity") {
                lambda_test_signed_byte_capacity(example);
            }
        }
    }
}

void testcase_testvector_capacity() { test_yaml_testvector_capacity(); }
