/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_capacity.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_capacity() {
    _test_case.begin("byte capacity YAML");

    auto lambda_test_unsigned_byte_capacity = [&](const YAML::Node& items) -> void {
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
    auto lambda_test_signed_byte_capacity = [&](const YAML::Node& items) -> void {
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

    YAML::Node testvector = YAML::LoadFile("./testvector_capacity.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "UNSIGNED BYTE CAPACITY") {
                lambda_test_unsigned_byte_capacity(items);
            } else if (schema == "SIGNED BYTE CAPACITY") {
                lambda_test_signed_byte_capacity(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_capacity() { test_yaml_testvector_capacity(); }
