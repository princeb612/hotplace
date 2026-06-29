/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_capacity.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_yaml_testvector_capacity() {
    _test_case.begin("byte capacity YAML");

    auto lambda_yaml_unsigned_byte_capacity = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                bignumber bn = item["value"].as<std::string>("");
                auto expect = item["expect"].as<unsigned int>();
                auto value = bn.unsigned_byte_capacity();
                _logger->writeln("%s %s byte capacity %zi expect %i", bn.str().c_str(), bn.hex().c_str(), value, expect);
                _test_case.assert(value == expect, __FUNCTION__, "%s %s byte capacity %i", bn.str().c_str(), bn.hex().c_str(), expect);
            }
        }
    };
    auto lambda_yaml_signed_byte_capacity = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                bignumber bn = item["value"].as<std::string>("");
                auto expect = item["expect"].as<unsigned int>();
                auto value = bn.signed_byte_capacity();
                _logger->writeln("%s %s byte capacity %zi expect %i", bn.str().c_str(), bn.hex().c_str(), value, expect);
                _test_case.assert(value == expect, __FUNCTION__, "%s %s byte capacity %i", bn.str().c_str(), bn.hex().c_str(), expect);
            }
        }
    };

    yaml_testcase test;
    test.add("UNSIGNED BYTE CAPACITY", lambda_yaml_unsigned_byte_capacity).add("SIGNED BYTE CAPACITY", lambda_yaml_signed_byte_capacity).run("testvector_capacity.yml");
}

void testcase_testvector_capacity() { test_yaml_testvector_capacity(); }
