/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_floatingpoint.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_yaml_testvector_floatingpoint() {
    _test_case.begin("floating point YAML");

    enum op {
        op_add = 1,
        op_sub = 2,
        op_mult = 3,
        op_div = 4,
    };

    auto lambda_arithmetic = [&](const std::string& a, const std::string& b, int op, const std::string& expect) -> void {
        valist va;
        basic_stream fmt;
        basic_stream bs;
        floating_point lhs;
        floating_point rhs;
        floating_point value;
        floating_point res;

        try {
            lhs = a;
            rhs = b;
            fmt << "{1}";
            switch (op) {
                case op_add:
                    fmt << " + ";
                    res = lhs + rhs;
                    break;
                case op_sub:
                    fmt << " - ";
                    res = lhs - rhs;
                    break;
                case op_mult:
                    fmt << " * ";
                    res = lhs * rhs;
                    break;
                case op_div:
                    fmt << " / ";
                    res = lhs / rhs;
                    break;
            }
            fmt << "{2} = {3} expect {4}";
            va << lhs.str() << rhs.str() << res.str() << expect;

            bs.vaprintf(fmt.c_str(), va);
            _logger->writeln(bs);
            try {
                value = expect;
                _logger->writeln("precision(32) -> %s", value.fstr(32).c_str());
                _logger->writeln("c_str()       -> %s", value.str().c_str());
                auto test = (res == value);
                _test_case.assert(test, __FUNCTION__, "%s", bs.c_str());
            } catch (...) {
                _test_case.assert(false, __FUNCTION__, "error %s", bs.c_str());
            }
        } catch (...) {
            _test_case.assert(false, __FUNCTION__, "error");
        }
    };

    auto lambda_yaml_floatingpoint = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto node_float1 = item["float1"];
                auto node_float2 = item["float2"];
                if (node_float1 && node_float2) {
                    auto float1 = node_float1.as<std::string>("");
                    auto float2 = node_float2.as<std::string>("");

                    auto node_add = item["add"];
                    if (node_add) {
                        std::string value_add = node_add.as<std::string>("0.0");
                        lambda_arithmetic(float1, float2, op_add, value_add);
                    }

                    auto node_sub = item["sub"];
                    if (node_sub) {
                        std::string value_sub = node_sub.as<std::string>("0.0");
                        lambda_arithmetic(float1, float2, op_sub, value_sub);
                    }

                    auto node_mul = item["mul"];
                    if (node_mul) {
                        std::string value_mul = node_mul.as<std::string>("0.0");
                        lambda_arithmetic(float1, float2, op_mult, value_mul);
                    }

                    auto node_div = item["div"];
                    if (node_div) {
                        std::string value_div = node_div.as<std::string>("0.0");
                        lambda_arithmetic(float1, float2, op_div, value_div);
                    }
                } else {
                    _test_case.assert(false, __FUNCTION__, "invalid test vector");
                }
            }
        }
    };

    yaml_testcase test;
    test.add("FLOATINGPOINT", lambda_yaml_floatingpoint).run("testvector_floatingpoint.yml");
}

void testcase_testvector_floatingpoint() { test_yaml_testvector_floatingpoint(); }
