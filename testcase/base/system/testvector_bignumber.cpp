/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_bignumber.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_bignumber() {
    _test_case.begin("bignumber YAML");

    YAML::Node testvector = YAML::LoadFile("./testvector_bignumber.yml");
    auto examples = testvector["testvector"];
    if (examples) {
        auto lambda_readstring = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto hex = item["hex"].as<std::string>();
                    auto dec = item["dec"].as<std::string>();

                    bignumber bn1 = hex;
                    bignumber bn2 = dec;

                    bn1.dump([&](const binary_t& bin) -> void { _logger->hdump("from hexvalue", bin, 16, 3); });
                    bn2.dump([&](const binary_t& bin) -> void { _logger->hdump("from decvalue", bin, 16, 3); });

                    _test_case.assert(bn1 == bn2, __FUNCTION__, "compare");
                    _test_case.assert(bn1.str() == dec, __FUNCTION__, "base16 %s", dec.c_str());
                }
            }
        };

        auto lambda_arithmetic_operations = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto node_int1 = item["int1"];
                    auto node_int2 = item["int2"];
                    if (node_int1 && node_int2) {
                        bignumber int1 = node_int1.as<std::string>();
                        bignumber int2 = node_int2.as<std::string>();

                        auto node_add = item["add"];
                        if (node_add) {
                            bignumber value_add = node_add.as<std::string>();
                            auto test = ((int1 + int2) == value_add);
                            _test_case.assert(test, __FUNCTION__, "%s + %s = %s", int1.str().c_str(), int2.str().c_str(), value_add.str().c_str());
                        }

                        auto node_sub = item["sub"];
                        if (node_sub) {
                            bignumber value_sub = node_sub.as<std::string>();
                            auto test = ((int1 - int2) == value_sub);
                            _test_case.assert(test, __FUNCTION__, "%s - %s = %s", int1.str().c_str(), int2.str().c_str(), value_sub.str().c_str());
                        }

                        auto node_mul = item["mul"];
                        if (node_mul) {
                            bignumber value_mul = node_mul.as<std::string>();
                            auto test = ((int1 * int2) == value_mul);
                            _test_case.assert(test, __FUNCTION__, "%s * %s = %s", int1.str().c_str(), int2.str().c_str(), value_mul.str().c_str());
                        }

                        auto node_div = item["div"];
                        if (node_div) {
                            bignumber value_div = node_div.as<std::string>();
                            auto test = ((int1 / int2) == value_div);
                            _test_case.assert(test, __FUNCTION__, "%s / %s = %s", int1.str().c_str(), int2.str().c_str(), value_div.str().c_str());
                        }

                        auto node_mod = item["mod"];
                        if (node_mod) {
                            bignumber value_mod = node_mod.as<std::string>();
                            auto test = ((int1 % int2) == value_mod);
                            _test_case.assert(test, __FUNCTION__, "%s %% %s = %s", int1.str().c_str(), int2.str().c_str(), value_mod.str().c_str());
                        }

                        auto node_lshift1 = item["lshift1"];
                        if (node_lshift1) {
                            bignumber value_lshift1 = node_lshift1.as<std::string>();
                            auto test = ((int1 << 1) == value_lshift1);
                            _test_case.assert(test, __FUNCTION__, "%s << %i = %s", int1.str().c_str(), 1, value_lshift1.str().c_str());
                        }

                        auto node_rshift1 = item["rshift1"];
                        if (node_rshift1) {
                            bignumber value_rshift1 = node_rshift1.as<std::string>();
                            auto test = ((int1 >> 1) == value_rshift1);
                            _test_case.assert(test, __FUNCTION__, "%s >> %i = %s", int1.str().c_str(), 1, value_rshift1.str().c_str());
                        }
                    } else {
                        _test_case.assert(false, __FUNCTION__, "invalid test vector");
                    }
                }
            }
        };

        auto lambda_intminmax = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto node_bits = item["bits"];
                    if (node_bits) {
                        bignumber bnbits = node_bits.as<std::string>();
                        if (bnbits < 1) {
                            _test_case.assert(false, __FUNCTION__, "invalid test vector");
                        } else {
                            auto node_intmin = item["intmin"];
                            auto node_intmax = item["intmax"];
                            auto node_uintmax = item["uintmax"];
                            if (node_intmin) {
                                bignumber intmin = -(bignumber(1) << (bnbits - 1));
                                bignumber value_intmin = node_intmin.as<std::string>();
                                _test_case.assert(intmin == value_intmin, __FUNCTION__, "int%s.min", bnbits.str().c_str());
                            }
                            if (node_intmax) {
                                bignumber intmax = (bignumber(1) << (bnbits - 1)) - bignumber(1);
                                bignumber value_intmax = node_intmax.as<std::string>();
                                _test_case.assert(intmax == value_intmax, __FUNCTION__, "int%s.max", bnbits.str().c_str());
                            }
                            if (node_uintmax) {
                                bignumber uintmax = (bignumber(1) << bnbits) - bignumber(1);
                                bignumber value_uintmax = node_uintmax.as<std::string>();
                                _test_case.assert(uintmax == value_uintmax, __FUNCTION__, "uint%s.max", bnbits.str().c_str());
                            }
                        }
                    }
                }
            }
        };

        auto lambda_bits_operations = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto node_int1 = item["int1"];
                    auto node_int2 = item["int2"];
                    if (node_int1 && node_int2) {
                        bignumber int1 = node_int1.as<std::string>();
                        bignumber int2 = node_int2.as<std::string>();

                        auto node_and = item["and"];
                        if (node_and) {
                            bignumber bnand = node_and.as<std::string>();
                            _test_case.assert((int1 & int2) == bnand, __FUNCTION__, "%s & %s = %s", int1.str().c_str(), int2.str().c_str(),
                                              bnand.str().c_str());
                        }

                        auto node_or = item["or"];
                        if (node_or) {
                            bignumber bnor = node_or.as<std::string>();
                            _test_case.assert((int1 | int2) == bnor, __FUNCTION__, "%s | %s = %s", int1.str().c_str(), int2.str().c_str(), bnor.str().c_str());
                        }

                        auto node_xor = item["xor"];
                        if (node_xor) {
                            bignumber bnxor = node_xor.as<std::string>();
                            _test_case.assert((int1 ^ int2) == bnxor, __FUNCTION__, "%s ^ %s = %s", int1.str().c_str(), int2.str().c_str(),
                                              bnxor.str().c_str());
                        }
                    } else {
                        _test_case.assert(false, __FUNCTION__, "invalid test vector");
                    }
                }
            }
        };

        auto lambda_negative = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto node_value = item["value"];
                    auto node_expect = item["expect"];
                    if (node_value && node_expect) {
                        bignumber bnvalue = node_value.as<std::string>();
                        bignumber bnexpect = node_expect.as<std::string>();
                        _test_case.assert(bnvalue.neg() == bnexpect, __FUNCTION__, "%s.neg() == %s", bnvalue.str().c_str(), bnexpect.str().c_str());
                    }
                }
            }
        };

        auto lambda_modpow = [&](const YAML::Node& example) -> void {
            auto items = example["items"];
            if (items && items.IsSequence()) {
                for (const auto& item : items) {
                    auto node_base = item["base"];
                    auto node_exp = item["exp"];
                    auto node_mod = item["mod"];
                    auto node_expect = item["expect"];
                    if (node_base && node_exp && node_mod && node_expect) {
                        bignumber bnbase = node_base.as<std::string>();
                        bignumber bnexp = node_exp.as<std::string>();
                        bignumber bnmod = node_mod.as<std::string>();
                        bignumber bnexpect = node_expect.as<std::string>();
                        bignumber bn = bignumber::modpow(bnbase, bnexp, bnmod);
                        _test_case.assert(bn == bnexpect, __FUNCTION__, "%s ^ %s %% %s = %s", bnbase.str().c_str(), bnexp.str().c_str(), bnmod.str().c_str(),
                                          bnexpect.str().c_str());
                    } else {
                        _test_case.assert(false, __FUNCTION__, "invalid test vector");
                    }
                }
            }
        };

        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());
            if (text_example == "readstring") {
                lambda_readstring(example);
            } else if (text_example == "arithmetic_operations") {
                lambda_arithmetic_operations(example);
            } else if (text_example == "intminmax") {
                lambda_intminmax(example);
            } else if (text_example == "bits_operations") {
                lambda_bits_operations(example);
            } else if (text_example == "negative") {
                lambda_negative(example);
            } else if (text_example == "modpow") {
                lambda_modpow(example);
            }
        }
    }
}

void testcase_testvector_bignumber() { test_yaml_testvector_bignumber(); }
