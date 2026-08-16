/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_der.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include "sample.hpp"

void test_yaml_testvector_der() {
    _test_case.begin("DER YAML");

    auto lambda_yaml_asn1der = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        for (const auto& item : items) {
            std::string text_item = item["item"].as<std::string>("");
            std::string text_der = item["der"].as<std::string>("");
            binary_t bin = base16_decode_rfc(text_der);

            {
                asn1_runtime reader;
                size_t pos = 0;
                auto stream = bin.data();
                auto size = bin.size();
                auto test = reader.read_weakly_typed(stream, size, pos);

                basic_stream bs_type;
                basic_stream bs_value;
                binary_t bin_encoded;
                reader.notation(&bs_type);
                reader.publish(&bs_value);
                reader.publish(&bin_encoded);

                _logger->write([&](basic_stream& dbs) -> void {
                    valist va;
                    va << bs_type << bs_value << bin_encoded;
                    dbs.println("decode and encode");
                    dbs.vaprintln("> notation {1}", va);
                    dbs.vaprintln("> value    {2}", va);
                    dbs.vaprintln("> DER      {3:x}", va);
                });
                _logger->dump(bin_encoded);

                _test_case.test(test, __FUNCTION__, "read and decode %s", text_item.c_str());
                _test_case.assert(pos == size, __FUNCTION__, "complete stream consumed %s", text_item.c_str());
                // TODO
                // _test_case.assert(bin == bin_encoded, __FUNCTION__, "decode and encode %s", text_item.c_str());
            }
        }
    };

    yaml_testcase test;
    test.add("DER", lambda_yaml_asn1der).run("testvector_der.yml");
}

void testcase_testvector_der() { test_yaml_testvector_der(); }
