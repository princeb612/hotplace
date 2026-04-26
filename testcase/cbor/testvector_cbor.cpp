/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_rfc7049.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include "sample.hpp"

void do_parse_cbor_routine(const char* text, const char* input, const char* diagnostic) {
    return_t ret = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* handle = nullptr;
    ansi_string bs;
    binary_t bin;
    bool test = false;
    bool test2 = false;

    reader.open(&handle);
    ret = reader.parse(handle, input);  // read
    if (errorcode_t::success == ret) {
        reader.publish(handle, &bs);   // diagnostic
        reader.publish(handle, &bin);  // concise
        reader.close(handle);

        {
            test_case_notimecheck notimecheck(_test_case);

            std::string b16;
            base16_encode(bin, b16);
            _logger->writeln("diagnostic %s", bs.c_str());
            _logger->writeln("cbor       %s", b16.c_str());

            test = (bin == base16_decode(input));
            if (false == test) {
                test = (bs == diagnostic);  // e.g. Infinity == 0xf97c00 == 0xfa7f800000 == 0xfb7ff0000000000000
            }
        }
    }

    _test_case.assert(test, __FUNCTION__, text);
}

void test_yaml_testvector_cbor() {
    _test_case.begin("test3.CBOR YAML");
    YAML::Node testvector = YAML::LoadFile("./testvector_cbor.yml");
    auto examples = testvector["testvector"];
    auto lambda_test = [&](const YAML::Node& examples) -> void {
        if (examples && examples.IsSequence()) {
            for (const auto& example : examples) {
                auto items = example["items"];
                for (const auto& item : items) {
                    std::string text_item = item["item"].as<std::string>();
                    std::string text_cbor = item["cbor"].as<std::string>();
                    std::string text_diag = item["diag"].as<std::string>();
                    auto loss = item["loss"];
                    if (loss) {
                    } else {
                        do_parse_cbor_routine(text_item.c_str(), text_cbor.c_str(), rtrim(text_diag).c_str());
                    }
                }
            }
        }
    };

    lambda_test(examples);
}

void testcase_testvector_cbor() { test_yaml_testvector_cbor(); }
