/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/test/testcase/io/parser/asn1module.hpp>
#include <hotplace/test/testcase/io/sample.hpp>

void test_yaml_testvector_parser() {
    t_aho_corasick_reducer<uint32, parser_token, memberof_parser_token> ac;
    prepare_asn1module_reducer(ac);

    auto lambda_yaml_asn1parser = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        asn1_value value(nullptr);

        return_t test = errorcode_t::success;
        lexical_context context;
        asn1_runtime runtime;  // automatic
        for (const auto& item : items) {
            std::string text_item = item["item"].as<std::string>("");
            std::string text_asn1 = item["asn1"].as<std::string>("");
            auto expect_node = item["expect"];

            std::multimap<std::string, range_t> expects;

            if (expect_node && expect_node.IsMap()) {
                for (const auto& pattern : expect_node) {
                    auto key_node = pattern.first;
                    auto value_node = pattern.second;

                    auto key = key_node.as<std::string>("");

                    if (value_node && value_node.IsSequence()) {
                        for (const auto& range_node : value_node) {
                            if (range_node.IsSequence()) {
                                range_t r;
                                if (range_node.size() == 2) {
                                    size_t pos = 0;
                                    for (const auto& range : range_node) {
                                        auto value = range.as<size_t>(0);
                                        if (0 == pos % 2) {
                                            r.begin = value;
                                        } else {
                                            r.end = value;
                                            expects.emplace(key, r);
                                            // _logger->writeln("- %s [%zi, %zi]", key.c_str(), r.begin, r.end);
                                        }
                                        ++pos;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            std::vector<parser_token> tokens;
            std::multimap<range_t, size_t> results;
            test = ac_search(ac, text_asn1.c_str(), text_asn1.size(), tokens, results);
            ac_printall(ac, tokens, results);
            _test_case.test(test, __FUNCTION__, R"(item "%s")", text_item.c_str());

            // the rule ID may change if `prepare_asn1module_reducer` is modified.

            std::multimap<std::string, range_t> formatted;
            for (const auto& pair : results) {
                const auto& r = pair.first;
                auto pid = pair.second;

                std::string key;
                switch (pid) {
                    case 6:
                        key = "header_clause";
                        break;
                    case 7:
                        key = "exports_clause";
                        break;
                    case 8:
                        key = "imports_clause";
                        break;
                    default:
                        break;
                }

                formatted.emplace(key, r);
            }
            bool cmp = equal(expects, formatted);
            _test_case.assert(cmp, __FUNCTION__, "compare expected header, exports, imports");
        }
    };

    yaml_testcase test;
    test.add("PARSER", lambda_yaml_asn1parser).run("testvector_parser.yml");
}

void testcase_testvector_parser() { test_yaml_testvector_parser(); }
