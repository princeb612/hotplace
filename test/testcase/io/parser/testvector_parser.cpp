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
        // lexical_context context;
        asn1_runtime runtime;  // automatic

        /**
         * expect:
         *   range: [[0, 5], [10, 15]
         * results
         *   "range", {0, 5}
         *   "range", {10, 15}
         */
        auto lambda_makemap_string_ranges = [](const YAML::Node& expect_node, std::multimap<std::string, range_t>& expects) -> void {
            expects.clear();

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
                                        }
                                        ++pos;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        for (const auto& item : items) {
            std::string text_item = item["item"].as<std::string>("");
            std::string text_asn1 = item["asn1"].as<std::string>("");

            std::multimap<std::string, range_t> expects;
            lambda_makemap_string_ranges(item["expect"], expects);
            std::multimap<std::string, range_t> expect_lt;
            lambda_makemap_string_ranges(item["level_trigger"], expect_lt);
            std::multimap<std::string, range_t> expect_et;
            lambda_makemap_string_ranges(item["edge_trigger"], expect_et);

            std::vector<parser_token> tokens;
            std::multimap<range_t, size_t> results;
            test = ac_search(ac, text_asn1.c_str(), text_asn1.size(), tokens, results);
            ac_printall(ac, tokens, results);
            _test_case.test(test, __FUNCTION__, R"(item "%s")", text_item.c_str());

            // the rule ID may change if `prepare_asn1module_reducer` is modified.

            std::multimap<std::string, range_t> result_formatted;
            for (const auto& pair : results) {
                const auto& r = pair.first;
                auto pid = pair.second;

                std::string key;
                switch (pid) {
                    case 6:
                        key = "end_module";
                        break;
                    case 7:
                        key = "header_clause";
                        break;
                    case 8:
                        key = "exports_clause";
                        break;
                    case 9:
                        key = "imports_clause";
                        break;
                    default:
                        break;
                }

                result_formatted.emplace(key, r);
            }
            bool cmp = equal(expects, result_formatted);
            _test_case.assert(cmp, __FUNCTION__, "compare expected header, exports, imports");

            std::multimap<std::string, range_t> result_lt;
            auto lambda_undercontrol = [&result_lt](matched_t type, hotplace::range_t r, size_t pid) -> bool {
                result_lt.emplace((matched_t::match == type) ? "matched" : "unmatched", r);
                _logger->writeln("under control of %s [%zi..%zi]", (matched_t::match == type) ? "module parser" : "notation parser", r.begin, r.end);
                return true;  // if return false, stops
            };
            travel_ranges(trigger_t::level, results, lambda_undercontrol);
            _test_case.assert(result_lt == expect_lt, __FUNCTION__, "level trigger");

            std::multimap<std::string, range_t> result_et;
            auto lambda_switch = [&result_et](matched_t type, hotplace::range_t r, size_t pid) -> bool {
                result_et.emplace((matched_t::match == type) ? "matched" : "unmatched", r);
                _logger->writeln("switch to %s [%zi..%zi]", (matched_t::match == type) ? "module parser" : "notation parser", r.begin, r.end);
                return true;  // if return false, stops
            };
            travel_ranges(trigger_t::edge, results, lambda_switch);
            _test_case.assert(result_et == expect_et, __FUNCTION__, "edge trigger");
        }
    };

    yaml_testcase test;
    test.add("PARSER", lambda_yaml_asn1parser).run("testvector_parser.yml");
}

void testcase_testvector_parser() { test_yaml_testvector_parser(); }
