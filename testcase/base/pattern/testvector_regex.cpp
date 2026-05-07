/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_regex.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_regex() {
    _test_case.begin("regex YAML");

    auto lambda_yaml_test_item = [&](const YAML::Node& item) -> void {
        auto input = item["input"].as<std::string>("");
        auto expr = item["expr"].as<std::string>("");
        auto node_results = item["results"];

        std::list<std::string> tokens_results;
        std::list<std::string> tokens_expect;
        std::list<range_t> tokens_range;

        _logger->writeln("input %s", input.c_str());
        _logger->writeln("expr  %s", expr.c_str());

        if (node_results && node_results.IsSequence()) {
            for (const auto& result : node_results) {
                auto res = result.as<std::string>("");
                _logger->writeln("expect %s", res.c_str());
                tokens_expect.push_back(std::move(res));
            }
        }

        // results as std::list<std::string>
        {
            size_t pos = 0;
            regex_token(input, expr, pos, tokens_results);
            for (auto res : tokens_results) {
                _logger->writeln("result %s", res.c_str());
            }
            _test_case.assert(tokens_results == tokens_expect, __FUNCTION__, "regex #1 results as std::list<std::string>");
        }

        // results as std::list<range_t>
        {
            size_t pos = 0;
            regex_token(input.c_str(), input.size(), expr.c_str(), pos, tokens_range);
            // rebuild
            tokens_results.clear();
            for (const auto& range : tokens_range) {
                auto res = input.substr(range.begin, range.end - range.begin);
                _logger->writeln("result %s", res.c_str());
                tokens_results.push_back(res);
            }
            _test_case.assert(tokens_results == tokens_expect, __FUNCTION__, "regex #2 results as std::list<range_t>");
        }

        // std::list<std::map<size_t, range_t>>
        {
            std::list<std::map<size_t, range_t>> tokens;
            size_t pos = 0;
            regex_tokens(input.c_str(), input.size(), expr.c_str(), pos, tokens);
            // rebuild
            tokens_results.clear();
            for (auto& token : tokens) {
                auto& range = token[0];
                auto res = input.substr(range.begin, range.end - range.begin);
                _logger->writeln("result %s", res.c_str());
                for (auto& t : token) {
                    _logger->writeln("- [%zi] %s", t.first, input.substr(t.second.begin, t.second.end - t.second.begin).c_str());
                }
                tokens_results.push_back(res);
            }
            _test_case.assert(tokens_results == tokens_expect, __FUNCTION__, "regex #3 results as std::list<std::map<size_t, range_t>>");
        }
    };

    auto lambda_yaml_regex = [&](const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                lambda_yaml_test_item(item);
            }
        }
    };

    YAML::Node testvector = YAML::LoadFile("testvector_regex.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>("");
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>("");
            auto items = example["items"];

            if (schema == "REGEX") {
                lambda_yaml_regex(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_regex() { test_yaml_testvector_regex(); }
