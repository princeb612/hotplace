/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_kmp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_kmp() {
    _test_case.begin("KMP YAML");

    enum option_flag_t {
        option_wildcards = 1,
        option_ignorecase = 2,
    };

    auto lambda_yaml_test_item = [&](const YAML::Node& item) -> void {
        auto text = item["item"].as<std::string>("");
        auto pattern = item["pattern"].as<std::string>("");
        auto match_node = item["match"];

        _logger->writeln("item    %s", text.c_str());
        _logger->writeln("pattern %s", pattern.c_str());

        t_kmp<char> kmp;
        kmp.learn(pattern.c_str(), pattern.size());

        // graphic
        auto lambda_graphic = [](const std::string& pattern, const std::string& words, const std::set<size_t>& results, basic_stream& bs) -> void {
            bs << words << "\n";
            auto size_pattern = pattern.size();
            for (auto pos : results) {
                bs.printf("%*s", (int)pos, "");
                bs << pattern;
                bs.fill(words.size() - pos - size_pattern + 1, '-');
                bs.println(R"(> pattern "%.*s")", pattern.size(), pattern.data());
            }
        };

        if (match_node && match_node.IsMap()) {
            for (const auto& match : match_node) {
                std::set<size_t> expects;
                std::set<size_t> results;

                auto key_node = match.first;
                auto value_node = match.second;

                auto words = key_node.as<std::string>("");

                for (const auto& vn : value_node) {
                    auto i = vn.as<size_t>(0);
                    expects.insert(i);
                }

                size_t pos = 0;
                do {
                    pos = kmp.search(words.c_str(), words.size(), pos);
                    if (t_kmp<char>::npos == pos) {
                        break;
                    }
                    results.insert(pos);
                    ++pos;
                } while (1);

                basic_stream bs;
                lambda_graphic(pattern, words, results, bs);
                _logger->write(bs);

                _test_case.assert(results == expects, __FUNCTION__, R"(case: %s : "%s")", text.c_str(), words.c_str());
            }
        }
    };

    auto lambda_yaml_kmp = [&](const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                lambda_yaml_test_item(item);
            }
        }
    };

    YAML::Node testvector = YAML::LoadFile("testvector_kmp.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>("");
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>("");
            auto items = example["items"];

            if (schema == "KMP") {
                lambda_yaml_kmp(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_kmp() { test_yaml_testvector_kmp(); }
