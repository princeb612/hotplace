/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_ahocorasick.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_yaml_testvector_ahocorasick() {
    _test_case.begin("aho corasick YAML");

    enum option_flag_t {
        option_wildcards = 1,
        option_ignorecase = 2,
    };

    auto lambda_builder = [](uint8 option) -> t_aho_corasick_t<char, char>* {
        t_aho_corasick_t<char, char>* ac = nullptr;
        if (0 == option) {
            ac = new t_aho_corasick<char>();
        } else if ((option_wildcards) == (option & (option_wildcards | option_ignorecase))) {
            ac = new t_aho_corasick_wildcard<char>('?', '*');
        } else if ((option_wildcards | option_ignorecase) == (option & (option_wildcards | option_ignorecase))) {
            ac = new t_aho_corasick_wildcard<char, char, memberof_tolower_handler>('?', '*');
        }
        return ac;
    };

    auto lambda_yaml_test_item = [&](const YAML::Node& item) -> void {
        auto text = item["item"].as<std::string>("");
        auto input = item["input"].as<std::string>("");
        auto option_node = item["option"];
        auto pattern_node = item["pattern"];

        uint8 value_option = 0;

        _logger->writeln("item  %s", text.c_str());
        _logger->writeln("input %s", input.c_str());

        if (option_node && option_node.IsSequence()) {
            auto options = option_node.as<std::vector<std::string>>();
            for (const auto& opt : options) {
                if (opt == "wildcards") {
                    value_option |= option_wildcards;
                } else if (opt == "ignorecase") {
                    value_option |= option_ignorecase;
                }
                _logger->writeln("option %s", opt.c_str());
            }
        }

        auto ac = lambda_builder(value_option);
        std::multimap<range_t, size_t> expects;

        if (pattern_node && pattern_node.IsMap()) {
            size_t id_pattern = 0;
            for (const auto& pattern : pattern_node) {
                auto key_node = pattern.first;
                auto value_node = pattern.second;

                auto key = key_node.as<std::string>("");
                ac->insert(key.c_str(), key.size());
                _logger->writeln("words %s", key.c_str());

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
                                        expects.emplace(r, id_pattern);
                                        _logger->writeln("- [%zi, %zi]", r.begin, r.end);
                                    }
                                    ++pos;
                                }
                            }
                        }
                    }
                }

                ++id_pattern;
            }
        }

        ac->build();
        auto results = ac->search(input.c_str(), input.size());
        auto test = equal(expects, results);

        // graphic
        auto lambda_graphic = [&](basic_stream& bs) -> void {
            _logger->writeln(input);
            for (const auto& item : results) {
                const auto& r = item.first;
                size_t id_pattern = item.second;
                std::vector<char> pattern;

                ac->get_pattern(id_pattern, pattern);

                bs.printf("%*s", (int)r.begin, "");
                bs << input.substr(r.begin, r.end - r.begin + 1);
                bs.fill(input.size() - r.end, '-');
                bs.println(R"(> pattern "%.*s")", pattern.size(), pattern.data());
            }
        };
        _logger->write(lambda_graphic);

        _test_case.assert(test, __FUNCTION__, R"(case: %s input: "%s")", text.c_str(), input.c_str());

        delete ac;
    };

    auto lambda_yaml_ahocorasick = [&](const YAML::Node& example, const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                lambda_yaml_test_item(item);
            }
        }
    };

    yaml_testcase test;
    test.add("AHO CORASICK", lambda_yaml_ahocorasick).run("testvector_ahocorasick.yml");
}

void testcase_testvector_ahocorasick() { test_yaml_testvector_ahocorasick(); }
