/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_aho_corasick.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_aho_corasick1() {
    _test_case.begin("aho_corasick");
    t_aho_corasick<char> ac;
    ac.insert("he", 2);
    ac.insert("she", 3);
    ac.insert("hers", 4);
    ac.insert("his", 3);
    ac.build();
    const char* source = "ahishers";
    std::multimap<range_t, size_t> result;
    std::multimap<range_t, size_t> expect = {{range_t(1, 3), 3}, {range_t(3, 5), 1}, {range_t(4, 5), 0}, {range_t(4, 7), 2}};
    result = ac.search(source, strlen(source));

    _logger->writeln(R"(source "%s")", source);
    for (auto item : result) {
        size_t begin = item.first.begin;
        size_t patid = item.second;
        std::vector<char> pat;
        ac.get_pattern(patid, pat);
        _logger->writeln(R"(pos [%zi] pattern[%i] "%.*s")", begin, patid, pat.size(), pat.data());
    }
    _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm");
}

void test_aho_corasick2() {
    _test_case.begin("aho_corasick");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, size_t> expects;  // pair(pos_occurrence, id_pattern)
    } _table[] = {
        {
            // t_aho_corasick ac;
            // ac.insert("he", 2);
            // ac.insert("she", 3);
            // ac.insert("hers", 4);
            // ac.insert("his", 3);
            // ac.build();
            // const char* source = "ahishers";
            // ac.search(source, strlen(source));
            "ahishers",
            {
                {"he", 2},
                {"she", 3},
                {"hers", 4},
                {"his", 3},
            },
            // ahishers
            //  his        (1..3)[3] his
            //    she      (3..5)[1] she
            //     he      (4..5)[0] he
            //     hers    (4..7)[2] hers
            {
                {range_t(1, 3), 3},
                {range_t(3, 5), 1},
                {range_t(4, 5), 0},
                {range_t(4, 7), 2},
            },
        },

        // other cases moved into "testvector_ahocorasick.yml"
    };

    for (auto item : _table) {
        t_aho_corasick<char> ac;
        std::multimap<range_t, size_t> expect;
        std::multimap<range_t, size_t> result;

        _logger->writeln(R"(source "%s")", item.source);
        int i = 0;
        for (auto pat : item.patterns) {
            ac.insert(pat.pattern, pat.len);
            _logger->writeln(R"(pattern[%i] "%.*s")", i++, pat.len, pat.pattern);
        }

        ac.build();
        result = ac.search(item.source, strlen(item.source));

        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, item.source + range.begin);
        }

        _test_case.assert(item.expects == result, __FUNCTION__, R"(multiple pattern search "%s")", item.source);
    }
}

void testcase_aho_corasick() {
    test_aho_corasick1();
    test_aho_corasick2();
}
