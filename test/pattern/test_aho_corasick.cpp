/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_aho_corasick_simple() {
    t_aho_corasick<char> ac;
    ac.insert("he", 2);
    ac.insert("she", 3);
    ac.insert("hers", 4);
    ac.insert("his", 3);
    ac.build();
    const char* source = "ahishers";
    std::multimap<range_t, unsigned> result;
    std::multimap<range_t, unsigned> expect = {{range_t(1, 3), 3}, {range_t(3, 5), 1}, {range_t(4, 5), 0}, {range_t(4, 7), 2}};
    result = ac.search(source, strlen(source));

    _logger->writeln(R"(source "%s")", source);
    for (auto item : result) {
        size_t begin = item.first.begin;
        unsigned patid = item.second;
        std::vector<char> pat;
        ac.get_pattern(patid, pat);
        _logger->writeln(R"(pos [%zi] pattern[%i] "%.*s")", begin, patid, pat.size(), &pat[0]);
    }
    _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm");
}

void test_aho_corasick() {
    _test_case.begin("t_aho_corasick");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, unsigned> expects;  // pair(pos_occurrence, id_pattern)
    } _table[] = {
        {
            // t_aho_corasick ac;
            // ac.insert("abc", 3);
            // ac.insert("ab", 2);
            // ac.insert("bc", 2);
            // ac.insert("a", 1);
            // ac.build();
            // const char* source = "abcaabc";
            // ac.search(source, strlen(source));
            "abcaabc",
            {
                {"abc", 3},
                {"ab", 2},
                {"bc", 2},
                {"a", 1},
            },
            //   abcaabc
            //   abc       (0..2)[0] abc
            //   ab        (0..1)[1] ab
            //   a         (0..0)[3] a
            //    bc       (1..2)[2] bc
            //      a      (3..3)[3] a
            //       abc   (4..6)[0] abc
            //       ab    (4..5)[1] ab
            //       a     (4..4)[3] a
            //        bc   (5..6)[2] bc
            {
                {range_t(0, 2), 0},
                {range_t(0, 1), 1},
                {range_t(0, 0), 3},
                {range_t(1, 2), 2},
                {range_t(3, 3), 3},
                {range_t(4, 6), 0},
                {range_t(4, 5), 1},
                {range_t(4, 4), 3},
                {range_t(5, 6), 2},
            },
        },
        {
            // t_aho_corasick ac;
            // ac.insert("cache", 5);
            // ac.insert("he", 2);
            // ac.insert("chef", 4);
            // ac.insert("achy", 4);
            // ac.build();
            // const char* source = "cacachefcachy";
            // ac.search(source, strlen(source));
            "cacachefcachy",
            {
                {"cache", 5},
                {"he", 2},
                {"chef", 4},
                {"achy", 4},
            },
            // cacachefcachy
            //   cache         (2.. 6)[0] cache
            //     chef        (4.. 7)[2] chef
            //      he         (5.. 6)[1] he
            //          achy   (9..12)[3] achy
            {
                {range_t(2, 6), 0},
                {range_t(4, 7), 2},
                {range_t(5, 6), 1},
                {range_t(9, 12), 3},
            },
        },
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
    };

    for (auto item : _table) {
        t_aho_corasick<char> ac;
        std::multimap<range_t, unsigned> expect;
        std::multimap<range_t, unsigned> result;

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
