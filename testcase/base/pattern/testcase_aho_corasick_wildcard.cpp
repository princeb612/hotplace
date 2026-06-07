/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_aho_corasick_wildcard.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_aho_corasick_wildcard() {
    // studying...
    _test_case.begin("aho_corasick + wildcards");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, size_t> expects;
    } _table[] = {
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        // -------------ing                                                             ( 0..15)[2] We don't playing
        // ----------------------------------------------------------------------ing    ( 0..72)[2] We don't playing ~ playing
        //                  because -------------------------------------------------   (17..73)[3] because we grow old; ~ playing.
        //                          we ---- old                                         (25..35)[0] we grow old
        //                                       we ---- old                            (38..48)[0] we grow old
        //                                                   because ----------------   (50..73)[3] because we stop playing.
        //                                                              stop ----ing    (61..72)[1] stop playing
        {
            "We don't playing because we grow old; we grow old because we stop playing.",
            {
                {"we * old", 8},
                {"stop *ing", 9},
                {"*ing", 4},
                {"because *", 9},
            },
            {
                {range_t(0, 15), 2},
                {range_t(0, 72), 2},
                {range_t(25, 35), 0},
                {range_t(38, 48), 0},
                {range_t(61, 72), 1},
                {range_t(17, 73), 3},
                {range_t(50, 73), 3},
            },
        },

        // other cases moved into "testvector_ahocorasick.yml"
    };

    // const OPTION& option = _cmdline->value();

    for (auto entry : _table) {
        t_aho_corasick_wildcard<char> ac('?', '*');
        std::multimap<range_t, size_t> result;
        std::multimap<range_t, size_t> expect;

        _logger->writeln(R"(source     "%.*s")", strlen(entry.source), entry.source);

        int i = 0;
        for (auto item : entry.patterns) {
            ac.insert(item.pattern, item.len);
            _logger->writeln(R"(pattern[%i] "%.*s")", i++, item.len, item.pattern);
        }
        ac.build();

        result = ac.search(entry.source, strlen(entry.source));
        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, entry.source + range.begin);
        }

        _test_case.assert(result == entry.expects, __FUNCTION__, "Aho Corasick algorithm + wildcards");
    }
}

void test_aho_corasick_ignorecase() {
    _test_case.begin("aho_corasick + wildcards + ignore case");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, size_t> expects;
    } _table[] = {
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        // we ----------ing                                                           ( 0..15)[0] We don't playing
        //                                                           we ---------ing  (58..72)[0] we stop playing
        //                          we ---- old                                       (25..35)[1] we grow old
        //                                       we ---- old                          (38..48)[1] we grow old
        {
            "We don't playing because we grow old; we grow old because we stop playing.",
            {
                {"we *ing", 7},
                {"we * old", 8},
            },
            {
                {range_t(0, 15), 0},
                {range_t(58, 72), 0},
                {range_t(25, 35), 1},
                {range_t(38, 48), 1},
            },
        },

        // other cases moved into "testvector_ahocorasick.yml"
    };

    for (auto entry : _table) {
        t_aho_corasick_wildcard<char, char, memberof_tolower_handler> ac('?', '*');
        std::multimap<range_t, size_t> result;
        std::multimap<range_t, size_t> expect;

        _logger->writeln(R"(source     "%.*s")", strlen(entry.source), entry.source);

        int i = 0;
        for (auto item : entry.patterns) {
            ac.insert(item.pattern, item.len);
            _logger->writeln(R"(pattern[%i] "%.*s")", i++, item.len, item.pattern);
        }
        ac.build();

        result = ac.search(entry.source, strlen(entry.source));
        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, entry.source + range.begin);
        }

        _test_case.assert(result == entry.expects, __FUNCTION__, "Aho Corasick algorithm + wildcards + ignorecase");
    }
}

void testcase_aho_corasick_wildcard() {
    test_aho_corasick_wildcard();
    test_aho_corasick_ignorecase();
}
