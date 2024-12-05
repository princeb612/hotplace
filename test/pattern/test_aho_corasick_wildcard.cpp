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

void test_aho_corasick_wildcard() {
    // studying...
    _test_case.begin("t_aho_corasick + wildcards");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, unsigned> expects;
    } _table[] = {
        // banana
        // ??       (0..1)[0]
        //  ??      (1..2)[0]
        //   ??     (2..3)[0]
        //    ??    (3..4)[0]
        //     ??   (4..5)[0]
        {"banana", {{"??", 2}}, {{range_t(0, 1), 0}, {range_t(1, 2), 0}, {range_t(2, 3), 0}, {range_t(3, 4), 0}, {range_t(4, 5), 0}}},
        // banana
        // ???      (0..2)[0]
        //  ???     (1..3)[0]
        //   ???    (2..4)[0]
        //    ???   (3..5)[0]
        {"banana", {{"???", 3}}, {{range_t(0, 2), 0}, {range_t(1, 3), 0}, {range_t(2, 4), 0}, {range_t(3, 5), 0}}},
        // banana
        //  ??a     (1..3)[0]
        //    ??a   (3..5)[0]
        {"banana", {{"??a", 3}}, {{range_t(1, 3), 0}, {range_t(3, 5), 0}}},
        // banana
        // ban      (0..2)[0]
        //  an?     (1..3)[1]
        //  a?a     (1..3)[2]
        //    an?   (3..5)[1]
        //    a?a   (3..5)[2]
        // case sibling single (element exist, also single sibling exists)
        {"banana", {{"ban", 3}, {"an?", 3}, {"a?a", 3}}, {{range_t(0, 2), 0}, {range_t(1, 3), 1}, {range_t(1, 3), 2}, {range_t(3, 5), 1}, {range_t(3, 5), 2}}},
        // banana
        // ba       (0..1)[0]
        // b--a     (0..3)[0]
        // b----a   (0..5)[0]
        // b-n      (0..2)[1]
        // b---n    (0..4)[1]
        {"banana", {{"b*a", 3}, {"b*n", 3}}, {{range_t(0, 1), 0}, {range_t(0, 3), 0}, {range_t(0, 5), 0}, {range_t(0, 2), 1}, {range_t(0, 4), 1}}},

        {"ahishers",
         {{"his", 3}, {"her", 3}, {"hers", 4}, {"?is", 3}, {"h?r", 3}, {"??s", 3}, {"a?", 2}},
         {{range_t(0, 1), 6},
          {range_t(1, 3), 0},
          {range_t(1, 3), 3},
          {range_t(1, 3), 5},
          {range_t(4, 6), 1},
          {range_t(4, 6), 4},
          {range_t(4, 7), 2},
          {range_t(5, 7), 5}}},
        // ahishers
        // a?i        (0..2)[0]
        //  ?is       (1..3)[1]
        //  h?        (1..2)[3]
        //  ??s       (1..3)[4]
        //   ?s       (2..3)[2]
        //     h?     (4..5)[3]
        //      ??s   (5..7)[4]
        //       ?s   (6..7)[2]
        {"ahishers",
         {{"a?i", 3}, {"?is", 3}, {"?s", 2}, {"h?", 2}, {"??s", 3}},
         {{range_t(0, 2), 0},
          {range_t(1, 3), 1},
          {range_t(1, 2), 3},
          {range_t(1, 3), 4},
          {range_t(2, 3), 2},
          {range_t(4, 5), 3},
          {range_t(5, 7), 4},
          {range_t(6, 7), 2}}},
        // 01234567
        // ahishers
        // ?h         (0..1)[2]
        //  h??       (1..3)[0]
        //   ?s       (2..3)[1]
        //    ?h      (3..4)[2]
        //     h??    (4..6)[0]
        //       ?s   (6..7)[1]
        {"ahishers",
         {{"h??", 3}, {"?s", 2}, {"?h", 2}},
         {{range_t(0, 1), 2}, {range_t(1, 3), 0}, {range_t(2, 3), 1}, {range_t(3, 4), 2}, {range_t(4, 6), 0}, {range_t(6, 7), 1}}},
        // 01234567
        // ahishers
        //  h-s       (1..3)[0]
        //  h--he     (1..5)[2]
        //    s---s   (3..7)[3]
        //     h--s   (4..7)[0]
        //       rs   (6..7)[1]
        {"ahishers",
         {{"h*s", 3}, {"r*s", 3}, {"h*h*e", 5}, {"s*s", 3}},
         {{range_t(1, 3), 0}, {range_t(1, 5), 2}, {range_t(3, 7), 3}, {range_t(4, 7), 0}, {range_t(6, 7), 1}}},

        //
        // PS Platinum Trophy Games
        //

        // 0         1
        // 01234567890
        // Dark Soul 3
        // D????S??? 3   (0..10)[0]
        //   ??_         (2.. 4)[1]
        //    ?_?        (3.. 5)[2]
        //        ??_    (7.. 9)[1]
        //         ?_?   (8..10)[2]
        {"Dark Soul 3",
         {{"D????S??? 3", 11}, {"?? ", 3}, {"? ?", 3}},
         {{range_t(0, 10), 0}, {range_t(2, 4), 1}, {range_t(3, 5), 2}, {range_t(7, 9), 1}, {range_t(8, 10), 2}}},
        // 0         1         2         3
        // 0123456789012345678901234567890
        // Monster Hunter World: Icebourne
        //    ?ter                           ( 3.. 6)[0]
        //           ?ter                    (10..13)[0]
        //                       ?ce         (22..24)[1]
        //                       Ice         (22..24)[2]
        {"Monster Hunter World: Icebourne",
         {{"?ter", 4}, {"?ce", 3}, {"Ice", 3}},
         {{range_t(3, 6), 0}, {range_t(10, 13), 0}, {range_t(22, 24), 1}, {range_t(22, 24), 2}}},
        // Elden Ring
        //    ?n        (3..4)[0]
        //        ?n    (7..8)[0]
        {"Elden Ring", {{"?n", 2}}, {{range_t(3, 4), 0}, {range_t(7, 8), 0}}},
        // the boxer - Simon & Garfunkel
        // 0         1         2         3         4         5         6
        // 012345678901234567890123456789012345678901234567890123456789012
        // still a man hears what he wants to hear and disregards the rest
        //          an                                                       ( 9..10)[2]
        //             he                                                    (12..13)[0]
        //             he?r                                                  (12..15)[1]
        //              e?r                                                  (13..15)[3]
        //                        he                                         (23..24)[0]
        //                            an                                     (27..28)[2]
        //                                    he                             (35..36)[0]
        //                                    he?r                           (35..38)[1]
        //                                     e?r                           (36..38)[3]
        //                                         an                        (40..41)[2]
        //                                                         he        (56..57)[0]
        //                                                         he?r      (56..59)[1]
        //                                                          e?r      (57..59)[3]
        {"still a man hears what he wants to hear and disregards the rest",
         {{"he", 2}, {"he?r", 4}, {"an", 2}, {"e?r", 3}},
         {{range_t(9, 10), 2},
          {range_t(12, 13), 0},
          {range_t(12, 15), 1},
          {range_t(13, 15), 3},
          {range_t(23, 24), 0},
          {range_t(27, 28), 2},
          {range_t(35, 36), 0},
          {range_t(35, 38), 1},
          {range_t(36, 38), 3},
          {range_t(40, 41), 2},
          {range_t(56, 57), 0},
          {range_t(56, 59), 1},
          {range_t(57, 59), 3}}},
        // 0         1         2         3         4         5         6
        // 012345678901234567890123456789012345678901234567890123456789012
        // still a man hears what he wants to hear and disregards the rest
        //                   what ----------- hear                         (18..38)[0]
        // st?ll ----- h                                                   ( 0..12)[1]
        // st?ll ---------------- h                                        ( 0..23)[1]
        // st?ll ---------------------------- h                            ( 0..35)[1]
        //                                         and -------------- rest (40..62)[2]
        {"still a man hears what he wants to hear and disregards the rest",
         {{"wha? * hear", 11}, {"st?ll * h", 9}, {"and * rest", 10}},
         {{range_t(18, 38), 0}, {range_t(0, 12), 1}, {range_t(0, 23), 1}, {range_t(0, 35), 1}, {range_t(40, 62), 2}}},
        // George Bernard Shaw
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        //          ????ing                                                             ( 9..15)[0]
        //                  be??use                                                     (17..23)[2]
        //                          we                                                  (25..26)[1]
        //                                       we                                     (38..39)[1]
        //                                                   be??use                    (50..56)[2]
        //                                                           we                 (58..59)[1]
        //                                                                   ????ing    (66..72)[0]
        // case yield - root (not found element, but single exists)
        {"We don't playing because we grow old; we grow old because we stop playing.",
         {{"????ing", 7}, {"we", 2}, {"be??use", 7}},
         {{range_t(9, 15), 0},
          {range_t(17, 23), 2},
          {range_t(25, 26), 1},
          {range_t(38, 39), 1},
          {range_t(50, 56), 2},
          {range_t(58, 59), 1},
          {range_t(66, 72), 0}}},
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        // -------------ing                                                             ( 0..15)[2]
        // ----------------------------------------------------------------------ing    ( 0..72)[2]
        //                  because -------------------------------------------------   (17..73)[3]
        //                          we ---- old                                         (25..35)[0]
        //                                       we ---- old                            (38..48)[0]
        //                                                   because ----------------   (50..73)[3]
        //                                                              stop ----ing    (61..72)[1]
        {"We don't playing because we grow old; we grow old because we stop playing.",
         {{"we * old", 8}, {"stop *ing", 9}, {"*ing", 4}, {"because *", 9}},
         {{range_t(0, 15), 2},
          {range_t(0, 72), 2},
          {range_t(25, 35), 0},
          {range_t(38, 48), 0},
          {range_t(61, 72), 1},
          {range_t(17, 73), 3},
          {range_t(50, 73), 3}}},
    };

    const OPTION& option = _cmdline->value();

    for (auto entry : _table) {
        // t_aho_corasick<char> ac(memberof_defhandler<char>);
        t_aho_corasick_wildcard<char> ac(memberof_defhandler<char>, '?', '*');
        std::multimap<range_t, unsigned> result;
        std::multimap<range_t, unsigned> expect;

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
            _logger->writeln("pos [%2zi..%2zi] pattern[%i]", range.begin, range.end, pid);
        }

        _test_case.assert(result == entry.expects, __FUNCTION__, "Aho Corasick algorithm + wildcards");
    }
}

char memberof_tolower(const char* source, size_t idx) { return source ? std::tolower(source[idx]) : char(); }

void test_aho_corasick_ignorecase() {
    _test_case.begin("t_aho_corasick + wildcards + ignore case");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, unsigned> expects;
    } _table[] = {
        // George Bernard Shaw
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        // we                                                                           ( 0.. 1)[1]
        //          ????ing                                                             ( 9..15)[0]
        //                  be??use                                                     (17..23)[2]
        //                          we                                                  (25..26)[1]
        //                                       we                                     (38..39)[1]
        //                                                   be??use                    (50..56)[2]
        //                                                           we                 (58..59)[1]
        //                                                                   ????ing    (66..72)[0]
        // case yield - root (not found element, but single exists)
        {"We don't playing because we grow old; we grow old because we stop playing.",
         {{"????ing", 7}, {"we", 2}, {"be??use", 7}},
         {{range_t(0, 1), 1},
          {range_t(9, 15), 0},
          {range_t(17, 23), 2},
          {range_t(25, 26), 1},
          {range_t(38, 39), 1},
          {range_t(50, 56), 2},
          {range_t(58, 59), 1},
          {range_t(66, 72), 0}}},
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        // we ----------ing                                                           ( 0..15)[0]
        //                                                           we ---------ing  (58..72)[0]
        //                          we ---- old                                       (25..35)[1]
        //                                       we ---- old                          (38..48)[1]
        {"We don't playing because we grow old; we grow old because we stop playing.",
         {{"we *ing", 7}, {"we * old", 8}},
         {{range_t(0, 15), 0}, {range_t(58, 72), 0}, {range_t(25, 35), 1}, {range_t(38, 48), 1}}},
    };

    const OPTION& option = _cmdline->value();

    for (auto entry : _table) {
        t_aho_corasick_wildcard<char> ac(memberof_tolower, '?', '*');
        std::multimap<range_t, unsigned> result;
        std::multimap<range_t, unsigned> expect;

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
            _logger->writeln("pos [%2zi..%2zi] pattern[%i]", range.begin, range.end, pid);
        }

        _test_case.assert(result == entry.expects, __FUNCTION__, "Aho Corasick algorithm + wildcards + ignorecase");
    }
}
