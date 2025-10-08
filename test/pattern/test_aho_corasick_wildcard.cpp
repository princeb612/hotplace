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
        // ??       (0..1)[0] ba
        //  ??      (1..2)[0] an
        //   ??     (2..3)[0] na
        //    ??    (3..4)[0] an
        //     ??   (4..5)[0] na
        {
            "banana",
            {
                {"??", 2},
            },
            {
                {range_t(0, 1), 0},
                {range_t(1, 2), 0},
                {range_t(2, 3), 0},
                {range_t(3, 4), 0},
                {range_t(4, 5), 0},
            },
        },
        // banana
        // ???      (0..2)[0] ban
        //  ???     (1..3)[0] ana
        //   ???    (2..4)[0] nan
        //    ???   (3..5)[0] ana
        {
            "banana",
            {
                {"???", 3},
            },
            {
                {range_t(0, 2), 0},
                {range_t(1, 3), 0},
                {range_t(2, 4), 0},
                {range_t(3, 5), 0},
            },
        },
        // banana
        //  ??a     (1..3)[0] ana
        //    ??a   (3..5)[0] ana
        {
            "banana",
            {
                {"??a", 3},
            },
            {
                {range_t(1, 3), 0},
                {range_t(3, 5), 0},
            },
        },
        // banana
        // ban      (0..2)[0] ban
        //  an?     (1..3)[1] ana
        //  a?a     (1..3)[2] ana
        //    an?   (3..5)[1] ana
        //    a?a   (3..5)[2] ana
        // case sibling single (element exist, also single sibling exists)
        {
            "banana",
            {
                {"ban", 3},
                {"an?", 3},
                {"a?a", 3},
            },
            {
                {range_t(0, 2), 0},
                {range_t(1, 3), 1},
                {range_t(1, 3), 2},
                {range_t(3, 5), 1},
                {range_t(3, 5), 2},
            },
        },
        // banana
        // ba       (0..1)[0] ba
        // b--a     (0..3)[0] bana
        // b----a   (0..5)[0] banana
        // b-n      (0..2)[1] ban
        // b---n    (0..4)[1] banan
        {
            "banana",
            {
                {"b*a", 3},
                {"b*n", 3},
            },
            {
                {range_t(0, 1), 0},
                {range_t(0, 3), 0},
                {range_t(0, 5), 0},
                {range_t(0, 2), 1},
                {range_t(0, 4), 1},
            },
        },

        // ahishers
        // (0.. 1)[6] ah
        // (1.. 3)[0] his
        // (1.. 3)[3] his
        // (1.. 3)[5] his
        // (4.. 6)[1] her
        // (4.. 6)[4] her
        // (4.. 7)[2] hers
        // (5.. 7)[5] ers

        {
            "ahishers",
            {
                {"his", 3},
                {"her", 3},
                {"hers", 4},
                {"?is", 3},
                {"h?r", 3},
                {"??s", 3},
                {"a?", 2},
            },
            {
                {range_t(0, 1), 6},
                {range_t(1, 3), 0},
                {range_t(1, 3), 3},
                {range_t(1, 3), 5},
                {range_t(4, 6), 1},
                {range_t(4, 6), 4},
                {range_t(4, 7), 2},
                {range_t(5, 7), 5},
            },
        },
        // ahishers
        // a?i        (0..2)[0] ahi
        //  ?is       (1..3)[1] his
        //  h?        (1..2)[3] hi
        //  ??s       (1..3)[4] his
        //   ?s       (2..3)[2] is
        //     h?     (4..5)[3] he
        //      ??s   (5..7)[4] ers
        //       ?s   (6..7)[2] rs
        {
            "ahishers",
            {
                {"a?i", 3},
                {"?is", 3},
                {"?s", 2},
                {"h?", 2},
                {"??s", 3},
            },
            {
                {range_t(0, 2), 0},
                {range_t(1, 3), 1},
                {range_t(1, 2), 3},
                {range_t(1, 3), 4},
                {range_t(2, 3), 2},
                {range_t(4, 5), 3},
                {range_t(5, 7), 4},
                {range_t(6, 7), 2},
            },
        },
        // 01234567
        // ahishers
        // ?h         (0..1)[2] ah
        //  h??       (1..3)[0] his
        //   ?s       (2..3)[1] is
        //    ?h      (3..4)[2] sh
        //     h??    (4..6)[0] her
        //       ?s   (6..7)[1] rs
        {
            "ahishers",
            {
                {"h??", 3},
                {"?s", 2},
                {"?h", 2},
            },
            {
                {range_t(0, 1), 2},
                {range_t(1, 3), 0},
                {range_t(2, 3), 1},
                {range_t(3, 4), 2},
                {range_t(4, 6), 0},
                {range_t(6, 7), 1},
            },
        },
        // 01234567
        // ahishers
        //  h-s       (1..3)[0] his
        //  h--he     (1..5)[2] hishe
        //    s---s   (3..7)[3] shers
        //     h--s   (4..7)[0] hers
        //       rs   (6..7)[1] rs
        {
            "ahishers",
            {
                {"h*s", 3},
                {"r*s", 3},
                {"h*h*e", 5},
                {"s*s", 3},
            },
            {
                {range_t(1, 3), 0},
                {range_t(1, 5), 2},
                {range_t(3, 7), 3},
                {range_t(4, 7), 0},
                {range_t(6, 7), 1},
            },
        },

        //
        // PS Platinum Trophy Games
        //

        // 0         1
        // 01234567890
        // Dark Soul 3
        // D????S??? 3   (0..10)[0] Dark Soul 3
        //   ??_         (2.. 4)[1]   rk_
        //    ?_?        (3.. 5)[2]    k_S
        //        ??_    (7.. 9)[1]        ul
        //         ?_?   (8..10)[2]         l_3
        {
            "Dark Soul 3",
            {
                {"D????S??? 3", 11},
                {"?? ", 3},
                {"? ?", 3},
            },
            {
                {range_t(0, 10), 0},
                {range_t(2, 4), 1},
                {range_t(3, 5), 2},
                {range_t(7, 9), 1},
                {range_t(8, 10), 2},
            },
        },
        // 0         1         2         3
        // 0123456789012345678901234567890
        // Monster Hunter World: Icebourne
        //    ?ter                           ( 3.. 6)[0] ster
        //           ?ter                    (10..13)[0] nter
        //                       ?ce         (22..24)[1] Ice
        //                       Ice         (22..24)[2] Ice
        {
            "Monster Hunter World: Icebourne",
            {
                {"?ter", 4},
                {"?ce", 3},
                {"Ice", 3},
            },
            {
                {range_t(3, 6), 0},
                {range_t(10, 13), 0},
                {range_t(22, 24), 1},
                {range_t(22, 24), 2},
            },
        },
        // Elden Ring
        //    ?n        (3..4)[0] en
        //        ?n    (7..8)[0] in
        {
            "Elden Ring",
            {
                {"?n", 2},
            },
            {
                {range_t(3, 4), 0},
                {range_t(7, 8), 0},
            },
        },
        // the boxer - Simon & Garfunkel
        // 0         1         2         3         4         5         6
        // 012345678901234567890123456789012345678901234567890123456789012
        // still a man hears what he wants to hear and disregards the rest
        //          an                                                       ( 9..10)[2] an
        //             he                                                    (12..13)[0] he
        //             he?r                                                  (12..15)[1] hear
        //              e?r                                                  (13..15)[3] ear
        //                        he                                         (23..24)[0] he
        //                            an                                     (27..28)[2] an
        //                                    he                             (35..36)[0] he
        //                                    he?r                           (35..38)[1] hear
        //                                     e?r                           (36..38)[3] ear
        //                                         an                        (40..41)[2] an
        //                                                         he        (56..57)[0] he
        //                                                         he?r      (56..59)[1] he r
        //                                                          e?r      (57..59)[3] e r
        {
            "still a man hears what he wants to hear and disregards the rest",
            {
                {"he", 2},
                {"he?r", 4},
                {"an", 2},
                {"e?r", 3},
            },
            {
                {range_t(9, 10), 2},
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
                {range_t(57, 59), 3},
            },
        },
        // 0         1         2         3         4         5         6
        // 012345678901234567890123456789012345678901234567890123456789012
        // still a man hears what he wants to hear and disregards the rest
        //                   what ----------- hear                         (18..38)[0] what he wants to hear
        // st?ll ----- h                                                   ( 0..12)[1] still a man h
        // st?ll ---------------- h                                        ( 0..23)[1] still a man hears what h
        // st?ll ---------------------------- h                            ( 0..35)[1] still a man hears what he wants to h
        //                                         and -------------- rest (40..62)[2] and disregards the rest
        {
            "still a man hears what he wants to hear and disregards the rest",
            {
                {"wha? * hear", 11},
                {"st?ll * h", 9},
                {"and * rest", 10},
            },
            {
                {range_t(18, 38), 0},
                {range_t(0, 12), 1},
                {range_t(0, 23), 1},
                {range_t(0, 35), 1},
                {range_t(40, 62), 2},
            },
        },
        // George Bernard Shaw
        // 0         1         2         3         4         5         6         7
        // 01234567890123456789012345678901234567890123456789012345678901234567890123
        // We don't playing because we grow old; we grow old because we stop playing.
        //          ????ing                                                             ( 9..15)[0] playing
        //                  be??use                                                     (17..23)[2] because
        //                          we                                                  (25..26)[1] we
        //                                       we                                     (38..39)[1] we
        //                                                   be??use                    (50..56)[2] because
        //                                                           we                 (58..59)[1] we
        //                                                                   ????ing    (66..72)[0] playing
        // case yield - root (not found element, but single exists)
        {
            "We don't playing because we grow old; we grow old because we stop playing.",
            {
                {"????ing", 7},
                {"we", 2},
                {"be??use", 7},
            },
            {
                {range_t(9, 15), 0},
                {range_t(17, 23), 2},
                {range_t(25, 26), 1},
                {range_t(38, 39), 1},
                {range_t(50, 56), 2},
                {range_t(58, 59), 1},
                {range_t(66, 72), 0},
            },
        },
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
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, entry.source + range.begin);
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
        // we                                                                           ( 0.. 1)[1] We
        //          ????ing                                                             ( 9..15)[0] playing
        //                  be??use                                                     (17..23)[2] because
        //                          we                                                  (25..26)[1] we
        //                                       we                                     (38..39)[1] we
        //                                                   be??use                    (50..56)[2] because
        //                                                           we                 (58..59)[1] we
        //                                                                   ????ing    (66..72)[0] playing
        // case yield - root (not found element, but single exists)
        {
            "We don't playing because we grow old; we grow old because we stop playing.",
            {
                {"????ing", 7},
                {"we", 2},
                {"be??use", 7},
            },
            {
                {range_t(0, 1), 1},
                {range_t(9, 15), 0},
                {range_t(17, 23), 2},
                {range_t(25, 26), 1},
                {range_t(38, 39), 1},
                {range_t(50, 56), 2},
                {range_t(58, 59), 1},
                {range_t(66, 72), 0},
            },
        },
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
            _logger->writeln("pos [%2zi..%2zi] pattern[%i] %.*s", range.begin, range.end, pid, range.end - range.begin + 1, entry.source + range.begin);
        }

        _test_case.assert(result == entry.expects, __FUNCTION__, "Aho Corasick algorithm + wildcards + ignorecase");
    }
}
