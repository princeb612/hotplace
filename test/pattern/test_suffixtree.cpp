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

// https://www.geeksforgeeks.org/pattern-searching-using-trie-suffixes/
void test_suffixtree() {
    _test_case.begin("suffix tree");

    struct testvector {
        const char* p;
        size_t size;
        std::set<unsigned> expects;
    };

    t_suffixtree<char> tree("geeksforgeeks.org", 17);
    testvector _table_pattern[] = {{"ee", 2, {1, 9}}, {"geek", 4, {0, 8}}, {"quiz", 4, {}}, {"forgeeks", 8, {5}}};

    for (auto item : _table_pattern) {
        std::set<unsigned> result = tree.search(item.p, item.size);
        for (auto idx : result) {
            _logger->writeln("found at %i", idx);
        }
        _test_case.assert(item.expects == result, __FUNCTION__, "search %.*s", (unsigned)item.size, item.p);
    }
}

void test_suffixtree2() {
    _test_case.begin("suffix tree");

    struct testvector {
        const char* p;
        size_t size;
        std::set<unsigned> expects;
    };

    t_suffixtree<char> tree;
    tree.reset().add("test ", 5).add("geeksforgeeks.org", 17);  // "test geeksforgeeks.org"
    testvector _table_pattern[] = {{"ee", 2, {6, 14}}, {"geek", 4, {5, 13}}, {"quiz", 4, {}}, {"forgeeks", 8, {10}}, {"est g", 4, {1}}};
    for (auto item : _table_pattern) {
        std::set<unsigned> result = tree.search(item.p, item.size);
        for (auto idx : result) {
            _logger->writeln("found at %i", idx);
        }
        _test_case.assert(item.expects == result, __FUNCTION__, "search %.*s", (unsigned)item.size, item.p);
    }
}
