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

void test_trie() {
    _test_case.begin("t_trie");
    // https://www.geeksforgeeks.org/trie-data-structure-in-cpp/
    struct testvector {
        const char* p;
        size_t size;
        bool expect;
    };
    testvector _table_pattern[] = {
        {"geek", 4}, {"geeks", 5}, {"code", 4}, {"coder", 5}, {"coding", 6},
    };
    testvector _table_search[] = {
        {"geek", 4, true}, {"geeks", 5, true}, {"code", 4, true}, {"coder", 5, true}, {"coding", 6, true}, {"codex", 5, false},
    };
    testvector _table_prefix[] = {
        {"ge", 2, true},
        {"cod", 3, true},
        {"coz", 3, false},
    };
    testvector _table_erase[] = {
        {"geek", 4, false},
        {"coding", 6, false},
    };

    t_trie<char> trie;
    bool test = false;

    for (auto item : _table_pattern) {
        trie.add(item.p, item.size);
    }

    // dump
    auto handler = [](const char* p, size_t size) -> void {
        if (p) {
            _logger->writeln("%.*s", (unsigned)size, p);
        }
    };
    trie.dump(handler);
    _test_case.assert(true, __FUNCTION__, "dump");

    // search
    for (auto item : _table_search) {
        test = trie.search(item.p, item.size);
        _test_case.assert(item.expect == test, __FUNCTION__, "search %.*s [%d]", (unsigned)item.size, item.p, item.expect ? 1 : 0);
    }
    // prefix
    for (auto item : _table_prefix) {
        test = trie.prefix(item.p, item.size);
        _test_case.assert(item.expect == test, __FUNCTION__, "prefix %.*s [%d]", (unsigned)item.size, item.p, item.expect ? 1 : 0);
    }
    // erase
    for (auto item : _table_erase) {
        trie.erase(item.p, item.size);
    }
    for (auto item : _table_erase) {
        test = trie.search(item.p, item.size);
        _test_case.assert(item.expect == test, __FUNCTION__, "search after erase %.*s [%d]", (unsigned)item.size, item.p, item.expect ? 1 : 0);
    }
}

void test_trie_autocompletion() {
    _test_case.begin("t_trie");
    // https://www.geeksforgeeks.org/auto-complete-feature-using-trie/
    struct testvector {
        const char* p;
        size_t size;
    };
    testvector _table_pattern[] = {
        {"hello", 5}, {"dog", 3}, {"hell", 4}, {"cat", 3}, {"a", 1}, {"hel", 3}, {"help", 4}, {"helps", 5}, {"helping", 7},
    };

    _test_case.begin("t_trie");
    t_trie<char> trie;
    bool test = false;

    for (auto item : _table_pattern) {
        trie.add(item.p, item.size);
    }

    // dump
    auto handler = [](const char* p, size_t size) -> void {
        if (p) {
            _logger->writeln("%.*s", (unsigned)size, p);
        }
    };
    trie.dump(handler);
    _test_case.assert(true, __FUNCTION__, "dump");

    test = trie.suggest("hel", 3, handler);
    _test_case.assert(true == test, __FUNCTION__, "auto-completion hel");
}

void test_trie_lookup() {
    _test_case.begin("t_trie");
    t_trie<char> trie;
    trie.add("hello", 5).add("world", 5);
    const char* source = "helloworld";
    size_t len = 0;
    // 0123456789
    // helloworld
    // hello      - in
    //  x         - not in
    //      world - in
    len = trie.lookup(source, 10);  // 5
    _test_case.assert(5 == len, __FUNCTION__, "lookup #1");
    len = trie.lookup(source + 1, 9);  // 0
    _test_case.assert(0 == len, __FUNCTION__, "lookup #2");
    len = trie.lookup(source + 5, 5);  // 5
    _test_case.assert(5 == len, __FUNCTION__, "lookup #3");

    int index = -1;
    index = trie.find("hello", 5);
    _test_case.assert(1 == index, __FUNCTION__, "find #1");
    index = trie.find("world", 5);
    _test_case.assert(2 == index, __FUNCTION__, "find #2");
    index = trie.find("word", 4);
    _test_case.assert(-1 == index, __FUNCTION__, "find #3");

    auto compare = [](const std::vector<char>& lhs, const std::string& rhs) -> bool {
        size_t match = 0;
        if (lhs.size() == rhs.size()) {
            for (size_t i = 0; i < lhs.size(); i++) {
                if (lhs[i] == rhs[i]) {
                    ++match;
                }
            }
        }
        return (match == lhs.size());
    };

    bool test = false;
    std::vector<char> res;
    test = trie.rfind(1, res);
    _test_case.assert(test && compare(res, "hello"), __FUNCTION__, "rfind #1");
    test = trie.rfind(2, res);
    _test_case.assert(test && compare(res, "world"), __FUNCTION__, "rfind #2");
    test = trie.rfind(3, res);
    _test_case.assert((false == test) && res.empty(), __FUNCTION__, "rfind #3");
}
