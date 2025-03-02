/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2025.03.02   Soo Han, Kim        rename rfind to lookup
 *                                  autoindex start from 0
 *                                  scan added
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
    trie.add("hello", 5)   // index 0
        .add("world", 5);  // index 1
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
    _test_case.assert(0 == index, __FUNCTION__, "find #1");
    index = trie.find("world", 5);
    _test_case.assert(1 == index, __FUNCTION__, "find #2");
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
    test = trie.lookup(0, res);
    _test_case.assert(test && compare(res, "hello"), __FUNCTION__, "rlookup #1");
    test = trie.lookup(1, res);
    _test_case.assert(test && compare(res, "world"), __FUNCTION__, "rlookup #2");
    test = trie.lookup(2, res);
    _test_case.assert((false == test) && res.empty(), __FUNCTION__, "rlookup #3");
}

void test_trie_scan() {
    _test_case.begin("t_trie");
    t_trie<char> trie;
    for (auto i = 0;; i++) {
        auto item = _h2hcodes + i;
        auto sym = item->sym;
        auto code = item->code;
        if (nullptr == code) {
            break;
        }
        trie.insert(code, strlen(code), sym);
    }

    // We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw
    // 1110010 00101 010100 100100 00111 101010 11111111010 01001 010100 101011 101000 00011 1111010 ...

    const char* plaintext = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";
    const char* sample =
        "111001000101010100100100001111010101111111101001001010100101011101000000111111010001101010101001100101001000110010100100000111011010100000101010100111"
        "100000101010100100110101100001111111000010100001111010001001001111101101010011110000010101010010011010110000111111100001010000111101000100100010100100"
        "011001010010000011101101010000010101010011110000010101010001000010010011110101101010010101110100000011111101000110101010100110010111010100010110010100"
        "1100010001010011110110010011000101010100101110100101101100101010000111011001001000101001101110100111000111111000111111";  // with padding (last 111111)
    size_t len = strlen(sample);
    int rc = 0;
    size_t pos = 0;
    basic_stream bs;
    while (true) {
        rc = trie.scan(sample, len, pos);
        if (-1 == rc) {
            break;
        }
        bs << (char)rc;
    }
    _logger->writeln(bs);
    _logger->dump(bs, 16, 3);
    _test_case.assert(bs == plaintext, __FUNCTION__, "huffman coding");
}
