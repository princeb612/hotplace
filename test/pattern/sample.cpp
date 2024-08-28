/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <functional>
#include <sdk/nostd.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

struct pattern_t {
    const char* pattern;
    unsigned len;
};

struct pattern_search_sample_data {
    std::string dummy;
    int value;

    pattern_search_sample_data(std::string s, int v) : dummy(s), value(v) {}
    pattern_search_sample_data(int v) : value(v) {}

    friend bool operator==(const pattern_search_sample_data& lhs, const pattern_search_sample_data& rhs) { return lhs.value == rhs.value; }
};

void test_kmp() {
    _test_case.begin("t_kmp");

    // 0123456789abcdef0123
    // abacaabaccabacabaabb
    //           abacab

    binary data("abacaabaccabacabaabb");
    binary pattern("abacab");

    {
        // vector
        t_kmp<byte_t> kmp;
        int idx = kmp.search(data, pattern);
        _logger->hdump("data", data);
        _logger->hdump("pattern", pattern);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<byte_t> %i", idx);
    }

    {
        // contiguous memory space
        t_kmp<byte_t> kmp;
        int idx = kmp.search(&data.get()[0], data.get().size(), &pattern.get()[0], pattern.get().size());
        _logger->hdump("data", data);
        _logger->hdump("pattern", pattern);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<byte_t> %i", idx);
    }

    {
        // compare member (see operator ==)
        std::vector<pattern_search_sample_data> data2;
        std::vector<pattern_search_sample_data> pattern2;
        auto prepare = [](std::vector<pattern_search_sample_data>& target, const binary& source) -> void {
            for (auto item : source.get()) {
                target.insert(target.end(), item);
            }
        };
        prepare(data2, data);
        prepare(pattern2, pattern);

        t_kmp<pattern_search_sample_data> kmp;
        int idx = kmp.search(&data2[0], data2.size(), &pattern2[0], pattern2.size());
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<struct> %i", idx);
    }

    {
        std::vector<pattern_search_sample_data*> data2;
        std::vector<pattern_search_sample_data*> pattern2;
        auto prepare = [](std::vector<pattern_search_sample_data*>& target, const binary& source) -> void {
            for (auto item : source.get()) {
                target.insert(target.end(), new pattern_search_sample_data(item));
            }
        };
        auto clean = [](std::vector<pattern_search_sample_data*>& target) -> void {
            for (auto item : target) {
                delete item;
            }
        };

        prepare(data2, data);
        prepare(pattern2, pattern);
        t_kmp<pattern_search_sample_data*> kmp;
        auto comparator = [](const pattern_search_sample_data* lhs, const pattern_search_sample_data* rhs) -> bool { return (lhs->value == rhs->value); };
        int idx = kmp.search(&data2[0], data2.size(), &pattern2[0], pattern2.size(), 0, comparator);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<struct*> %i using comparator", idx);
        clean(data2);
        clean(pattern2);
    }
}

void test_aho_corasick() {
    _test_case.begin("t_aho_corasick");

    struct testvector {
        const char* source;
        std::vector<pattern_t> patterns;
        std::multimap<range_t, unsigned> expects;  // pair(pos_occurrence, id_pattern)
    } _table[] = {
        {// t_aho_corasick ac;
         // ac.insert("abc", 3);
         // ac.insert("ab", 2);
         // ac.insert("bc", 2);
         // ac.insert("a", 1);
         // ac.build();
         // const char* source = "abcaabc";
         // ac.search(source, strlen(source));
         "abcaabc",
         {{"abc", 3}, {"ab", 2}, {"bc", 2}, {"a", 1}},
         //   abcaabc
         //   abc       (0..2)[0]
         //   ab        (0..1)[1]
         //   a         (0..0)[3]
         //    bc       (1..2)[2]
         //      a      (3..3)[3]
         //       abc   (4..6)[0]
         //       ab    (4..5)[1]
         //       a     (4..4)[3]
         //        bc   (5..6)[2]
         {{range_t(0, 2), 0},
          {range_t(0, 1), 1},
          {range_t(0, 0), 3},
          {range_t(1, 2), 2},
          {range_t(3, 3), 3},
          {range_t(4, 6), 0},
          {range_t(4, 5), 1},
          {range_t(4, 4), 3},
          {range_t(5, 6), 2}}},
        {// t_aho_corasick ac;
         // ac.insert("cache", 5);
         // ac.insert("he", 2);
         // ac.insert("chef", 4);
         // ac.insert("achy", 4);
         // ac.build();
         // const char* source = "cacachefcachy";
         // ac.search(source, strlen(source));
         "cacachefcachy",
         {{"cache", 5}, {"he", 2}, {"chef", 4}, {"achy", 4}},
         // cacachefcachy
         //   cache         (2..6)[0]
         //     chef        (4..7)[2]
         //      he         (5..6)[1]
         //          achy   (9..12)[3]
         {{range_t(2, 6), 0}, {range_t(4, 7), 2}, {range_t(5, 6), 1}, {range_t(9, 12), 3}}},
        {// t_aho_corasick ac;
         // ac.insert("he", 2);
         // ac.insert("she", 3);
         // ac.insert("hers", 4);
         // ac.insert("his", 3);
         // ac.build();
         // const char* source = "ahishers";
         // ac.search(source, strlen(source));
         "ahishers",
         {{"he", 2}, {"she", 3}, {"hers", 4}, {"his", 3}},
         // ahishers
         //  his        (1..3)[3]
         //    she      (3..5)[1]
         //     he      (4..5)[0]
         //     hers    (4..7)[2]
         {{range_t(1, 3), 3}, {range_t(3, 5), 1}, {range_t(4, 5), 0}, {range_t(4, 7), 2}}},
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

        _test_case.assert(item.expects == result, __FUNCTION__, R"(multiple pattern search "%s")", item.source);
    }

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
    for (auto item : result) {
        _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
    }
    _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm");
}

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

void test_ukkonen() {
    _test_case.begin("ukkonen algorithm");

    struct testvector {
        const char* p;
        size_t size;
        unsigned count;
        struct {
            const char* p;
            size_t size;
            std::set<int> expects;
        } expect[5];
    };
    testvector _table[] =  // ...
        {{"bananas", 7, 4, {{"ana", 3, {1, 3}}, {"ban", 3, {0}}, {"nana", 4, {2}}, {"apple", 5, {}}}},
         {"xabac", 5, 1, {{"ba", 2, {2}}, {"a", 1, {1, 3}}}},
         {"abcabcde", 8, 2, {{"abc", 3, {0, 3}}, {"bc", 2, {1, 4}}}},
         {"THIS IS A TEST TEXT$", 20, 3, {{"TEST", 4, {10}}, {"IS A", 4, {5}}, {"EXT$", 4, {16}}}}};

    for (auto item : _table) {
        t_ukkonen<char> tree(item.p, item.size);
        auto debug_handler = [](t_ukkonen<char>::trienode* node, int level, const char* p, size_t size) -> void {
            if (p) {
                basic_stream bs;

                bs.printf("%p start %i end %i len %i index %i link %p\n", node, node->start, node->end, node->length(), node->suffix_index, node->suffix_link);

                bs.fill(level, ' ');
                bs.printf(R"("%.*s")", (unsigned)size, p);

                _logger->writeln(bs);
            }
        };
        tree.debug(debug_handler);
        for (unsigned i = 0; i < item.count; i++) {
            std::set<int> result = tree.search(item.expect[i].p, item.expect[i].size);
            basic_stream bs;
            print<std::set<int>, basic_stream>(result, bs);

            _test_case.assert(item.expect[i].expects == result, __FUNCTION__, "ukkonen search %s -> %s", item.expect[i].p, bs.c_str());
        }
    }
}

void test_ukkonen2() {
    _test_case.begin("ukkonen algorithm");

    t_ukkonen<char> tree;
    tree.add("b", 1).add("an", 2).add("anas", 4);
    auto dump_handler = [](const char* p, size_t size) -> void {
        if (p) {
            _logger->writeln(R"("%.*s")", (unsigned)size, p);
        }
    };
    tree.dump(dump_handler);
    std::set<int> result = tree.search("ana", 3);
    std::set<int> expect = {1, 3};
    _test_case.assert(result == expect, __FUNCTION__, "ukkonen search");
}

// LCP
// https://www.geeksforgeeks.org/longest-common-prefix-using-sorting/
std::string get_lcp(std::string ar[], size_t n) {
    std::string lcp;
    if (n) {
        if (1 == n) {
            lcp = ar[0];
        } else {
            std::sort(ar, ar + n);

            int en = std::min(ar[0].size(), ar[n - 1].size());

            std::string first = ar[0], last = ar[n - 1];
            int i = 0;
            while (i < en && first[i] == last[i]) i++;

            lcp = first.substr(0, i);
        }
    }
    return lcp;
}

void test_lcp() {
    _test_case.begin("LCP");
    std::string ar[] = {"geeksforgeeks", "geeks", "geek", "geezer"};
    int n = sizeof(ar) / sizeof(ar[0]);
    std::string result = get_lcp(ar, n);

    basic_stream bs;
    bs << "The longest common prefix is: " << result;
    _logger->writeln(bs);

    _test_case.assert(result == "gee", __FUNCTION__, "LCP");
}

void test_wildcards() {
    _test_case.begin("wildcards");

    std::string text = "baaabab";

    t_wildcards<char> wild('?', '*');

    struct testvector {
        const char* pattern;
        bool expect;
    };
    testvector _table[] = {
        {"*****ba*****ab", true},
        {"ba?aba?", true},
        {"ba?ab?c", false},
        {"ba?a*b", true},
    };

    for (auto item : _table) {
        bool test = wild.match(text.c_str(), text.size(), item.pattern, strlen(item.pattern));
        _test_case.assert(item.expect == test, __FUNCTION__, "wildcards %s [%d]", item.pattern, item.expect ? 1 : 0);
    }
}

// pointer simulation
enum tok_t {
    tok_bool,
    tok_int,
    tok_real,
    tok_id,
    tok_assign,
    tok_boolvalue,
    tok_intvalue,
    tok_semicolon,
    tok_question,
    tok_asterisk,
};
struct node {
    tok_t data;

    node(tok_t data) : data(data) {}
};

void test_wildcards2() {
    _test_case.begin("wildcards");

    // pattern matching by pointer
    auto memberof = [](node* const* n, size_t idx) -> tok_t { return n[idx]->data; };
    t_wildcards<tok_t, node*> wild(tok_question, tok_asterisk, memberof);

    // bool a;
    // int b = 0;
    tok_t raw_source[] = {tok_bool, tok_id, tok_semicolon, tok_int, tok_id, tok_assign, tok_intvalue, tok_semicolon};
    // bool ?;
    tok_t raw_pattern1[] = {tok_bool, tok_question, tok_semicolon};
    // bool ?; *
    tok_t raw_pattern2[] = {tok_bool, tok_question, tok_semicolon, tok_asterisk};
    // ? ? ? int ? = ?;
    tok_t raw_pattern3[] = {tok_question, tok_question, tok_question, tok_int, tok_question, tok_assign, tok_question, tok_semicolon};
    // * int ? = *;
    tok_t raw_pattern4[] = {tok_asterisk, tok_int, tok_question, tok_assign, tok_asterisk, tok_semicolon};
    // * int ? = ; (not found)
    tok_t raw_pattern5[] = {tok_asterisk, tok_int, tok_question, tok_assign, tok_semicolon};
    // * real *
    tok_t raw_pattern6[] = {tok_asterisk, tok_real, tok_asterisk};

    auto build_vector = [](std::vector<node*>& target, const tok_t* source, size_t size) -> void {
        for (size_t i = 0; i < size; i++) {
            target.push_back(new node(source[i]));
        }
    };
    auto free_vector = [](std::vector<node*>& target) -> void {
        for (auto item : target) {
            delete item;
        }
        target.clear();
    };

    std::vector<node*> source;
    build_vector(source, raw_source, RTL_NUMBER_OF(raw_source));

    struct testvector {
        const char* text;
        tok_t* array;
        size_t size;
        bool expect;
    };
    testvector _table[] = {
        {"bool ?;", raw_pattern1, RTL_NUMBER_OF(raw_pattern1), true},          {"bool ?; *", raw_pattern2, RTL_NUMBER_OF(raw_pattern2), true},
        {"? ? ? int ? = ?;", raw_pattern3, RTL_NUMBER_OF(raw_pattern3), true}, {"* int ? = *;", raw_pattern4, RTL_NUMBER_OF(raw_pattern4), true},
        {"* int ? = ;", raw_pattern5, RTL_NUMBER_OF(raw_pattern5), false},     {"* real *", raw_pattern6, RTL_NUMBER_OF(raw_pattern6), false},
    };
    for (auto item : _table) {
        std::vector<node*> data;
        build_vector(data, item.array, item.size);

        bool test = wild.match(source, data);
        _test_case.assert(test == item.expect, __FUNCTION__, "wildcards %s [%i]", item.text, item.expect ? 1 : 0);

        free_vector(data);
    }

    free_vector(source);
}

/**
 * merge overlapping intervals
 * https://www.geeksforgeeks.org/merging-intervals/
 * applied parser::psearchex
 */
void test_merge_ovl_intervals() {
    _test_case.begin("merge overlapping intervals");
    t_merge_ovl_intervals<int> moi;
    typedef t_merge_ovl_intervals<int>::interval interval;
    typedef std::vector<interval> result;
    result res;
    result expect;
    basic_stream bs;

    auto func = [&](result::const_iterator iter, int where) -> void {
        switch (where) {
            case seek_t::seek_begin:
                bs << "{";
                bs << "{" << iter->s << "," << iter->e << "}";
                break;
            case seek_t::seek_move:
                bs << ",";
                bs << "{" << iter->s << "," << iter->e << "}";
                break;
            case seek_t::seek_end:
                bs << "}";
                break;
        }
    };

    expect = {interval(1, 9, 0)};
    moi.clear().add(6, 8).add(1, 9).add(2, 4).add(4, 7);
    res = moi.merge();
    for_each<result>(res, func);
    _logger->writeln(bs);  // {1, 9}
    _test_case.assert(res == expect, __FUNCTION__, "test #1");
    bs.clear();

    expect = {interval(1, 4, 0), interval(6, 8, 0), interval(9, 10, 0)};
    // expect = {{1,4,0},{6,8,0},{9,10,0}};
    moi.clear().add(9, 10).add(6, 8).add(1, 3).add(2, 4).add(6, 8);  // partially duplicated
    res = moi.merge();
    for_each<result>(res, func);
    _logger->writeln(bs);  // {1, 4}, {6, 8}, {9, 10}
    _test_case.assert(res == expect, __FUNCTION__, "test #2");
    bs.clear();

    expect = {interval(1, 8, 4), interval(9, 10, 3)};
    moi.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
    res = moi.merge();
    for_each<result>(res, func);
    _logger->writeln(bs);  // {1, 8}, {9, 10}
    _test_case.assert(res == expect, __FUNCTION__, "test #3");
    bs.clear();

    expect = {interval(1, 8, 4), interval(9, 10, 3)};
    moi.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
    res = moi.merge();
    for_each<result>(res, func);
    _logger->writeln(bs);  // {1, 8}, {9, 10}
    _test_case.assert(res == expect, __FUNCTION__, "test #4");
    bs.clear();

    expect = {interval(1, 8, 4)};
    moi.clear().add(1, 8, 4);
    res = moi.merge();
    for_each<result>(res, func);
    _logger->writeln(bs);  // {1, 8}
    _test_case.assert(res == expect, __FUNCTION__, "test #5");
    bs.clear();
}

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
    _test_case.begin("t_aho_corasick + wildcards");

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

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test_kmp();
    test_aho_corasick();
    test_trie();
    test_trie_autocompletion();
    test_trie_lookup();
    test_suffixtree();
    test_suffixtree2();
    test_ukkonen();
    test_ukkonen2();
    test_lcp();
    test_wildcards();
    test_wildcards2();
    test_merge_ovl_intervals();
    test_aho_corasick_wildcard();
    test_aho_corasick_ignorecase();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
