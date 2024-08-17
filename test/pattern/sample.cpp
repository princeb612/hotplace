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
        int npat;
        struct {
            const char* p;
            size_t size;
        } pat[10];
        int nexpect;
        struct {
            // pair(pos_occurrence, id_pattern)
            size_t idx;
            unsigned patid;
        } expect[10];
    } _table[] = {
        {
            // t_aho_corasick ac;
            // ac.insert("abc", 3).insert("ab", 2).insert("bc", 2).insert("a", 1);
            // ac.build();
            // const char* source = "abcaabc";
            // ac.search(source, strlen(source));
            "abcaabc",
            4,
            {
                {"abc", 3},  // pattern 0
                {"ab", 2},   // pattern 1
                {"bc", 2},   // pattern 2
                {"a", 1},    // pattern 3
            },
            9,
            {
                //          abcaabc
                {0, 0},  // abc
                {0, 1},  // ab
                {0, 3},  // a
                {1, 2},  //  bc
                {3, 3},  //    a
                {4, 0},  //     abc
                {4, 1},  //     ab
                {4, 3},  //     a
                {5, 2},  //      bc
            },
        },
        {
            // t_aho_corasick ac;
            // ac.insert("cache", 5).insert("he", 2).insert("chef", 4).insert("achy", 4);
            // ac.build();
            // const char* source = "cacachefcachy";
            // ac.search(source, strlen(source));
            "cacachefcachy",
            4,
            {
                {"cache", 5},  // pattern 0
                {"he", 2},     // pattern 1
                {"chef", 4},   // pattern 2
                {"achy", 4},   // pattern 3
            },
            4,
            {
                //          cacachefcachy
                {2, 0},  //   cache
                {4, 2},  //     chef
                {5, 1},  //      he
                {9, 3},  //          achy
            },
        },
        {
            // t_aho_corasick ac;
            // ac.insert("he", 2).insert("she", 3).insert("hers", 4).insert("his", 3);
            // ac.build();
            // const char* source = "ahishers";
            // ac.search(source, strlen(source));
            "ahishers",
            4,
            {
                {"he", 2},    // pattern 0
                {"she", 3},   // pattern 1
                {"hers", 4},  // pattern 2
                {"his", 3},   // pattern 3
            },
            4,
            {
                //         ahishers
                {1, 3},  // his
                {3, 1},  //   she
                {4, 0},  //    he
                {4, 2},  //    hers
            },
        },
    };

    for (auto item : _table) {
        t_aho_corasick<char> ac;
        std::multimap<size_t, unsigned> expect;
        std::multimap<size_t, unsigned> result;

        _logger->writeln(R"(source "%s")", item.source);
        for (int i = 0; i < item.npat; i++) {
            auto p = item.pat[i].p;
            auto size = item.pat[i].size;
            ac.insert(p, size);
            _logger->writeln(R"(pattern[%i] "%.*s")", i, size, p);
        }
        for (int i = 0; i < item.nexpect; i++) {
            auto patid = item.expect[i].patid;
            auto p = item.pat[patid].p;
            auto idx = item.expect[i].idx;
            expect.insert({idx, patid});
            _logger->writeln(R"(expect pattern[%i](as is "%s") at source[%zi])", patid, p, idx);
        }

        ac.build();
        result = ac.search(item.source, strlen(item.source));

        _test_case.assert(expect == result, __FUNCTION__, R"(multiple pattern search "%s")", item.source);
    }

    t_aho_corasick<char> ac;
    ac.insert("he", 2);
    ac.insert("she", 3);
    ac.insert("hers", 4);
    ac.insert("his", 3);
    ac.build();
    const char* source = "ahishers";
    std::multimap<size_t, unsigned> result;
    std::multimap<size_t, unsigned> expect = {{1, 3}, {3, 1}, {4, 0}, {4, 2}};  // only have to keep order {4,0}, {4,2}
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
            printf("%.*s\n", (unsigned)size, p);
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
            printf("%.*s\n", (unsigned)size, p);
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
        unsigned count;
        unsigned expect[5];
    };

    t_suffixtree<char> tree("geeksforgeeks.org", 17);
    testvector _table_pattern[] = {
        {"ee", 2, 2, {1, 9}},    //
        {"geek", 4, 2, {0, 8}},  //
        {"quiz", 4, 0},          //
        {"forgeeks", 8, 1, {5}}  //
    };

    for (auto item : _table_pattern) {
        std::set<unsigned> expect;
        for (unsigned i = 0; i < item.count; i++) {
            expect.insert(item.expect[i]);
        }

        std::set<unsigned> result = tree.search(item.p, item.size);
        for (auto idx : result) {
            _logger->writeln("found at %i", idx);
        }
        _test_case.assert(expect == result, __FUNCTION__, "search %.*s", (unsigned)item.size, item.p);
    }
}

void test_suffixtree2() {
    _test_case.begin("suffix tree");

    struct testvector {
        const char* p;
        size_t size;
        unsigned count;
        unsigned expect[5];
    };

    t_suffixtree<char> tree;
    tree.reset().add("test ", 5).add("geeksforgeeks.org", 17);  // "test geeksforgeeks.org"
    testvector _table_pattern[] = {
        {"ee", 2, 2, {6, 14}},     //
        {"geek", 4, 2, {5, 13}},   //
        {"quiz", 4, 0},            //
        {"forgeeks", 8, 1, {10}},  //
        {"est g", 4, 1, {1}}       //
    };
    for (auto item : _table_pattern) {
        std::set<unsigned> expect;
        for (unsigned i = 0; i < item.count; i++) {
            expect.insert(item.expect[i]);
        }

        std::set<unsigned> result = tree.search(item.p, item.size);
        for (auto idx : result) {
            _logger->writeln("found at %i", idx);
        }
        _test_case.assert(expect == result, __FUNCTION__, "search %.*s", (unsigned)item.size, item.p);
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
            size_t count;
            int res[5];
        } expect[5];
    };
    testvector _table[] =  // ...
        {{"bananas",
          7,
          4,
          {
              {"ana", 3, 2, {1, 3}},
              {"ban", 3, 1, {0}},
              {"nana", 4, 1, {2}},
              {"apple", 5, 0, {}},
          }},
         {"xabac",
          5,
          1,
          {
              {"ba", 2, 1, {2}},
              {"a", 1, 2, {1, 3}},
          }},
         {"abcabcde",
          8,
          2,
          {
              {"abc", 3, 2, {0, 3}},
              {"bc", 2, 2, {1, 4}},
          }},
         {"THIS IS A TEST TEXT$",
          20,
          3,
          {
              {"TEST", 4, 1, {10}},
              {"IS A", 4, 1, {5}},
              {"EXT$", 4, 1, {16}},
          }}};

    for (auto item : _table) {
        t_ukkonen<char> tree(item.p, item.size);
        auto debug_handler = [](t_ukkonen<char>::trienode* node, int level, const char* p, size_t size) -> void {
            if (p) {
                basic_stream bs;

                bs.printf("%p start %i end %i len %i index %i link %p\n", node, node->start, node->end, node->length(), node->suffix_index, node->suffix_link);

                bs.fill(level, ' ');
                bs.printf(R"("%.*s")", (unsigned)size, p);

                _logger->writeln(bs);
                fflush(stdout);
            }
        };
        tree.debug(debug_handler);
        for (unsigned i = 0; i < item.count; i++) {
            std::set<int> expect;
            for (int j = 0; j < item.expect[i].count; j++) {
                expect.insert(item.expect[i].res[j]);
            }
            std::set<int> result = tree.search(item.expect[i].p, item.expect[i].size);
            basic_stream bs;
            print<std::set<int>, basic_stream>(result, bs);

            _test_case.assert(result == expect, __FUNCTION__, "ukkonen search %s -> %s", item.expect[i].p, bs.c_str());
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
            fflush(stdout);
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
    std::cout << "The longest common prefix is: " << result << std::endl;
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

/**
 * @brief   Aho Corasick + wildcard
 * @remarks
 *          single(?) - testing
 *          any(*) - not supported yet
 *
 *          sketch ... aho corasick + wildcard
 *
 *          pattern
 *                  his her hers ?is h?r h*s
 *                  (0 his, 1 her, 2 hers, 3 ?is, 4 h?r, 5 h*s)
 *          input
 *                  ahishers
 *          results                  asis        approach    expect      final       checkpoint
 *          results.single(?)
 *                  [01234567]
 *                   ahishers
 *                   a?              o(6)        -           0[6]        0[6]
 *                    his            o(0)        o(0,3,5)    1[0,3,5]    1[0,3,5]
 *                    ?is            o(3)        -
 *                    ??s            o(5)        -
 *                       her         o(1)        o(1,4)      4[1,4]      4[1,2,4]
 *                       h?r         o(4)        -
 *                       hers        o(2)        -           4[2]
 *                        ??s        o(5)        -           5[5]        5[5]
 *          results.any(*)
 *                    h*s            o(6)        -                       1[0,3,5,6]
 *                       h**s        o(6)        -                       4[1,2,4,6]  actual distance shoud be counted
 *
 * @sample
 *          // t_aho_corasick<char> ac(memberof_defhandler<char>);
 *          t_aho_corasick_wildcard<char> ac(memberof_defhandler<char>, '?', '*');
 *          // his her hers ?is h?r h*s
 *          ac.insert("his", 3);   // pattern 0
 *          ac.insert("her", 3);   // pattern 1
 *          ac.insert("hers", 4);  // pattern 2
 *          ac.insert("?is", 3);   // pattern 3
 *          ac.insert("h?r", 3);   // pattern 4
 *          ac.insert("??s", 3);   // pattern 5
 *          ac.insert("a?", 2);    // pattern 6
 *          ac.build();
 *          const char* source = "ahishers";
 *          std::multimap<size_t, unsigned> result;
 *          std::multimap<size_t, unsigned> expect = {{0, 6}, {1, 0}, {1, 3}, {1, 5}, {4, 1}, {4, 2}, {4, 4}, {5, 5}};
 *          result = ac.search(source, strlen(source));
 *          for (auto item : result) {
 *              _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
 *          }
 *          _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm + wildcards");
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick_wildcard : public t_aho_corasick<BT, T> {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;
    typedef typename t_aho_corasick<BT, T>::trienode trienode;
    enum {
        flag_single = (1 << 0),
        flag_any = (1 << 1),
    };

   public:
    t_aho_corasick_wildcard(memberof_t memberof = memberof_defhandler<BT, T>, const BT& wildcard_single = BT(), const BT& wildcard_any = BT())
        : t_aho_corasick<BT, T>(memberof), _wildcard_single(wildcard_single), _wildcard_any(wildcard_any) {}

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        trienode* current = this->_root;

        for (size_t i = 0; i < size; ++i) {
            const BT& t = this->_memberof(pattern, i);

            if (_wildcard_single == t) {
                current->flag |= flag_single;
            } else if (_wildcard_any == t) {
                current->flag |= flag_any;
            }
            trienode* child = current->children[t];
            if (nullptr == child) {
                child = new trienode;
                current->children[t] = child;
            }
            current = child;
        }

        size_t index = this->_patterns.size();
        current->output.insert(index);
        this->_patterns.insert({index, size});
    }
    virtual void doinsert_pattern(const BT* pattern, size_t size) {
        if (pattern) {
            trienode* current = this->_root;

            for (size_t i = 0; i < size; ++i) {
                const BT& t = pattern[i];
                // sketch - same as t_aho_corasick<BT, T>::doinsert but added flag
                if (_wildcard_single == t) {
                    current->flag |= flag_single;
                } else if (_wildcard_any == t) {
                    current->flag |= flag_any;
                }
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;
                }
                current = child;
            }

            size_t index = this->_patterns.size();
            current->output.insert(index);
            this->_patterns.insert({index, size});
        }
    }

    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<unsigned>>& result) {
        if (source) {
            typedef std::pair<trienode*, size_t> pair_t;
            std::set<pair_t> visit;
            std::queue<pair_t> q;
            q.push({this->_root, 0});

            // debug
            // auto print_children = [&](typename std::unordered_map<BT, trienode*>::const_iterator iter, basic_stream& bs) -> void {
            //     bs.printf("%c, %p", iter->first, iter->second);
            // };
            // auto dump = [&](trienode* current) -> void {
            //     basic_stream bs;
            //     basic_stream output;
            //     print_pair<std::unordered_map<BT, trienode*>, basic_stream>(current->children, bs, print_children);
            //     print<std::set<unsigned>, basic_stream>(current->output, output);
            //     if (false == bs.empty()) {
            //         _logger->writeln("%p children : %s", current, bs.c_str());
            //     }
            //     if (false == output.empty()) {
            //         _logger->writeln("%p output   : %s", current, output.c_str());
            //     }
            // };
            // debug

            auto enqueue = [&](trienode* node, size_t idx) -> void {
                if (idx < size) {
                    // q.push({node, idx});

                    pair_t p = {node, idx};
                    auto iter = visit.find(p);
                    if (visit.end() == iter) {
                        q.push(p);
                        visit.insert(p);
                        // dump(node);
                    }
                }
            };

            // dump(this->_root);

            while (false == q.empty()) {
                auto [current, i] = q.front();
                visit.insert({current, i});
                q.pop();

                const BT& t = this->_memberof(source, i);
                while ((current != this->_root) && (current->children.end() == current->children.find(t)) && (false == has_wildcard(current))) {
                    current = current->failure;
                }
                auto iter = current->children.find(t);
                if (current->children.end() != iter) {
                    // case - found t
                    auto child = iter->second;
                    this->collect_results(child, i, result);
                    enqueue(child, i + 1);

                    // case - sibling single
                    if (current->flag & flag_single) {
                        auto single = current->children[_wildcard_single];
                        enqueue(single, i + 1);
                    }

                    // yield - case not t
                    auto temp = current->failure;
                    if (temp) {
                        if (temp->flag & flag_single) {
                            auto single = temp->children[_wildcard_single];
                            enqueue(single, i + 1);
                        }
                    }
                } else if (current->flag & flag_single) {
                    // case - not t but single
                    auto single = current->children[_wildcard_single];
                    this->collect_results(single, i, result);
                    enqueue(single, i + 1);

                    // yield - case not t nor single
                    auto temp = current->failure;
                    if (temp) {
                        auto iter = temp->children.find(t);
                        if (temp->children.end() != iter) {
                            auto child = iter->second;
                            enqueue(child, i + 1);
                        }
                    }
                } else if (current->flag & flag_any) {
                    // not implemented yet
                }
            }
        }
    }

   private:
    bool has_wildcard(trienode* node) { return node->flag > 0; } /* check node->flag & (flag_single | flag_any) */
    BT _wildcard_single;
    BT _wildcard_any;
};

void test_aho_corasick_wildcard() {
    // studying...
    _test_case.begin("t_aho_corasick + wildcards");

    const unsigned MAX_PATTERN = 10;
    struct testvector {
        const char* source;
        unsigned count_pattern;
        struct {
            const char* pattern;
            unsigned len;
        } pat[MAX_PATTERN];
        unsigned count_expect;
        struct {
            size_t pos;
            unsigned pid;  // pattern id
        } expect[20];
    } _table[] = {
        // banana
        // ??       0[0]
        //  ??      1[0]
        //   ??     2[0]
        //    ??    3[0]
        //     ??   4[0]
        {"banana", 1, {{"??", 2}}, 5, {{0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0}}},
        // banana
        // ???      0[0]
        //  ???     1[0]
        //   ???    2[0]
        //    ???   3[0]
        {"banana", 1, {{"???", 3}}, 4, {{0, 0}, {1, 0}, {2, 0}, {3, 0}}},
        // banana
        //  ??a     1[0]
        //    ??a   3[0]
        {"banana", 1, {{"??a", 3}}, 2, {{1, 0}, {3, 0}}},
        // banana
        // ban     0[0]
        //  an?    1[1]
        //  a?a    1[2]
        //    an?  3[1]
        //    a?a  3[2]
        {"banana", 3, {{"ban", 3}, {"an?", 3}, {"a?a", 3}}, 5, {{0, 0}, {1, 1}, {1, 2}, {3, 1}, {3, 2}}},
        {"ahishers",
         7,
         {{"his", 3}, {"her", 3}, {"hers", 4}, {"?is", 3}, {"h?r", 3}, {"??s", 3}, {"a?", 2}},
         8,
         {{0, 6}, {1, 0}, {1, 3}, {1, 5}, {4, 1}, {4, 2}, {4, 4}, {5, 5}}},
        // ahishers
        // a?i         0[0]
        //  ?is        1[1]
        //  h?         1[3]
        //  ??s        1[4]
        //   ?s        2[2]
        //     h?      4[3]
        //      ??s    5[4]
        //       ?s    6[2]
        {"ahishers", 5, {{"a?i", 3}, {"?is", 3}, {"?s", 2}, {"h?", 2}, {"??s", 3}}, 8, {{0, 0}, {1, 1}, {1, 3}, {1, 4}, {2, 2}, {4, 3}, {5, 4}, {6, 2}}},
        // ahishers
        // ?h          0[2]
        //  h??        1[0]
        //   ?s        2[1]
        //    ?h       3[2]
        //     h??     4[0]
        //       ?s    6[1]
        {"ahishers", 3, {{"h??", 3}, {"?s", 2}, {"?h", 2}}, 6, {{0, 2}, {1, 0}, {2, 1}, {3, 2}, {4, 0}, {6, 1}}},

        //
        // PS Platinum Trophy Games
        //

        // Dark Soul3
        // D????S???3   0[0]
        //   ??_        2[1]
        //    ?_?       3[2]
        {"Dark Soul3", 3, {{"D????S???3", 10}, {"?? ", 3}, {"? ?", 3}}, 3, {{0, 0}, {2, 1}, {3, 2}}},
        // Monster Hunter World: Icebournce
        //    ?ter                              3[0]
        //           ?ter                       10[0]
        //                       ?ce            22[1]
        //                       Ice            22[2]
        //                              ?ce     30[1]
        {"Monster Hunter World: Icebournce", 3, {{"?ter", 4}, {"?ce", 2}, {"Ice", 2}}, 5, {{3, 0}, {10, 0}, {22, 1}, {22, 2}, {29, 1}}},
        // Elden Ring
        //    ?n
        //        ?n
        {"Elden Ring", 1, {{"?n", 2}}, 2, {{3, 0}, {7, 0}}},
    };

    const OPTION& option = _cmdline->value();

    for (auto item : _table) {
        // t_aho_corasick<char> ac(memberof_defhandler<char>);
        t_aho_corasick_wildcard<char> ac(memberof_defhandler<char>, '?', '*');
        std::multimap<size_t, unsigned> result;
        std::multimap<size_t, unsigned> expect;

        _logger->writeln(R"(source     "%.*s")", strlen(item.source), item.source);

        for (unsigned i = 0; i < item.count_pattern; i++) {
            ac.insert(item.pat[i].pattern, item.pat[i].len);
            _logger->writeln(R"(pattern[%i] "%.*s")", i, item.pat[i].len, item.pat[i].pattern);
        }
        ac.build();

        result = ac.search(item.source, strlen(item.source));
        for (auto item : result) {
            _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
        }
        for (unsigned i = 0; i < item.count_expect; i++) {
            expect.insert({item.expect[i].pos, item.expect[i].pid});
        }
        _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm + wildcards");
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

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
