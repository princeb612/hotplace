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

void test_btree() {
    _test_case.begin("binary tree");
    // case.1
    {
        t_btree<int> bt;
        basic_stream bs;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        bs.printf("members in [ ");
        bt.for_each([&](int const& i) -> void { bs.printf("%d ", i); });
        bs.printf("]");
        _logger->writeln(bs);

        _test_case.assert(20 == bt.size(), __FUNCTION__, "t_btree.insert");

        for (i = 0; i < 20; i++) {
            bt.remove(i);
        }
        _test_case.assert(0 == bt.size(), __FUNCTION__, "t_btree.remove");
        _test_case.assert(true == bt.empty(), __FUNCTION__, "t_btree.empty");
    }
    // case.2
    {
        t_btree<std::string> bt;
        basic_stream bs;
        bt.insert("hello");
        bt.insert("world");
        bt.insert("t_btree");

        bs.printf("members in [ ");
        bt.for_each([&](const std::string& s) -> void { bs.printf("%s ", s.c_str()); });
        bs.printf("]");
        _logger->writeln(bs);

        _test_case.assert(3 == bt.size(), __FUNCTION__, "t_btree<std::string>");
    }
    // case.3~
    {
        struct basedata {
            uint32 key;
            std::string value;

            basedata(uint32 k, const std::string& v) : key(k), value(v) {}
            basedata(const basedata& rhs) : key(rhs.key), value(rhs.value) {}
        };
        // 1 2 3 ...
        struct testdata1 : basedata {
            testdata1(uint32 k, const std::string& v) : basedata(k, v) {}
            testdata1(const testdata1& rhs) : basedata(rhs) {}

            bool operator<(const testdata1& rhs) const {
                bool test = false;
                if (key < rhs.key) {
                    return true;
                } else if (key == rhs.key) {
                    return value < rhs.value;
                } else {
                    return false;
                }
            }
        };
        // a b c ...
        struct testdata2 : basedata {
            testdata2(uint32 k, const std::string& v) : basedata(k, v) {}
            testdata2(const testdata2& rhs) : basedata(rhs) {}

            bool operator<(const testdata2& rhs) const {
                bool test = false;
                if (value < rhs.value) {
                    return true;
                } else if (value == rhs.value) {
                    return key < rhs.key;
                } else {
                    return false;
                }
            }
        };

        // case.3
        {
            t_btree<struct testdata1> bt;
            basic_stream bs;
            bt.insert(testdata1(1, "one"));
            bt.insert(testdata1(2, "two"));
            bt.insert(testdata1(3, "three"));
            bt.insert(testdata1(4, "four"));
            bt.insert(testdata1(5, "five"));

            bs.printf("members in [ ");
            bt.for_each([&](const struct testdata1& t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
            bs.printf("]");
            _logger->writeln(bs);

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #1");
        }
        // case.4
        {
            t_btree<struct testdata2> bt;
            basic_stream bs;
            bt.insert(testdata2(1, "one"));
            bt.insert(testdata2(2, "two"));
            bt.insert(testdata2(3, "three"));
            bt.insert(testdata2(4, "four"));
            bt.insert(testdata2(5, "five"));

            bs.printf("members in [ ");
            bt.for_each([&](const struct testdata2& t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
            bs.printf("]");
            _logger->writeln(bs);

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #2");
        }
    }
    // case.5~
    {
        basic_stream bs;
        constexpr char sample[] = "still a man hears what he wants to hear and disregards the rest";

        struct testdata {
            byte_t symbol;
            size_t weight;

            testdata() : symbol(0), weight(0) {}
            testdata(byte_t b) : symbol(b), weight(0) {}
            testdata(const testdata& rhs) : symbol(rhs.symbol), weight(rhs.weight) {}

            // bool operator<(const testdata& rhs) const { return symbol < rhs.symbol;
            // }
        };

        // case.5
        {
            t_btree<testdata, t_type_comparator<testdata>> bt;
            for (auto b : sample) {
                if (b) {
                    bt.insert(testdata((byte_t)b), [](testdata& code) -> void { code.weight++; });
                }
            }
            _test_case.assert(15 == bt.size(), __FUNCTION__, "t_btree<structure, custom_compararor> insert and update");

            bs.printf("members in [\n");
            bt.for_each([&](const testdata& t) -> void { bs.printf("%c %02x %zi\n", isprint(t.symbol) ? t.symbol : '?', t.symbol, t.weight); });
            bs.printf("]");
            _logger->writeln(bs);
        }
    }
}

void test_avl_tree() {
    _test_case.begin("AVL tree");
    {
        t_avltree<int> bt;
        basic_stream bs;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        bs.printf("members in [ ");
        bt.for_each([&](int const& i) -> void { bs.printf("%d ", i); });
        bs.printf("]");
        _logger->writeln(bs);

        _test_case.assert(20 == bt.size(), __FUNCTION__, "t_avltree.insert");

        for (i = 0; i < 20; i++) {
            bt.remove(i);
        }
        _test_case.assert(0 == bt.size(), __FUNCTION__, "t_avltree.remove");
        _test_case.assert(true == bt.empty(), __FUNCTION__, "t_avltree.empty");
    }
}

void test_vector() {
    _test_case.begin("vector");

    basic_stream bs;

    t_vector<int> v1;
    v1.push_back(1);
    v1.push_back(2);
    v1.push_back(3);

    _logger->writeln("case 1");
    print<t_vector<int>, basic_stream>(v1, bs);
    _logger->writeln(bs);

    _test_case.assert(3 == v1.size(), __FUNCTION__, "case 1");
    _test_case.assert((1 == v1[0]) && (2 == v1[1]) && (3 == v1[2]), __FUNCTION__, "case 2");

    t_vector<int> v2(v1);
    t_vector<int> v3(std::move(v1));

    _test_case.assert(3 == v2.size(), __FUNCTION__, "case 3");
    _test_case.assert(3 == v3.size(), __FUNCTION__, "case 4");
    _test_case.assert(0 == v1.size(), __FUNCTION__, "case 5");
}

void test_list() {
    _test_case.begin("list");

    t_list<int> l1;
    l1.push_back(1);
    l1.push_back(2);
    l1.push_back(3);

    basic_stream bs;
    print<t_list<int>, basic_stream>(l1, bs);
    _logger->writeln(bs);

    _test_case.assert(3 == l1.size(), __FUNCTION__, "case 1");
    _test_case.assert(1 == l1.front() && 3 == l1.back(), __FUNCTION__, "case 2");

    t_list<int> l2(l1);
    t_list<int> l3(std::move(l1));

    _test_case.assert(3 == l2.size(), __FUNCTION__, "case 3");
    _test_case.assert(3 == l3.size(), __FUNCTION__, "case 4");
    _test_case.assert(0 == l1.size(), __FUNCTION__, "case 5");
}

void test_pq() {
    _test_case.begin("binaryheap");

    t_binary_heap<uint32> heap;
    openssl_prng prng;
    basic_stream bs;

    std::vector<uint32> table;
    table.resize(10);

    for (size_t i = 0; i < 10; i++) {
        table[i] = prng.rand32();  // expensive
    }

    _test_case.assert(heap.size() == 0, __FUNCTION__, "random generated");

    for (size_t i = 0; i < 10; i++) {
        heap.push(table[i]);  // fast
    }

    _test_case.assert(heap.size() > 0, __FUNCTION__, "case 1");

    bool errorcheck = false;
    uint32 lastone = 0;
    while (heap.size()) {
        uint32 elem = heap.top();
        if (lastone > elem) {
            errorcheck |= true;
        }
        heap.pop();
    }

    _test_case.assert(0 == heap.size(), __FUNCTION__, "case 2");
    _test_case.assert(false == errorcheck, __FUNCTION__, "case 3");
}

template <typename T>
void do_test_graph(t_graph<T>& graph, const T& start) {
    auto traverse_handler = [](const T& from, const T&, int, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", ", ", "");
        basic_stream out;
        out << from << " : " << bs;
        _logger->writeln(out);
    };

    auto adj = graph.build_adjacent();
    adj->learn().infer();
    adj->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "adjacent list #1");
    adj->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "adjacent list #2");
    delete adj;

    auto dfs = graph.build_dfs();
    dfs->learn().infer();
    dfs->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "DFS #1");
    dfs->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "DFS #2");
    delete dfs;

    auto bfs = graph.build_bfs();
    bfs->learn().infer();
    bfs->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "BFS #1");
    bfs->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "BFS #2");
    delete bfs;
}

template <typename T>
void do_test_graph_shortest_path(t_graph<T>& graph, const T& start) {
    auto traverse_handler = [](const T& from, const T& to, int distance, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", " -> ", "");
        basic_stream out;
        out << "path[" << from << "->" << to << "] " << bs << " (distance : " << distance << ")";
        _logger->writeln(out);
    };

    auto shortest = graph.build_dijkstra();
    shortest->learn().infer();
    shortest->traverse(start, traverse_handler);  // [start]
    _test_case.assert(true, __FUNCTION__, "shortest path");
    delete shortest;
}
template <typename T>
void do_test_graph_shortest_path(t_graph<T>& graph, const T& start, const T& end) {
    auto traverse_handler = [&](const T& from, const T& to, int distance, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", " -> ", "");
        basic_stream out;
        out << "path[" << from << "->" << to << "] " << bs << " (distance : " << distance << ")";
        _logger->writeln(out);
    };

    auto shortest = graph.build_dijkstra();
    shortest->learn().infer();
    shortest->traverse(start, end, traverse_handler);  // [start-end]
    _test_case.assert(true, __FUNCTION__, "shortest path");
    delete shortest;
}

void test_graph() {
    _test_case.begin("graph<int>");

    // Data Structures and Algorithm Analysis in C++, 9 Graph Algorithms
    // directed.jpg
    t_graph<int> g;
    g.add_edge(1, 2)
        .add_directed_edge(1, 3)
        .add_directed_edge(1, 4)
        .add_directed_edge(2, 4)
        .add_directed_edge(2, 5)
        .add_directed_edge(3, 6)
        .add_directed_edge(4, 3)
        .add_directed_edge(4, 6)
        .add_directed_edge(4, 7)
        .add_directed_edge(5, 4)
        .add_directed_edge(5, 7)
        .add_directed_edge(7, 6);

    // Shortest-Path Algorithms
    // undirected.jpg
    t_graph<int> g2;
    g2.add_undirected_edge(0, 1, 4)
        .add_undirected_edge(0, 7, 8)
        .add_undirected_edge(1, 7, 11)
        .add_undirected_edge(1, 2, 8)
        .add_undirected_edge(7, 8, 7)
        .add_undirected_edge(7, 6, 1)
        .add_undirected_edge(2, 8, 2)
        .add_undirected_edge(8, 6, 6)
        .add_undirected_edge(2, 3, 7)
        .add_undirected_edge(2, 5, 4)
        .add_undirected_edge(6, 5, 2)
        .add_undirected_edge(3, 5, 14)
        .add_undirected_edge(3, 4, 9)
        .add_undirected_edge(5, 4, 10);

    do_test_graph<int>(g, 1);
    for (auto i = 1; i <= 7; i++) {
        do_test_graph_shortest_path<int>(g, i);
    }
    do_test_graph<int>(g2, 1);
    for (auto i = 0; i <= 8; i++) {
        do_test_graph_shortest_path<int>(g2, i);
    }

    t_graph<int> g3;
    g3.add_undirected_edge(1, 2)
        .add_undirected_edge(2, 3)
        .add_undirected_edge(3, 4)
        .add_undirected_edge(4, 5)
        .add_undirected_edge(5, 6)
        .add_undirected_edge(6, 3)
        .add_undirected_edge(3, 7)
        .add_undirected_edge(7, 1);
    do_test_graph<int>(g3, 1);
    for (auto i = 1; i <= 7; i++) {
        do_test_graph_shortest_path<int>(g3, i);
    }
    do_test_graph_shortest_path<int>(g3, 1, 5);
}

/*
 *  @sa     User-defined literals (since C++11)
 */
int operator"" _min(unsigned long long int x) { return x; }
int operator"" _hour(unsigned long long int x) { return x * 60; }
int operator"" _hour(long double x) { return x * 60; }

void test_graph2() {
    _test_case.begin("graph<std::string>");
    t_graph<std::string> g;

    g.add_edge("get up", "eat breakfast", 15_min);

    g.add_edge("eat breakfast", "brush teeath (morning)", 3_min);
    g.add_edge("eat breakfast", "go to work", 1_hour);

    g.add_edge("go to work", "work", 8_hour);
    g.add_edge("work", "go home", 1_hour);

    g.add_edge("go home", "shower", 15_min);
    g.add_edge("shower", "eat dinner", 15_min);

    g.add_edge("eat dinner", "brush teeath (evening)", 3_min);
    g.add_edge("eat dinner", "watch tv", 1.5_hour);
    g.add_edge("eat dinner", "go to bed", 0.5_hour);

    g.add_edge("go to bed", "dream", 3_min);

    do_test_graph<std::string>(g, "get up");
    do_test_graph_shortest_path<std::string>(g, "get up");
    do_test_graph_shortest_path<std::string>(g, "get up", "dream");
}

struct pattern_search_sample_data {
    std::string dummy;
    int value;

    pattern_search_sample_data(std::string s, int v) : dummy(s), value(v) {}
    pattern_search_sample_data(int v) : value(v) {}

    friend bool operator==(const pattern_search_sample_data& lhs, const pattern_search_sample_data& rhs) { return lhs.value == rhs.value; }
};

void test_pattern_search() {
    _test_case.begin("t_kmp_pattern");

    // 0123456789abcdef0123
    // abacaabaccabacabaabb
    //           abacab

    binary data("abacaabaccabacabaabb");
    binary pattern("abacab");

    {
        // vector
        t_kmp_pattern<byte_t> kmp;
        int idx = kmp.match(data, pattern);
        _logger->hdump("data", data);
        _logger->hdump("pattern", pattern);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<byte_t> %i", idx);
    }

    {
        // contiguous memory space
        t_kmp_pattern<byte_t> kmp;
        int idx = kmp.match(&data.get()[0], data.get().size(), &pattern.get()[0], pattern.get().size());
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

        t_kmp_pattern<pattern_search_sample_data> kmp;
        int idx = kmp.match(&data2[0], data2.size(), &pattern2[0], pattern2.size());
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
        t_kmp_pattern<pattern_search_sample_data*> kmp;
        auto comparator = [](const pattern_search_sample_data* lhs, const pattern_search_sample_data* rhs) -> bool { return (lhs->value == rhs->value); };
        int idx = kmp.match(&data2[0], data2.size(), &pattern2[0], pattern2.size(), 0, comparator);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<struct*> %i using comparator", idx);
        clean(data2);
        clean(pattern2);
    }
}

void test_multipattern_search() {
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
            unsigned patid;
            size_t idx;
        } expect[10];
    } _table[] = {
        {
            // t_aho_corasick ac;
            // ac.insert("abc", 3).insert("ab", 2).insert("bc", 2).insert("a", 1);
            // ac.build_state_machine();
            // const char* source = "abcaabc";
            // ac.search(source, strlen(source));
            "abcaabc",
            4,
            {
                {"abc", 3},
                {"ab", 2},
                {"bc", 2},
                {"a", 1},
            },
            9,
            {
                //          abcaabc
                {3, 0},  // a
                {1, 0},  // ab
                {0, 0},  // abc
                {2, 1},  //  bc
                {3, 3},  //    a
                {3, 4},  //     a
                {1, 4},  //     ab
                {0, 4},  //     abc
                {2, 5},  //      bc
            },
        },
        {
            // t_aho_corasick ac;
            // ac.insert("cache", 5).insert("he", 2).insert("chef", 4).insert("achy", 4);
            // ac.build_state_machine();
            // const char* source = "cacachefcachy";
            // ac.search(source, strlen(source));
            "cacachefcachy",
            4,
            {
                {"cache", 5},
                {"he", 2},
                {"chef", 4},
                {"achy", 4},
            },
            4,
            {
                //          cacachefcachy
                {0, 2},  //   cache
                {1, 5},  //      he
                {2, 4},  //     chef
                {3, 9},  //          achy
            },
        },
        {
            // t_aho_corasick ac;
            // ac.insert("he", 2).insert("she", 3).insert("hers", 4).insert("his", 3);
            // ac.build_state_machine();
            // const char* source = "ahishers";
            // ac.search(source, strlen(source));
            "ahishers",
            4,
            {
                {"he", 2},
                {"she", 3},
                {"hers", 4},
                {"his", 3},
            },
            4,
            {
                //         ahishers
                {3, 1},  //  his
                {1, 3},  //    she
                {0, 4},  //     he
                {2, 4},  //     hers
            },
        },
    };

    for (auto item : _table) {
        t_aho_corasick<char> ac;
        std::multimap<unsigned, size_t> expect;
        std::multimap<unsigned, size_t> result;

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
            expect.insert({patid, idx});
            _logger->writeln(R"(expect pattern[%i](as is "%s") at source[%zi])", patid, p, idx);
        }

        ac.build_state_machine();
        result = ac.search(item.source, strlen(item.source));

        _test_case.assert(expect == result, __FUNCTION__, R"(multiple pattern search "%s")", item.source);
    }

    t_aho_corasick<char> ac;
    ac.insert("he", 2).insert("she", 3).insert("hers", 4).insert("his", 3);
    ac.build_state_machine();
    const char* source = "ahishers";
    ac.search(source, strlen(source));

    std::multimap<unsigned, size_t> result;
    std::multimap<unsigned, size_t> expect = {{0, 4}, {1, 3}, {2, 4}, {3, 1}};
    result = ac.search(source, strlen(source));
    for (auto item : result) {
        _logger->writeln("pattern[%i] at [%zi]", item.first, item.second);
    }
    _test_case.assert(result == expect, __FUNCTION__, "multiple pattern");
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

    test_btree();
    test_avl_tree();
    test_vector();
    test_list();
    test_pq();
    test_graph();
    test_graph2();
    test_pattern_search();
    test_multipattern_search();
    test_trie();
    test_trie_autocompletion();
    test_suffixtree();
    test_suffixtree2();
    test_ukkonen();
    test_ukkonen2();
    test_lcp();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
