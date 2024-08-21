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

void test_find_lessthan_or_equal() {
    _test_case.begin("find_lessthan_or_equal");

    std::set<int> container = {1, 2, 4, 7, 11, 16, 22, 29};
    std::vector<int> input = {1, 2, 3, 5, 8, 10, 12, 17, 20, 23, 30};
    std::vector<int> expect = {1, 2, 2, 4, 7, 7, 11, 16, 16, 22, 29};

    basic_stream bs;
    print<std::set<int>, basic_stream>(container, bs);
    _logger->writeln(bs);

    for (size_t i = 0; i < input.size(); i++) {
        int value = 0;
        int point = input[i];
        find_lessthan_or_equal<int>(container, point, value);
        _test_case.assert(value == expect[i], __FUNCTION__, "%i -> %i", point, value);
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

    test_btree();
    test_avl_tree();
    test_vector();
    test_list();
    test_pq();
    test_find_lessthan_or_equal();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
