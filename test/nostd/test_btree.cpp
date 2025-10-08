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

void test_btree() {
    _test_case.begin("binary tree");
    // case.1
    {
        t_btree<int> bt;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        _logger->writeln([&](basic_stream& bs) -> void {
            bs.printf("members in [ ");
            bt.for_each([&](int const& i) -> void { bs.printf("%d ", i); });
            bs.printf("]");
        });

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
        bt.insert("hello");
        bt.insert("world");
        bt.insert("t_btree");

        _logger->writeln([&](basic_stream& bs) -> void {
            bs.printf("members in [ ");
            bt.for_each([&](const std::string& s) -> void { bs.printf("%s ", s.c_str()); });
            bs.printf("]");
        });

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
            bt.insert(testdata1(1, "one"));
            bt.insert(testdata1(2, "two"));
            bt.insert(testdata1(3, "three"));
            bt.insert(testdata1(4, "four"));
            bt.insert(testdata1(5, "five"));

            _logger->writeln([&](basic_stream& bs) -> void {
                bs.printf("members in [ ");
                bt.for_each([&](const struct testdata1& t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
                bs.printf("]");
            });

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #1");
        }
        // case.4
        {
            t_btree<struct testdata2> bt;
            bt.insert(testdata2(1, "one"));
            bt.insert(testdata2(2, "two"));
            bt.insert(testdata2(3, "three"));
            bt.insert(testdata2(4, "four"));
            bt.insert(testdata2(5, "five"));

            _logger->writeln([&](basic_stream& bs) -> void {
                bs.printf("members in [ ");
                bt.for_each([&](const struct testdata2& t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
                bs.printf("]");
            });

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #2");
        }
    }
    // case.5~
    {
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
            auto lambda = [](testdata& code) -> void { code.weight++; };
            for (auto b : sample) {
                if (b) {
                    bt.insert(testdata((byte_t)b), lambda);
                }
            }
            _test_case.assert(15 == bt.size(), __FUNCTION__, "t_btree<structure, custom_compararor> insert and update");

            _logger->writeln([&](basic_stream& bs) -> void {
                bs.printf("members in [\n");
                bt.for_each([&](const testdata& t) -> void { bs.printf("%c %02x %zi\n", isprint(t.symbol) ? t.symbol : '?', t.symbol, t.weight); });
                bs.printf("]");
            });
        }
    }
}
