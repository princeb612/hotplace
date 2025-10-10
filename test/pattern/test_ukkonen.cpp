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
                _logger->writeln([&](basic_stream& bs) -> void {
                    bs.printf("%p start %i end %i len %i index %i link %p\n", node, node->start, node->end, node->length(), node->suffix_index,
                              node->suffix_link);

                    bs.fill(level, ' ');
                    bs.printf(R"("%.*s")", (unsigned)size, p);
                });
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
