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
