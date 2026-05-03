/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_kmp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

struct pattern_search_sample_data {
    std::string dummy;
    int value;

    pattern_search_sample_data(std::string s, int v) : dummy(s), value(v) {}
    pattern_search_sample_data(int v) : value(v) {}

    friend bool operator==(const pattern_search_sample_data& other, const pattern_search_sample_data& rhs) { return other.value == rhs.value; }
};

void test_kmp() {
    _test_case.begin("kmp");

    // 0123456789abcdef0123
    // abacaabaccabacabaabb
    //           abacab

    binary_t data = str2bin("abacaabaccabacabaabb");
    binary_t pattern = str2bin("abacab");

    {
        // vector
        t_kmp<byte_t> kmp;
        size_t idx = kmp.search(data, pattern);
        _logger->hdump("data", data);
        _logger->hdump("pattern", pattern);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<byte_t> %zi", idx);
    }

    {
        // contiguous memory space
        t_kmp<byte_t> kmp;
        size_t idx = kmp.search(data.data(), data.size(), pattern.data(), pattern.size());
        _logger->hdump("data", data);
        _logger->hdump("pattern", pattern);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<byte_t> %zi", idx);
    }

    {
        // compare member (see operator ==)
        std::vector<pattern_search_sample_data> data2;
        std::vector<pattern_search_sample_data> pattern2;
        auto prepare = [](std::vector<pattern_search_sample_data>& target, const binary_t& source) -> void {
            for (auto item : source) {
                target.insert(target.end(), item);
            }
        };
        prepare(data2, data);
        prepare(pattern2, pattern);

        t_kmp<pattern_search_sample_data> kmp;
        size_t idx = kmp.search(data2.data(), data2.size(), pattern2.data(), pattern2.size());
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<struct> %zi", idx);
    }

    {
        std::vector<pattern_search_sample_data*> data2;
        std::vector<pattern_search_sample_data*> pattern2;
        auto prepare = [](std::vector<pattern_search_sample_data*>& target, const binary_t& source) -> void {
            for (auto item : source) {
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
        auto comparator = [](const pattern_search_sample_data* other, const pattern_search_sample_data* rhs) -> bool { return (other->value == rhs->value); };
        size_t idx = kmp.search(data2.data(), data2.size(), pattern2.data(), pattern2.size(), 0, comparator);
        _test_case.assert(0xa == idx, __FUNCTION__, "pattern search<struct*> %zi using comparator", idx);
        clean(data2);
        clean(pattern2);
    }
}

void testcase_kmp() { test_kmp(); }
