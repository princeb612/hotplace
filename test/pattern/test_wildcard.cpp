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
