/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_set.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

/**
 * merge overlapping intervals
 * https://www.geeksforgeeks.org/merging-intervals/
 * applied parser::psearchex
 */
void test_range_set1() {
    _test_case.begin("set");
    t_tagged_range_set<int, int> rs;
    typedef t_tagged_range_set<int, int>::interval interval;
    typedef std::vector<interval> result;
    result res;
    result expect;

    auto func = [&](result::const_iterator iter, int where, basic_stream& bs) -> void {
        switch (where) {
            case seek_t::seek_begin:
                bs << "{";
                bs << "{" << iter->begin << "," << iter->end << "}";
                break;
            case seek_t::seek_move:
                bs << ",";
                bs << "{" << iter->begin << "," << iter->end << "}";
                break;
            case seek_t::seek_end:
                bs << "}";
                break;
        }
    };

    auto lambda_log = [&](basic_stream& bs) -> void { for_each<result, basic_stream>(res, func, bs); };

    expect = {interval(1, 9, 0)};
    rs.clear().add(6, 8).add(1, 9).add(2, 4).add(4, 7);
    res = rs.merge();
    // {1, 9}
    _logger->writeln(lambda_log);
    _test_case.assert(res == expect, __FUNCTION__, "test #1");

    expect = {interval(1, 4, 0), interval(6, 8, 0), interval(9, 10, 0)};
    // expect = {{1,4,0},{6,8,0},{9,10,0}};
    rs.clear().add(9, 10).add(6, 8).add(1, 3).add(2, 4).add(6, 8);  // partially duplicated
    res = rs.merge();
    // {1, 4}, {6, 8}, {9, 10}
    _logger->writeln(lambda_log);
    _test_case.assert(res == expect, __FUNCTION__, "test #2");

    expect = {interval(1, 8, 4), interval(9, 10, 3)};
    rs.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
    res = rs.merge();
    // {1, 8}, {9, 10}
    _logger->writeln(lambda_log);
    _test_case.assert(res == expect, __FUNCTION__, "test #3");

    expect = {interval(1, 8, 4), interval(9, 10, 3)};
    rs.clear().add(9, 10, 3).add(6, 8, 2).add(1, 3, 0).add(2, 4, 1).add(1, 8, 4);
    res = rs.merge();
    // {1, 8}, {9, 10}
    _logger->writeln(lambda_log);
    _test_case.assert(res == expect, __FUNCTION__, "test #4");

    expect = {interval(1, 8, 4)};
    rs.clear().add(1, 8, 4);
    res = rs.merge();
    // {1, 8}
    _logger->writeln(lambda_log);
    _test_case.assert(res == expect, __FUNCTION__, "test #5");
}

void test_range_set2() {
    _test_case.begin("set");

    {
        using range_set = t_range_set<size_t>;
        using interval = t_interval<size_t>;

        range_set rs;
        rs.add(0, 1).add(1, 31);
        auto res = rs.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.begin, item.end);
        }
        _test_case.assert(1 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == interval(0, 31), __FUNCTION__, "res[0]");
    }

    {
        using range_set = t_range_set<uint8>;
        using interval = t_interval<uint8>;

        range_set rs;
        rs.add(1, 4).add(6, 10).subtract(3, 7);
        auto res = rs.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.begin, item.end);
        }
        _test_case.assert(2 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == interval(1, 2), __FUNCTION__, "res[0]");
        _test_case.assert(res[1] == interval(8, 10), __FUNCTION__, "res[1]");
    }

    {
        using range_set = t_range_set<int>;
        using interval = t_interval<int>;

        range_set rs;
        rs.add(1, 4).add(6, 10).subtract(1, 7);
        auto res = rs.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.begin, item.end);
        }
        _test_case.assert(1 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == interval(8, 10), __FUNCTION__, "res[0]");
    }

    {
        using range_set = t_range_set<int>;
        using interval = t_interval<int>;

        range_set rs;
        rs.add(-10, 4).add(6, 10).subtract(-3, 8);
        auto res = rs.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.begin, item.end);
        }
        _test_case.assert(2 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == interval(-10, -4), __FUNCTION__, "res[0]");
        _test_case.assert(res[1] == interval(9, 10), __FUNCTION__, "res[1]");
    }
}

void test_ack() {
    _test_case.begin("set");

    using range_set = t_range_set<uint32>;

    auto lambda = [&](const char* func, const char* text, t_range_set<uint32>& p, ack_t& end) -> void {
        ack_t ack;
        ack << p;

        range_set temp;
        ack >> temp;

        _test_case.assert(ack == end, func, text);
        _test_case.assert(p == temp, func, text);
    };

    {
        // #35 ACK(12, FAR:5)
        range_set part;
        part.add(7).add(8).add(9).add(10).add(11).add(12);

        ack_t expect(12, 5);

        lambda(__FUNCTION__, "ACK(12, FAR:5)", part, expect);
    }
    {
        // #37 ACK(14, FAR:0, [0]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14);

        ack_t expect(14, 0);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(14, FAR:0, [0]G:0,R:5)", part, expect);
    }
    {
        // #46 ACK(16, FAR:2, [0]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14).add(15, 16);

        ack_t expect(16, 2);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(16, FAR:2, [0]G:0,R:5)", part, expect);
    }
    {
        // #47 ACK(18, FAR:4, [0]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18);

        ack_t expect(18, 4);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(18, FAR:4, [0]G:0,R:5)", part, expect);
    }
    {
        // #48 ACK(21, FAR:0, [0]G:1,R:4, [1]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21);

        ack_t expect(21, 0);
        expect.ack_ranges.push_back(ack_range_t(1, 4));
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(21, FAR:0, [0]G:1,R:4, [1]G:0,R:5)", part, expect);
    }
    {
        // #49 ACK(21, FAR:0, [0]G:0,R:5, [1]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19);

        ack_t expect(21, 0);
        expect.ack_ranges.push_back(ack_range_t(0, 5));
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(21, FAR:0, [0]G:0,R:5, [1]G:0,R:5)", part, expect);
    }
    {
        // #50 ACK(22, FAR:8, [0]G:0,R:5)
        range_set part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20);

        ack_t expect(22, 8);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(22, FAR:8, [0]G:0,R:5)", part, expect);
    }
}

void test_subtraction() {
    _test_case.begin("set");
    // [retransmission] check PKN not acknowledged

    {
        using range_set = t_range_set<uint32>;

        range_set rs;
        rs.add(7, 12).add(15, 16).add(17, 18).add(19, 25);
        rs.subtract(7, 11).subtract(16, 16).subtract(17, 19).subtract(23, 25).for_each([](uint32 begin, uint32 end) -> void {
            if (begin == end) {
                _logger->writeln("> %u", begin);
            } else {
                _logger->writeln("> %u-%u", begin, end);
            }
        });
        range_set expect;
        expect.add(12, 12).add(15, 15).add(20, 22);
        _test_case.assert(rs == expect, __FUNCTION__, "subtract #1");
    }

    {
        using range_set = t_range_set<uint32>;

        range_set rs;
        rs.add(7, 12).add(15, 16).add(17, 18).add(19, 25);
        range_set ovl2;
        ovl2.add(7, 11).add(16, 16).add(17, 19).add(23, 25);
        rs.subtract(ovl2).for_each([](uint32 begin, uint32 end) -> void {
            if (begin == end) {
                _logger->writeln("> %u", begin);
            } else {
                _logger->writeln("> %u-%u", begin, end);
            }
        });
        range_set expect;
        expect.add(12, 12).add(15, 15).add(20, 22);
        _test_case.assert(rs == expect, __FUNCTION__, "subtract #2");
    }

    {
        using range_set = t_range_set<uint32>;

        range_set part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20).add(25).add(23).add(24);
        part.subtract(7, 12).subtract(14).subtract(16).subtract(17, 18).subtract(19, 22).subtract(23, 24).subtract(26, 30).for_each([](uint32 begin, uint32 end) -> void {
            if (begin == end) {
                _logger->writeln("> %u", begin);
            } else {
                _logger->writeln("> %u-%u", begin, end);
            }
        });
        range_set expect;
        expect.add(15).add(25);
        _test_case.assert(part == expect, __FUNCTION__, "subtract #3");
    }

    {
        using range_set = t_range_set<uint32>;

        range_set part1;
        part1.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20).add(25).add(23).add(24);
        range_set part2;
        part2.add(7, 12).add(14).add(16).add(17, 18).add(19, 22).add(23, 24).add(26, 30);
        part1.subtract(part2).for_each([](uint32 begin, uint32 end) -> void {
            if (begin == end) {
                _logger->writeln("> %u", begin);
            } else {
                _logger->writeln("> %u-%u", begin, end);
            }
        });
        range_set expect;
        expect.add(15).add(25);
        _test_case.assert(part1 == expect, __FUNCTION__, "subtract #4");
    }
    {
        using range_set = t_range_set<char>;

        range_set part1;
        part1.add('A', 'C').add('D', 'F');
        range_set part2;
        part2.add('C', 'E');
        part1.subtract(part2).for_each([](char begin, char end) -> void {
            if (begin == end) {
                _logger->writeln("> %c", begin);
            } else {
                _logger->writeln("> %c-%c", begin, end);
            }
        });
        range_set expect;
        expect.add('A', 'B').add('F');
        _test_case.assert(part1 == expect, __FUNCTION__, "subtract #5");
    }
}

template <typename T>
void dump(t_range_set<t_range_value<T>>& rs, basic_stream& dbs) {
    dbs.clear();
    rs.for_each2([&](t_interval<t_range_value<T>> interval) -> void {
        dbs.printf("%s", (interval.begin_flag == range_flag_t::closed) ? "[" : "(");
        switch (interval.begin.type) {
            case range_type_t::minvalue:
                dbs.printf("MIN");
                break;
            case range_type_t::value: {
                variant v(interval.begin.value);
                vtprintf(&dbs, v);
            } break;
            case range_type_t::maxvalue:
                dbs.printf("MAX");
                break;
        }
        if (interval.begin != interval.end) {
            dbs.printf("..");
            switch (interval.end.type) {
                case range_type_t::minvalue:
                    dbs.printf("MIN");
                    break;
                case range_type_t::value: {
                    variant v(interval.end.value);
                    vtprintf(&dbs, v);
                } break;
                case range_type_t::maxvalue:
                    dbs.printf("MAX");
                    break;
            }
        }
        dbs.printf("%s", (interval.end_flag == range_flag_t::closed) ? "]" : ")");
    });
}

void test_range_set3() {
    _test_case.begin("set");
    t_range_set<t_range_value<int>> rs;
    basic_stream bs;

    {
        rs.clear().add(0, range_type_t::maxvalue);
        const char* expect = "[0..MAX]";
        dump<int>(rs, bs);
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", expect);
        _test_case.assert(true == rs.has(1), __FUNCTION__, "true == has(1)");
        _test_case.assert(false == rs.has(-1), __FUNCTION__, "false == has(-1)");
        _test_case.assert(false == rs.has(range_type_t::minvalue), __FUNCTION__, "false == has(MIN)");
        _test_case.assert(true == rs.has(range_type_t::maxvalue), __FUNCTION__, "true == has(MAX)");
    }
    {
        rs.clear().add(range_type_t::minvalue, -1);
        const char* expect = "[MIN..-1]";
        dump<int>(rs, bs);
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", expect);
        _test_case.assert(false == rs.has(1), __FUNCTION__, "false == has(1)");
        _test_case.assert(true == rs.has(-1), __FUNCTION__, "true == has(-1)");
        _test_case.assert(true == rs.has(range_type_t::minvalue), __FUNCTION__, "true == has(MIN)");
        _test_case.assert(false == rs.has(range_type_t::maxvalue), __FUNCTION__, "false == has(MAX)");
    }
    {
        rs.clear().add(range_type_t::minvalue, range_type_t::maxvalue);
        const char* expect = "[MIN..MAX]";
        dump<int>(rs, bs);
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", expect);
        _test_case.assert(true == rs.has(1), __FUNCTION__, "true == has(1)");
        _test_case.assert(true == rs.has(-1), __FUNCTION__, "true == has(-1)");
        _test_case.assert(true == rs.has(range_type_t::minvalue), __FUNCTION__, "true == has(MIN)");
        _test_case.assert(true == rs.has(range_type_t::maxvalue), __FUNCTION__, "true == has(MAX)");
    }
    {
        rs.clear().add(range_type_t::minvalue, range_type_t::minvalue);
        const char* expect = "[MIN]";
        dump<int>(rs, bs);
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", expect);
        _test_case.assert(false == rs.has(1), __FUNCTION__, "false == has(1)");
        _test_case.assert(false == rs.has(-1), __FUNCTION__, "false == has(-1)");
        _test_case.assert(true == rs.has(range_type_t::minvalue), __FUNCTION__, "true == has(MIN)");
        _test_case.assert(false == rs.has(range_type_t::maxvalue), __FUNCTION__, "false == has(MAX)");
    }
    {
        rs.clear().add(range_type_t::maxvalue, range_type_t::maxvalue);
        const char* expect = "[MAX]";
        dump<int>(rs, bs);
        _test_case.assert(bs == expect, __FUNCTION__, "test %s", expect);
        _test_case.assert(false == rs.has(1), __FUNCTION__, "false == has(1)");
        _test_case.assert(false == rs.has(-1), __FUNCTION__, "false == has(-1)");
        _test_case.assert(false == rs.has(range_type_t::minvalue), __FUNCTION__, "false == has(MIN)");
        _test_case.assert(true == rs.has(range_type_t::maxvalue), __FUNCTION__, "true == has(MAX)");
    }
}

void test_range_set4() {
    _test_case.begin("set");
    {
        // [1.0..1.5)(3.5..4.0]
        using range_set = t_range_set<float>;
        using interval = t_interval<float>;

        range_set rs;
        rs.clear().add(1.0, 2.0).add(3.0, 4.0).subtract(1.5, 3.5);

        range_set expect;
        expect  //
            .clear()
            .add(interval(1.0, 1.5, range_flag_t::closed, range_flag_t::open))
            .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
        _test_case.assert(rs == expect, __FUNCTION__, "[1.0..1.5)(3.5..4.0]");
    }

    {
        // [MIN..-1.0][1.0..1.5)(3.5..4.0]
        using range_set = t_range_set<t_range_value<float>>;
        using interval = t_interval<t_range_value<float>>;

        range_set rs;
        rs.clear().add(range_type_t::minvalue, -1.0).add(1.0, 2.0).add(3.0, 4.0).subtract(1.5, 3.5);

        basic_stream bs;
        dump<float>(rs, bs);
        _logger->writeln("> %s", bs.c_str());

        range_set expect;
        expect  //
            .clear()
            .add(range_type_t::minvalue, -1.0)
            .add(interval(1.0, 1.5, range_flag_t::closed, range_flag_t::open))
            .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
        _test_case.assert(rs == expect, __FUNCTION__, "[MIN..-1.0][1.0..1.5)(3.5..4.0]");
    }
    {
        // [MIN, -1.0][1.0, 2.0](3.5, 4.0]
        using range_set = t_range_set<t_range_value<float>>;
        using interval = t_interval<t_range_value<float>>;

        range_set rs;
        rs.clear().add(range_type_t::minvalue, -1.0).add(1.0, 2.0).add(3.0, 4.0).subtract(1.5, 3.5).add(1.5, 2.0).add(3.5, 3.6).merge();

        basic_stream bs;
        dump<float>(rs, bs);
        _logger->writeln("> %s", bs.c_str());

        range_set expect;
        expect  //
            .clear()
            .add(range_type_t::minvalue, -1.0)
            .add(interval(1.0, 2.0, range_flag_t::closed, range_flag_t::closed))
            .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
        _test_case.assert(rs == expect, __FUNCTION__, "[MIN..-1.0][1.0..2.0](3.5..4.0]");
        _test_case.assert(false == rs.has(3.5), __FUNCTION__, "false == has(3.5)");
    }
    {
        // [MIN..-1.0][1.0..1.5)(1.5..2.0)(3.0..3.5)(3.5..4.0]
        using range_set = t_range_set<t_range_value<float>>;
        using interval = t_interval<t_range_value<float>>;

        range_set rs;
        rs.clear()
            .add(range_type_t::minvalue, -1.0)
            .add(1.0, 2.0)
            .add(3.0, 4.0)
            .subtract(1.5, 3.5)
            .add(interval(1.5, 2.0, range_flag_t::open, range_flag_t::open))
            .add(interval(3.0, 3.5, range_flag_t::open, range_flag_t::open))
            .merge();

        basic_stream bs;
        dump<float>(rs, bs);
        _logger->writeln("> %s", bs.c_str());

        range_set expect;
        expect  //
            .clear()
            .add(range_type_t::minvalue, -1.0)
            .add(interval(1.0, 1.5, range_flag_t::closed, range_flag_t::open))
            .add(interval(1.5, 2.0, range_flag_t::open, range_flag_t::open))
            .add(interval(3.0, 3.5, range_flag_t::open, range_flag_t::open))
            .add(interval(3.5, 4.0, range_flag_t::open, range_flag_t::closed));
        _test_case.assert(rs == expect, __FUNCTION__, "[MIN..-1.0][1.0..1.5)(1.5..2.0)(3.0..3.5)(3.5..4.0]");
        _test_case.assert(true == rs.has(3.14), __FUNCTION__, "true == has(3.14)");
        _test_case.assert(false == rs.has(1.5), __FUNCTION__, "false == has(1.5)");
        _test_case.assert(false == rs.has(2.0), __FUNCTION__, "false == has(2.0)");
        _test_case.assert(false == rs.has(3.5), __FUNCTION__, "false == has(3.5)");
    }
}

void test_set() {
    bool has = false;
    // t_set_runtime<int>
    {
        t_set_runtime<int> runtime;
        runtime.insert(1).insert_range(3, 5).erase(3).insert(2);
        has = runtime.contains(3);
        _test_case.assert(false == has, __FUNCTION__, "#1 contains");
    }
    // union
    {
        t_set_runtime<int> runtime;
        runtime.insert(1).insert_range(3, 5).erase(3).insert(2);

        t_set_runtime<int> other;
        other.insert_range(4, 6);

        runtime.union_with(other);
        has = runtime.contains(6);
        _test_case.assert(true == has, __FUNCTION__, "#2 union");
    }
    // erase
    {
        t_set_runtime<int> runtime;
        runtime.insert(1).insert_range(3, 5);

        t_set_runtime<int> other;
        other.insert_range(4, 5);

        runtime.erase_from(other);
        t_set_runtime<int> expect;
        expect.insert(1).insert(3);

        _test_case.assert(runtime == expect, __FUNCTION__, "#3 erase");
    }
    // intersect
    {
        t_set_runtime<int> runtime;
        runtime.insert(1).insert_range(3, 5);

        t_set_runtime<int> other;
        other.insert_range(4, 5);

        runtime.intersect_with(other);
        t_set_runtime<int> expect;
        expect.insert_range(4, 5);

        _test_case.assert(runtime == expect, __FUNCTION__, "#4 intersect");
    }
    // t_set_runtime<double>
    {
        t_set_runtime<double> runtime;
        runtime.insert_range(1.0, 5.0).erase(3.0);
        has = runtime.contains(3.0);
        _test_case.assert(false == has, __FUNCTION__, "#5 contains");
    }
    // intersect
    {
        t_set_runtime<double> runtime;
        runtime.insert_range(1.0, 5.0).erase(3.0);

        t_set_runtime<double> other;
        other.insert_range(2.0, 2.5);

        runtime.intersect_with(other);

        t_set_runtime<double> expect;
        expect.insert_range(2.0, 2.5);

        _test_case.assert(runtime == expect, __FUNCTION__, "#6 intersect");
    }
    // t_set_runtime<std::string>
    {
        t_set_runtime<std::string> runtime;
        runtime.insert("apple").insert("banana").insert("carrot").erase("carrot");
        has = runtime.contains("carrot");
        _test_case.assert(false == has, __FUNCTION__, "#7 contains");
    }
    {
        t_set_runtime<std::string> runtime;
        runtime.insert("apple");

        t_set_runtime<std::string> other;
        other.insert("banana");

        runtime.union_with(other);
        has = runtime.contains("banana");
        _test_case.assert(true == has, __FUNCTION__, "#8 contains");
    }
}

void testcase_set() {
    test_range_set1();
    test_range_set2();
    // RFC 9000 19.3 ACK Frames
    test_ack();
    test_subtraction();
    test_range_set3();
    test_range_set4();
    test_set();
}
