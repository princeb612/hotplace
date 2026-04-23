/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_stream_i128() {
    _test_case.begin("stream");
#ifdef __SIZEOF_INT128__
    ansi_string stream;

    // int8 — [-128 : 127]
    // int16 — [-32768 : 32767]
    // int32 — [-2147483648 : 2147483647]
    // int64 — [-9223372036854775808 : 9223372036854775807]
    // int128 — [-170141183460469231731687303715884105728 : 170141183460469231731687303715884105727]
    // int256 — [-57896044618658097711785492504343953926634992332820282019728792003956564819968 :
    // 57896044618658097711785492504343953926634992332820282019728792003956564819967]

    // uint8 — [0 : 255]
    // uint16 — [0 : 65535]
    // uint32 — [0 : 4294967295]
    // uint64 — [0 : 18446744073709551615]
    // uint128 — [0 : 340282366920938463463374607431768211455]
    // uint256 — [0 : 115792089237316195423570985008687907853269984665640564039457584007913129639935]

    stream.printf("%I128i", (int128)((int128)0x7fffffff << 32) + 0xffffffff);  // int64 9223372036854775807
    _test_case.assert(stream == "9223372036854775807", __FUNCTION__, "signed int64 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128i", (int128)((int128)0x7fffffffffffffff << 64) + 0xffffffffffffffff);  // int128 170141183460469231731687303715884105727
    _test_case.assert(stream == "170141183460469231731687303715884105727", __FUNCTION__, "signed int128 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128u", (uint128)atoi128("170141183460469231731687303715884105727"));  // 170141183460469231731687303715884105727
    _test_case.assert(stream == "170141183460469231731687303715884105727", __FUNCTION__, "signed int128 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128u", (uint128)((uint128)0xffffffffffffffff << 64) + 0xffffffffffffffff);  // 340282366920938463463374607431768211455
    _test_case.assert(stream == "340282366920938463463374607431768211455", __FUNCTION__, "unsigned int128 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128u", (uint128)-1);  // 340282366920938463463374607431768211455
    _test_case.assert(stream == "340282366920938463463374607431768211455", __FUNCTION__, "unsigned int128 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128u", (uint128)atou128("340282366920938463463374607431768211455"));  // 340282366920938463463374607431768211455
    _test_case.assert(stream == "340282366920938463463374607431768211455", __FUNCTION__, "unsigned int128 max %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128i", (int128)((int128)0x8000000000000000 << 64) + 0x0000000000000000);  // -170141183460469231731687303715884105728
    _test_case.assert(stream == "-170141183460469231731687303715884105728", __FUNCTION__, "signed int128 min %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }

    stream.printf("%I128i", atoi128("-170141183460469231731687303715884105728"));  // -170141183460469231731687303715884105728
    _test_case.assert(stream == "-170141183460469231731687303715884105728", __FUNCTION__, "signed int128 min %s", stream.c_str());
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(stream.c_str());
        stream.clear();
    }
#endif
}

void test_stream_getline() {
    _test_case.begin("stream");
    return_t ret = errorcode_t::success;
    ansi_string stream(" line1 \nline2 \n  line3\nline4");
    ansi_string line;

    size_t pos = 0;
    size_t brk = 0;
    int l = 0;

    _test_case.reset_time();
    while (1) {
        ret = stream.getline(pos, &brk, line);
        if (errorcode_t::success != ret) {
            break;
        }
        line.rtrim();

        {
            test_case_notimecheck notimecheck(_test_case);
            _logger->writeln("%.*s", (unsigned)line.size(), line.c_str());
            l++;
        }

        pos = brk;
    }
    _test_case.assert(4 == l, __FUNCTION__, "getline");
}

template <typename TYPE>
void t_test_rule_of_5(const std::string& name) {
    //  -fsanitize=address -fno-omit-frame-pointer -g

    _logger->writeln(name);

    {
        TYPE a("hello");
        TYPE b = a;  // copy ctor
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b;
        b = a;  // copy assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b = std::move(a);  // move ctor
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b;
        b = std::move(a);  // move assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        // map insert (copy ctor)
        std::map<int, TYPE> m;
        TYPE t("Alice");
        m.insert({1, t});
    }
    {
        // operator[] (default + assignment)
        std::map<int, TYPE> m;
        m[1] = TYPE("Bob");
    }
    {
        // emplace (move)
        std::map<int, TYPE> m;
        m.emplace(1, TYPE("Charlie"));
    }
    {
        TYPE a("hello");
        TYPE b;
        a = a;  // self assignment (X)
        _logger->writeln("a       = %s", a.c_str());
        b = a;  // copy assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
        b = std::move(a);  // move assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        // vector (reallocation → move/copy explosion)
        std::vector<TYPE> v;
        for (int i = 0; i < 10; ++i) {
            v.push_back(TYPE("Temp"));
        }
    }
    _test_case.assert(true, __FUNCTION__, "see sanitize log");
}

void test_stream_basic_stream() {
    _test_case.begin("stream");
    t_test_rule_of_5<basic_stream>("basic_stream");
}

void test_stream_vtprintf() {
    _test_case.begin("stream");
    basic_stream bs;
    variant v;

    v.set_int32(10);
    vtprintf(&bs, v);

    v.set_str_new("sample");
    vtprintf(&bs, v);

    _logger->writeln(bs.c_str());

    _test_case.assert(true, __FUNCTION__, "vtprintf");
}

void test_stream_autoindent() {
    _test_case.begin("stream");
    basic_stream bs;
    bs.autoindent(2);
    bs.printf("test\ntest");
    const char* expect = "  test\n  test";
    _logger->writeln(bs);
    _test_case.assert(bs == expect, __FUNCTION__, "indent");
}

void test_stream_split() {
    _test_case.begin("stream");
    const size_t testsize = 0x410;  // 1024 + 16
    const size_t testfragsize = 0x80;
    binary_t block;
    for (auto i = 0; i < testsize; i++) {
        block.push_back((byte_t)(i % 0x100));
    }

    typedef std::map<size_t, size_t> split_table;
    split_table table1;
    split_table expect1 = {{0x0, 0x80}, {0x80, 0x80}, {0x100, 0x80}, {0x180, 0x80}, {0x200, 0x80}, {0x280, 0x80}, {0x300, 0x80}, {0x380, 0x80}, {0x400, 0x10}};
    auto lambda1 = [&](const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize) -> void {
        table1.insert({fragoffset, fragsize});
        _logger->writeln("split @0x%03zx [0x%zx]", fragoffset, fragsize);
        // _logger->dump(stream + fragoffset, fragsize, 16, 3);
    };
    split(block, testfragsize, lambda1);
    _test_case.assert(table1 == expect1, __FUNCTION__, "split");

    split_table table2;
    split_table expect2 = {{0x0, 0x70}, {0x70, 0x80}, {0x0f0, 0x80}, {0x170, 0x80}, {0x1f0, 0x80}, {0x270, 0x80}, {0x2f0, 0x80}, {0x370, 0x80}, {0x3f0, 0x20}};
    auto lambda2 = [&](const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize) -> void {
        table2.insert({fragoffset, fragsize});
        _logger->writeln("split @0x%03zx [0x%zx]", fragoffset, fragsize);
        // _logger->dump(stream + fragoffset, fragsize, 16, 3);
    };
    split(block, testfragsize, 0x10, lambda2);
    _test_case.assert(table2 == expect2, __FUNCTION__, "split");
}

void test_stream_split2() {
    _test_case.begin("stream");
    /**
     * input
     *   group #0 "group0" size 100
     *   group #1 "group1" size 210
     *   group #2 "group2" size 30
     *   group #3 "group3" size 0
     *   segment size 80
     * output
     *   segment #0 group #0 "group0" offset 0 size 80
     *   segment #1 group #0 "group0" offset 80 size 20
     *   segment #1 group #1 "group1" offset 0 size 60
     *   segment #2 group #1 "group1" offset 60 size 80
     *   segment #3 group #1 "group1" offset 140 size 70
     *   segment #3 group #2 "group2" offset 0 size 10
     *   segment #4 group #2 "group2" offset 10 size 20
     *   segment #4 group #3 "group3" offset 0 size 0
     */
    struct expect_table_t {
        int segment;
        int group;
        std::string desc;
        size_t offset;
        size_t size;
    } expect_table[] = {
        {0, 0, "group0", 0, 80},   {1, 0, "group0", 80, 20}, {1, 1, "group1", 0, 60},  {2, 1, "group1", 60, 80},
        {3, 1, "group1", 140, 70}, {3, 2, "group2", 0, 10},  {4, 2, "group2", 10, 20}, {4, 3, "group3", 0, 0},
    };

    binary_t group0;
    binary_t group1;
    binary_t group2;
    binary_t group3;
    group0.resize(100);
    group1.resize(210);
    group2.resize(30);

    splitter<std::string> spl;
    spl.set_segment_size(80);
    spl.add(std::move(group0), std::move(std::string("group0")));
    spl.add(std::move(group1), std::move(std::string("group1")));
    spl.add(std::move(group2), std::move(std::string("group2")));
    spl.add(std::move(group3), std::move(std::string("group3")));
    size_t idx = 0;
    int segment = -1;
    int group = -1;
    const char* routine = __FUNCTION__;
    auto lambda = [&](uint32 flags, const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize, const std::string& desc) -> void {
        std::string comments;
        if (splitter_flag_t::splitter_new_segment & flags) {
            ++segment;
            comments += "new segment";
        }
        if (splitter_flag_t::splitter_new_group & flags) {
            ++group;
            if (false == comments.empty()) {
                comments += " & ";
            }
            comments += "new group";
        }

        auto expect = expect_table[idx++];
        bool test = false;
        test = (expect.segment == segment) && (expect.group == group) && (expect.desc == desc) && (expect.offset == fragoffset) && (expect.size == fragsize);
        _test_case.assert(test, routine, R"(segment #%i group #%i "%s" size %zi fragment offset %zi fragment size %zi %s)", segment, group, desc.c_str(), size,
                          fragoffset, fragsize, comments.c_str());

        // dump if necessary
    };
    spl.run(lambda);
}

void test_stream_split3() {
    _test_case.begin("stream");
    // sketch dtls_record_publisher::publish(tls_records*, ...)

    uint16 segment_size = 500;
    std::list<uint16> temp;

    // push_back(N) N must less than or equal segment_size

    temp.push_back(200);
    temp.push_back(300);

    temp.push_back(400);

    temp.push_back(400);
    temp.push_back(50);

    size_t size = 0;
    std::list<std::queue<uint16>> container;
    std::queue<uint16> q;
    for (auto item : temp) {
        if (size + item > segment_size) {
            container.push_back(std::move(q));
            size = 0;
        }

        q.push(item);
        size += item;
    }
    if (false == q.empty()) {
        container.push_back(std::move(q));
    }

    std::list<std::queue<uint16>> expect;
    {
        // {{200, 300}, {400}, {400, 50}};
        std::queue<uint16> qitem;
        qitem.push(200);
        qitem.push(300);
        expect.push_back(std::move(qitem));
        qitem.push(400);
        expect.push_back(std::move(qitem));
        qitem.push(400);
        qitem.push(50);
        expect.push_back(std::move(qitem));
    }
    _test_case.assert(container == expect, __FUNCTION__, "segmentation");
}

void testcase_stream() {
    test_stream_basic_stream();
    test_stream_i128();
    test_stream_getline();
    test_stream_vtprintf();
    test_stream_autoindent();
    test_stream_split();
    test_stream_split2();
    test_stream_split3();
}
