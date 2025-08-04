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

void test_consolecolor() {
    _test_case.begin("console_color");
    console_color concolor;

    _test_case.reset_time();
    console_style_t styles[] = {
        console_style_t::normal, console_style_t::bold, console_style_t::dim, console_style_t::italic, console_style_t::underline, console_style_t::invert,
    };
    console_color_t fgcolors[] = {
        console_color_t::black, console_color_t::red,     console_color_t::green, console_color_t::yellow,
        console_color_t::blue,  console_color_t::magenta, console_color_t::cyan,  console_color_t::white,
    };
    console_color_t bgcolors[] = {
        console_color_t::black,
        console_color_t::white,
    };

    basic_stream bs;
    uint32 loop = 0;
    for (auto bgcolor : bgcolors) {
        concolor.set_bgcolor(bgcolor);
        for (auto style : styles) {
            concolor.set_style(style);
            for (auto fgcolor : fgcolors) {
                concolor.set_fgcolor(fgcolor);

                if (fgcolor != bgcolor) {
                    bs << concolor.turnon() << "test" << concolor.turnoff();
                    if (15 == (loop % 16)) {
                        bs << "\n";
                    }
                    ++loop;
                }
            }
        }
    }
    bs << "\n";
    _logger->consoleln(bs);
    bs.clear();
    _test_case.assert(true, __FUNCTION__, "console color.1 loop %i times", loop);

    concolor.set_style(console_style_t::normal);
    concolor.set_fgcolor(console_color_t::yellow);
    concolor.set_bgcolor(console_color_t::black);

    bs << concolor.turnon() << "color";
    bs << concolor.turnoff() << "default";
    _logger->writeln(bs);
    bs.clear();
    _test_case.assert(true, __FUNCTION__, "console color.2");

    bs << concolor.turnon() << concolor.set_style(console_style_t::bold).set_fgcolor(console_color_t::yellow).set_bgcolor(console_color_t::black) << "color"
       << concolor.turnoff() << "default";
    _logger->writeln(bs);
    bs.clear();
    _test_case.assert(true, __FUNCTION__, "console color.3");
}

void do_test_dump_routine(const byte_t* dump_address, size_t dump_size, stream_t* stream_object, unsigned hex_part = 16, unsigned indent = 0,
                          size_t rebase = 0x0) {
    return_t ret = errorcode_t::success;
    _logger->dump(dump_address, dump_size, hex_part, indent);
    _test_case.test(ret, __FUNCTION__, "dump addr %p size %zi hex %i indent %i rebase %zi", dump_address, dump_size, hex_part, indent, rebase);
}

void test_dumpmemory() {
    _test_case.begin("dump_memory");
    return_t ret = errorcode_t::success;
    ansi_string bs;
    const char* text = "still a man hears what he wants to hear and disregards the rest";  // the boxer - Simon & Garfunkel

    do_test_dump_routine((byte_t*)text, strlen(text), &bs);
    do_test_dump_routine((byte_t*)text, strlen(text), &bs, 32);
    do_test_dump_routine((byte_t*)text, strlen(text), &bs, 16, 4);
    do_test_dump_routine((byte_t*)text, strlen(text), &bs, 16, 4, 0x1000);

    std::string str(text);
    ret = dump_memory(str, &bs);
    _logger->writeln("dump\n%s", bs.c_str());
    _test_case.test(ret, __FUNCTION__, "dump std::string");

    binary_t bin = std::move(str2bin(str));
    ret = dump_memory(bin, &bs);
    _logger->writeln("dump\n%s", bs.c_str());
    _test_case.test(ret, __FUNCTION__, "dump std::vector<byte_t>");

    binary_t bin2;
    ret = dump_memory(bin2, &bs);
    _logger->writeln("dump\n%s", bs.c_str());
    _test_case.test(ret, __FUNCTION__, "dump blank");
}

void test_i128() {
    _test_case.begin("int128");
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
}

void do_test_sprintf_routine(valist& va, const char* fmt, const char* expect) {
    basic_stream bs;

    sprintf(&bs, fmt, va);
    _logger->writeln("formatter %s", fmt);
    _logger->writeln("result    %s", bs.c_str());
    if (expect) {
        _test_case.assert(0 == strcmp(expect, bs.c_str()), __FUNCTION__, "sprintf");
    }
}

void test_sprintf() {
    _test_case.begin("sprintf");

    valist va;
    va << 3.141592 << "phi" << 123;

    _logger->writeln("{1} 3.141592 {2} phi {3} 123");

    _test_case.reset_time();
    do_test_sprintf_routine(va, "value={1} value={2} value={3}", "value=3.141592 value=phi value=123");
    do_test_sprintf_routine(va, "value={2} value={3} value={1}", "value=phi value=123 value=3.141592");
    do_test_sprintf_routine(va, "value={3} value={2} value={1}", "value=123 value=phi value=3.141592");
    do_test_sprintf_routine(va, "value={2} value={1} value={3}", "value=phi value=3.141592 value=123");
    do_test_sprintf_routine(va, "value={2} value={1} value={3} value={2}", "value=phi value=3.141592 value=123 value=phi");
    do_test_sprintf_routine(va, "value={3} value={2} value={2} value={1} value={4} value={5}",
                            "value=123 value=phi value=phi value=3.141592 value={4} value={5}");

    basic_stream bs;
    bs.printf("value %08x ", 0x304);
    sprintf(&bs, "{1}:{2}:{3}", va);
    _logger->writeln(bs);
    _test_case.assert(bs == "value 00000304 3.141592:phi:123", __FUNCTION__, "value 00000304 3.141592:phi:123");
}

void test_vprintf() {
    _test_case.begin("vprintf");

    return_t ret = errorcode_t::success;
    ansi_string str;

#if __cplusplus >= 201402L  // c++14
    valist val;
    make_valist(val, 1, 3.141592, "hello");
    ret = sprintf(&str, "param1 {1} param2 {2} param3 {3}", val);

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "make_list(Ts... args) and sprintf");

    valist va;
    ret = sprintf(&str, "param1 {1} param2 {2} param3 {3}", va << 1 << 3.14 << "hello");

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "sprintf");

    ret = vprintf(&str, "param1 {1} param2 {2} param3 {3}", 1, 3.141592, "hello");

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "vprintf (Ts... args)");
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "at least c++14 required");
#endif
}

void test_stream() {
    _test_case.begin("stream");

    basic_stream bs;
    valist va;

    va << 1 << "test string";  // argc 2

    sprintf(&bs, "value1={1} value2={2}", va);  // value1=1 value2=test string
    _logger->writeln(bs.c_str());
    bs.clear();

    sprintf(&bs, "value1={2} value2={1}", va);  // value1=test string value2=1
    _logger->writeln(bs.c_str());
    bs.clear();

    sprintf(&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3={3}
    _logger->writeln(bs.c_str());

    _test_case.assert(true, __FUNCTION__, "stream");
}

void test_stream_getline() {
    _test_case.begin("stream::getline");

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

void test_stream_stdmap() {
    _test_case.begin("std::map");

    {
        std::map<basic_stream, std::string> stdmap;
        stdmap.insert(std::make_pair("key", "value"));
        stdmap["key1"] = "value1";
        std::string value = stdmap["key"];

        _logger->writeln("key=%s", value.c_str());

        _test_case.assert("value" == value, __FUNCTION__, "basic_stream");
    }

    {
        std::map<ansi_string, std::string> stdmap;
        stdmap.insert(std::make_pair("key", "value"));
        stdmap["key1"] = "value1";
        std::string value = stdmap["key"];

        _logger->writeln("key=%s", value.c_str());

        _test_case.assert("value" == value, __FUNCTION__, "ansi_string");
    }

#if defined _WIN32 || defined _WIN64
    {
        std::map<wide_string, wide_string> stdmap;
        stdmap.insert(std::make_pair(L"key", L"value"));
        stdmap[L"key1"] = L"value1";
        wide_string value = stdmap[L"key"];

        _logger->dump(value.data(), value.size());

        _test_case.assert(wide_string(L"value") == value, __FUNCTION__, "wide_string");
    }
#endif
}

void test_vtprintf() {
    _test_case.begin("variant");

    basic_stream bs;
    variant v;

    v.set_int32(10);
    vtprintf(&bs, v);

    v.set_str_new("sample");
    vtprintf(&bs, v);

    _logger->writeln(bs.c_str());

    _test_case.assert(true, __FUNCTION__, "vtprintf");
}

void test_autoindent() {
    _test_case.begin("autoindent");
    basic_stream bs;
    bs.autoindent(2);
    bs.printf("test\ntest");
    const char* expect = "  test\n  test";
    _logger->writeln(bs);
    _test_case.assert(bs == expect, __FUNCTION__, "indent");
}

void test_split() {
    _test_case.begin("split");

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

void test_split2() {
    _test_case.begin("split");

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

void test_split3() {
    _test_case.begin("split");

    // sketch dtls_record_publisher::publish(tls_records*, ...)

    uint16 maxsize = 500;
    std::list<uint16> temp;

    // push_back(N) N must less than or equal maxsize

    temp.push_back(200);
    temp.push_back(300);

    temp.push_back(400);

    temp.push_back(400);
    temp.push_back(50);

    size_t size = 0;
    std::list<std::queue<uint16>> container;
    std::queue<uint16> q;
    for (auto item : temp) {
        if (size + item > maxsize) {
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
    _test_case.assert(container == expect, __FUNCTION__, "dtls_record_publisher::publish underlying logic");
}
