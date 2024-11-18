/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <functional>
#include <iostream>
#include <sdk/sdk.hpp>
#include <string>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;
    int attach;

    _OPTION() : verbose(0), log(0), time(0), attach(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int simple_instance1_dtor = 0;
int simple_instance2_dtor = 0;

class simple_instance1 {
   public:
    simple_instance1() {
        _instance.make_share(this);
        _logger->writeln("constructor");
    }
    ~simple_instance1() {
        _logger->writeln("destructor");

        simple_instance1_dtor = 1;
    }

    void dosomething() { _logger->writeln("hello world"); }
    int addref() { return _instance.addref(); }
    int release() { return _instance.delref(); }
    int getref() { return _instance.getref(); }

   private:
    t_shared_reference<simple_instance1> _instance;
};

class simple_instance2 {
   public:
    simple_instance2() { _logger->writeln("constructor"); }
    ~simple_instance2() {
        _logger->writeln("destructor");

        simple_instance2_dtor = 1;
    }
    void dosomething() { _logger->writeln("hello world"); }
};

void test_sharedinstance1() {
    int ret = 0;

    _test_case.begin("shared reference");

    simple_instance1 *inst = new simple_instance1;  // ++refcounter
    _test_case.assert(1 == inst->getref(), __FUNCTION__, "ref count == 1");
    ret = inst->addref();  // ++refcounter
    _test_case.assert(2 == ret, __FUNCTION__, "addref");
    inst->dosomething();
    ret = inst->release();  // --refcounter
    _test_case.assert(1 == ret, __FUNCTION__, "release");
    inst->dosomething();
    ret = inst->release();  // --refcounter, delete here
    _test_case.assert(0 == ret, __FUNCTION__, "release");
    _test_case.assert(1 == simple_instance1_dtor, __FUNCTION__, "dtor called");
}

void test_sharedinstance2() {
    _test_case.begin("shared instance");

    {
        simple_instance2 *object = new simple_instance2;
        t_shared_instance<simple_instance2> inst(object);  // ++refcounter
        _test_case.assert(1 == inst.getref(), __FUNCTION__, "getref==1");
        inst->dosomething();
        t_shared_instance<simple_instance2> inst2(inst);  // ++refcounter
        _test_case.assert(2 == inst.getref(), __FUNCTION__, "getref==2");
        inst2->dosomething();
        {
            t_shared_instance<simple_instance2> inst3;
            inst3 = inst;
            _test_case.assert(3 == inst3.getref(), __FUNCTION__, "getref==3");
        }
        // delete here (2 times ~t_shared_instance)
    }  // curly brace for instance lifetime
    _test_case.assert(1 == simple_instance2_dtor, __FUNCTION__, "shared instance");
}

void test_convert_endian() {
    _test_case.begin("endian");

    {
        int16 i = 0x1234;
        int16 a = htons(i);
        int16 b = convert_endian(i);
        _test_case.assert(a == b, __FUNCTION__, "hton16 %x %x", a, b);
    }

    {
        int32 i = 0x12345678;
        int32 a = htonl(i);
        int32 b = convert_endian(i);
        _test_case.assert(a == b, __FUNCTION__, "hton32 %x %x", a, b);
    }

    struct testvector_64 {
        uint64 h;
        uint64 n;
    } _table_64[] = {
        {
            t_htoi<uint64>("0123456789ABCDEF"),
            t_htoi<uint64>("EFCDAB8967452301"),
        },
        {
            t_htoi<uint64>("1122334455667788"),
            t_htoi<uint64>("8877665544332211"),
        },
    };

    for (auto item : _table_64) {
        _logger->dump((byte_t *)&item.h, sizeof(uint64));
        _logger->dump((byte_t *)&item.n, sizeof(uint64));
        _test_case.assert(hton64(item.h) == item.n, __FUNCTION__, "hton64 %x %x", item.h, item.n);
    }

    struct testvector_128 {
        uint128 h;
        uint128 n;
    } _table_128[] = {
        {
            t_htoi<uint128>("0123456789ABCDEFFEDCBA9876543210"),
            t_htoi<uint128>("1032547698BADCFEEFCDAB8967452301"),
        },
        {
            t_htoi<uint128>("00112233445566778899AABBCCDDEEFF"),
            t_htoi<uint128>("FFEEDDCCBBAA99887766554433221100"),
        },
    };

    for (auto item : _table_128) {
        _logger->dump((byte_t *)&item.h, sizeof(uint128));
        _logger->dump((byte_t *)&item.n, sizeof(uint128));
        _test_case.assert(hton128(item.h) == item.n, __FUNCTION__, "hton128 %x %x", item.h, item.n);
    }
}

void test_endian() {
    _test_case.begin("endian");

    bool ret = false;
    std::string text;
    bool is_be = is_big_endian();
    bool is_le = is_little_endian();

#if defined __LITTLE_ENDIAN
    text = "__LITTLE_ENDIAN__";
    ret = (true == is_le);
#elif defined __BIG_ENDIAN
    text = "__BIG_ENDIAN__";
    ret = (true == is_be);
#endif
    _test_case.assert((true == ret), __FUNCTION__, text.c_str());
}

#define TESTVECTOR_ENTRY(e1, e2) \
    { e1, e2 }

void test_byte_capacity_unsigned() {
    _test_case.begin("byte capacity");
    struct testvector {
        uint128 x;
        int expect;
    } _table[] = {
        TESTVECTOR_ENTRY(0x1, 1),
        TESTVECTOR_ENTRY(0x8, 1),
        TESTVECTOR_ENTRY(0x80, 1),
        TESTVECTOR_ENTRY(0x800, 2),
        TESTVECTOR_ENTRY(0x8000, 2),
        TESTVECTOR_ENTRY(0x80000, 3),
        TESTVECTOR_ENTRY(0x800000, 3),
        TESTVECTOR_ENTRY(0x8000000, 4),
        TESTVECTOR_ENTRY(0x80000000, 4),
        TESTVECTOR_ENTRY(0x800000000, 5),
        TESTVECTOR_ENTRY(0x8000000000, 5),
        TESTVECTOR_ENTRY(0x80000000000, 6),
        TESTVECTOR_ENTRY(0x800000000000, 6),
        TESTVECTOR_ENTRY(0x8000000000000, 7),
        TESTVECTOR_ENTRY(0x80000000000000, 7),
        TESTVECTOR_ENTRY(0x800000000000000, 8),
        TESTVECTOR_ENTRY(0x8000000000000000, 8),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000"), 9),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000"), 9),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000"), 10),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000"), 10),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000"), 11),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000"), 11),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000"), 12),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000"), 12),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000"), 13),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000"), 13),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000000"), 14),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000000"), 14),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000000"), 15),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000000000"), 15),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("10000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("20000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("40000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000000000"), 16),
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity(entry.x);
        _logger->writeln("%032I128x -> %i", entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
    }
}

void test_byte_capacity_signed() {
    _test_case.begin("byte capacity");
    struct testvector {
        int128 x;
        int expect;
    } _table[] = {
        TESTVECTOR_ENTRY(127, 1),
        TESTVECTOR_ENTRY(-128, 1),
        TESTVECTOR_ENTRY(128, 2),
        TESTVECTOR_ENTRY(-129, 2),
        TESTVECTOR_ENTRY(32767, 2),
        TESTVECTOR_ENTRY(-32768, 2),
        TESTVECTOR_ENTRY(32768, 3),
        TESTVECTOR_ENTRY(-32769, 3),
        TESTVECTOR_ENTRY(8388607, 3),
        TESTVECTOR_ENTRY(-8388608, 3),
        TESTVECTOR_ENTRY(2147483647, 4),
        TESTVECTOR_ENTRY(-2147483648, 4),
        TESTVECTOR_ENTRY(549755813887, 5),
        TESTVECTOR_ENTRY(-549755813888, 5),
        TESTVECTOR_ENTRY(140737488355327, 6),
        TESTVECTOR_ENTRY(-140737488355328, 6),
        TESTVECTOR_ENTRY(36028797018963967, 7),
        TESTVECTOR_ENTRY(-36028797018963968, 7),
        TESTVECTOR_ENTRY(9223372036854775807, 8),
        TESTVECTOR_ENTRY(t_atoi<int128>("-9223372036854775808"), 8),
        TESTVECTOR_ENTRY(t_atoi<int128>("2361183241434822606847"), 9),
        TESTVECTOR_ENTRY(t_atoi<int128>("-2361183241434822606848"), 9),
        TESTVECTOR_ENTRY(t_atoi<int128>("604462909807314587353087"), 10),
        TESTVECTOR_ENTRY(t_atoi<int128>("-604462909807314587353088"), 10),
        TESTVECTOR_ENTRY(t_atoi<int128>("154742504910672534362390527"), 11),
        TESTVECTOR_ENTRY(t_atoi<int128>("-154742504910672534362390528"), 11),
        TESTVECTOR_ENTRY(t_atoi<int128>("39614081257132168796771975167"), 12),
        TESTVECTOR_ENTRY(t_atoi<int128>("-39614081257132168796771975168"), 12),
        TESTVECTOR_ENTRY(t_atoi<int128>("10141204801825835211973625643007"), 13),
        TESTVECTOR_ENTRY(t_atoi<int128>("-10141204801825835211973625643008"), 13),
        TESTVECTOR_ENTRY(t_atoi<int128>("2596148429267413814265248164610047"), 14),
        TESTVECTOR_ENTRY(t_atoi<int128>("-2596148429267413814265248164610048"), 14),
        TESTVECTOR_ENTRY(t_atoi<int128>("664613997892457936451903530140172287"), 15),
        TESTVECTOR_ENTRY(t_atoi<int128>("-664613997892457936451903530140172288"), 15),
        TESTVECTOR_ENTRY(t_atoi<int128>("170141183460469231731687303715884105727"), 16),
        TESTVECTOR_ENTRY(t_atoi<int128>("-170141183460469231731687303715884105728"), 16),
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity_signed<int128>(entry.x);
        _logger->writeln("%40I128i %032I128x (%i bytes)", entry.x, entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
    }
}

void test_maphint() {
    _test_case.begin("t_maphint");
    return_t ret = errorcode_t::success;

    std::map<int, std::string> source;
    t_maphint<int, std::string> hint(source);
    source[1] = "one";
    source[2] = "two";
    source[3] = "three";
    std::string value;
    hint.find(1, &value);
    _test_case.assert("one" == value, __FUNCTION__, "t_maphint.find(1)");
    ret = hint.find(10, &value);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "t_maphint.find(10)");

    t_maphint_const<int, std::string> hint_const(source);
    hint_const.find(2, &value);
    _test_case.assert("two" == value, __FUNCTION__, "t_maphint.find(2)");
}

void test_binary() {
    _test_case.begin("binary");
    binary_t bin;
    uint16 ui16 = 1;
    ui16 = convert_endian(ui16);
    binary_load(bin, sizeof(uint32), (byte_t *)&ui16, sizeof(ui16));
    // 4 bytes long
    // 00000000 : 00 00 00 01 -- -- -- -- -- -- -- -- -- -- -- -- | ....
    _logger->dump(bin);

    return_t ret = errorcode_t::success;
    auto i1 = t_binary_to_integer<uint64>(bin, ret);
    _test_case.assert(errorcode_t::narrow_type == ret, __FUNCTION__, "binary_to_integer #narrow");
    auto i2 = t_binary_to_integer<uint32>(bin, ret);
    _test_case.assert(1 == i2, __FUNCTION__, "binary_to_integer #uint32");
    auto i3 = t_binary_to_integer2<uint64>(bin, ret);
    _test_case.assert(1 == i3, __FUNCTION__, "binary_to_integer #uint64");

    // narrow, truncate
    // 00000000 : 56 78 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | Vx
    binary_t bin1;
    binary_t bin2;
    uint32 ui32 = 0x12345678;
    t_binary_load<uint32>(bin1, sizeof(uint16), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint16), ui32, hton32);
    auto i4 = t_binary_to_integer<uint16>(bin1, ret);

    _logger->hdump("> binary_load (narrow)", bin1);
    _logger->hdump("> binary_append2 (narrow)", bin2);
    _test_case.assert(bin1 == base16_decode("0x5678"), __FUNCTION__, "binary_load (narrow)");
    _test_case.assert(bin2 == base16_decode("0x5678"), __FUNCTION__, "binary_append2 (narrow)");
    _test_case.assert(0x5678 == i4, __FUNCTION__, "binary_to_integer #0x%04x", i4);

    bin2.clear();

    // wide
    // 00000000 : 00 00 00 00 12 34 56 78 -- -- -- -- -- -- -- -- | .....4Vx
    t_binary_load<uint32>(bin1, sizeof(uint64), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint64), ui32, hton32);
    auto i5 = t_binary_to_integer<uint64>(bin1, ret);

    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == i5, __FUNCTION__, "binary_to_integer #0x%I64x", i5);

    bin2.clear();

    // wide
    // 00000000 : 00 00 00 00 00 00 00 00 00 00 00 00 12 34 56 78 | .............4Vx
    t_binary_load<uint32>(bin1, sizeof(uint128), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint128), ui32, hton32);
    auto i6 = t_binary_to_integer<uint128>(bin1, ret);
    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == i6, __FUNCTION__, "binary_to_integer #0x%I128x", i6);

    bin2.clear();
}

void test_loglevel() {
    _test_case.begin("logger");

    std::map<loglevel_t, std::string> table;
    table.insert({loglevel_trace, "trace"});
    table.insert({loglevel_debug, "debug"});
    table.insert({loglevel_info, "info"});
    table.insert({loglevel_warn, "warn"});
    table.insert({loglevel_error, "error"});
    table.insert({loglevel_fatal, "fatal"});
    table.insert({loglevel_notice, "notice"});

    std::list<loglevel_t> case1;
    std::list<loglevel_t> case2;
    case1.push_back(loglevel_trace);
    case2.push_back(loglevel_trace);
    case1.push_back(loglevel_debug);
    case2.push_back(loglevel_debug);
    case1.push_back(loglevel_info);
    case2.push_back(loglevel_info);
    case1.push_back(loglevel_warn);
    case2.push_back(loglevel_warn);
    case1.push_back(loglevel_error);
    case2.push_back(loglevel_error);
    case1.push_back(loglevel_fatal);
    case2.push_back(loglevel_fatal);
    case1.push_back(loglevel_notice);
    case2.push_back(loglevel_notice);

    auto dolog = [&](loglevel_t lvl, loglevel_t imp) -> void {
        _logger->set_loglevel(lvl).set_implicit_loglevel(imp);

        const std::string &lvlstr = table[lvl];
        const std::string &impstr = table[imp];
        std::string oper;
        if (lvl > imp) {
            oper = " > ";
        } else if (lvl == imp) {
            oper = " = ";
        } else {
            oper = " < ";
        }

        _logger->writeln(loglevel_notice, "level:%s %s implicit:%s", lvlstr.c_str(), oper.c_str(), impstr.c_str());
        _logger->writeln("> loglevel:implicit");
        _logger->writeln(loglevel_trace, "> loglevel:trace");
        _logger->writeln(loglevel_debug, "> loglevel:debug");
        _logger->writeln(loglevel_info, "> loglevel:info");
        _logger->writeln(loglevel_warn, "> loglevel:warn");
        _logger->writeln(loglevel_error, "> loglevel:error");
        _logger->writeln(loglevel_fatal, "> loglevel:fatal");
        _logger->writeln(loglevel_notice, "> loglevel:notice");
    };

    for (auto lvl : case1) {
        for (auto imp : case2) {
            dolog(lvl, imp);
        }
    }

    _logger->set_loglevel(loglevel_trace).set_implicit_loglevel(loglevel_trace);
}

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION &o, char *param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION &o, char *param) -> void { o.time = 1; }).optional()
              << t_cmdarg_t<OPTION>("-a", "attach", [](OPTION &o, char *param) -> void { o.attach = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.attach) {
        _test_case.attach(_logger);
    }

    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();
    test_convert_endian();
    test_byte_capacity_unsigned();
    test_byte_capacity_signed();
    test_maphint();
    test_binary();
    test_loglevel();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
