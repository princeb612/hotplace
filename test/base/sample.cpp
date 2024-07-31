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

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

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

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0).set_format("[Y-M-D h:m:s.f] ")
        //.set_logfile("log")
        ;
    _logger.make_share(builder.build());
    _test_case.attach(&*_logger);

    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();
    test_convert_endian();
    test_byte_capacity_unsigned();
    test_byte_capacity_signed();
    test_maphint();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
