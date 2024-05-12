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

void dump_data(const char *text, void *ptr, size_t size) {
    basic_stream bs;
    dump_memory((byte_t *)ptr, size, &bs, 16, 2);
    _logger->writeln("%s\n%s", text ? text : "", bs.c_str());
}

void test_convert_endian() {
    _test_case.begin("endian");

    uint64 i64 = t_htoi<uint64>("0001020304050607");
    uint128 i128 = t_htoi<uint128>("000102030405060708090a0b0c0d0e0f");

    if (is_little_endian()) {
        uint32 i32 = 7;
        _test_case.assert(ntoh32(i32) == convert_endian(i32), __FUNCTION__, "32bits");
        _test_case.assert(ntoh64(i64) == convert_endian(i64), __FUNCTION__, "64bits");
        _test_case.assert(ntoh128(i128) == convert_endian(i128), __FUNCTION__, "128bits");
    } else {
        // ntoh ... no effect
    }

#define do_convert_endian_test(type, val)        \
    {                                            \
        type var = val;                          \
        type temp = convert_endian(var);         \
        dump_data("before", &var, sizeof(var));  \
        dump_data("after", &temp, sizeof(temp)); \
    }

    do_convert_endian_test(uint32, 7);
    do_convert_endian_test(uint32, -2);
    do_convert_endian_test(uint64, 7);
    do_convert_endian_test(uint64, -2);
    do_convert_endian_test(uint128, 7);
    do_convert_endian_test(uint128, -2);
    do_convert_endian_test(uint64, i64);
    do_convert_endian_test(uint128, i128);
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

void test_maphint() {
    _test_case.begin("maphint");
    return_t ret = errorcode_t::success;

    std::map<int, std::string> source;
    maphint<int, std::string> hint(source);
    source[1] = "one";
    source[2] = "two";
    source[3] = "three";
    std::string value;
    hint.find(1, &value);
    _test_case.assert("one" == value, __FUNCTION__, "maphint.find(1)");
    ret = hint.find(10, &value);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "maphint.find(10)");

    maphint_const<int, std::string> hint_const(source);
    hint_const.find(2, &value);
    _test_case.assert("two" == value, __FUNCTION__, "maphint.find(2)");
}

void test_btree() {
    _test_case.begin("binary tree");
    // case.1
    {
        t_btree<int> bt;
        basic_stream bs;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        bs.printf("members in [ ");
        bt.for_each([&](int const &i) -> void { bs.printf("%d ", i); });
        bs.printf("]");
        _logger->writeln(bs);

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
        basic_stream bs;
        bt.insert("hello");
        bt.insert("world");
        bt.insert("t_btree");

        bs.printf("members in [ ");
        bt.for_each([&](const std::string &s) -> void { bs.printf("%s ", s.c_str()); });
        bs.printf("]");
        _logger->writeln(bs);

        _test_case.assert(3 == bt.size(), __FUNCTION__, "t_btree<std::string>");
    }
    // case.3~
    {
        struct basedata {
            uint32 key;
            std::string value;

            basedata(uint32 k, const std::string &v) : key(k), value(v) {}
            basedata(const basedata &rhs) : key(rhs.key), value(rhs.value) {}
        };
        // 1 2 3 ...
        struct testdata1 : basedata {
            testdata1(uint32 k, const std::string &v) : basedata(k, v) {}
            testdata1(const testdata1 &rhs) : basedata(rhs) {}

            bool operator<(const testdata1 &rhs) const {
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
            testdata2(uint32 k, const std::string &v) : basedata(k, v) {}
            testdata2(const testdata2 &rhs) : basedata(rhs) {}

            bool operator<(const testdata2 &rhs) const {
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
            basic_stream bs;
            bt.insert(testdata1(1, "one"));
            bt.insert(testdata1(2, "two"));
            bt.insert(testdata1(3, "three"));
            bt.insert(testdata1(4, "four"));
            bt.insert(testdata1(5, "five"));

            bs.printf("members in [ ");
            bt.for_each([&](const struct testdata1 &t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
            bs.printf("]");
            _logger->writeln(bs);

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #1");
        }
        // case.4
        {
            t_btree<struct testdata2> bt;
            basic_stream bs;
            bt.insert(testdata2(1, "one"));
            bt.insert(testdata2(2, "two"));
            bt.insert(testdata2(3, "three"));
            bt.insert(testdata2(4, "four"));
            bt.insert(testdata2(5, "five"));

            bs.printf("members in [ ");
            bt.for_each([&](const struct testdata2 &t) -> void { bs.printf("%u %s ", t.key, t.value.c_str()); });
            bs.printf("]");
            _logger->writeln(bs);

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #2");
        }
    }
    // case.5~
    {
        basic_stream bs;
        constexpr char sample[] = "still a man hears what he wants to hear and disregards the rest";

        struct testdata {
            byte_t symbol;
            size_t weight;

            testdata() : symbol(0), weight(0) {}
            testdata(byte_t b) : symbol(b), weight(0) {}
            testdata(const testdata &rhs) : symbol(rhs.symbol), weight(rhs.weight) {}

            // bool operator<(const testdata& rhs) const { return symbol < rhs.symbol;
            // }
        };

        // case.5
        {
            t_btree<testdata, t_type_comparator<testdata>> bt;
            for (auto b : sample) {
                if (b) {
                    bt.insert(testdata((byte_t)b), [](testdata &code) -> void { code.weight++; });
                }
            }
            _test_case.assert(15 == bt.size(), __FUNCTION__, "t_btree<structure, custom_compararor> insert and update");

            bs.printf("members in [\n");
            bt.for_each([&](const testdata &t) -> void { bs.printf("%c %02x %zi\n", isprint(t.symbol) ? t.symbol : '?', t.symbol, t.weight); });
            bs.printf("]");
            _logger->writeln(bs);
        }
    }
}

void test_avl_tree() {
    _test_case.begin("AVL tree");
    {
        t_avltree<int> bt;
        basic_stream bs;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        bs.printf("members in [ ");
        bt.for_each([&](int const &i) -> void { bs.printf("%d ", i); });
        bs.printf("]");
        _logger->writeln(bs);

        _test_case.assert(20 == bt.size(), __FUNCTION__, "t_avltree.insert");

        for (i = 0; i < 20; i++) {
            bt.remove(i);
        }
        _test_case.assert(0 == bt.size(), __FUNCTION__, "t_avltree.remove");
        _test_case.assert(true == bt.empty(), __FUNCTION__, "t_avltree.empty");
    }
}

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0).set_format("Y-M-D h:m:s.f ");
    _logger.make_share(builder.build());

    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();
    test_convert_endian();
    test_maphint();
    test_btree();
    test_avl_tree();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
