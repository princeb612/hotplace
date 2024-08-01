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

void test_ieee754() {
    _test_case.begin("ieee754");

    ieee754_typeof_t type = ieee754_typeof_t::ieee754_finite;

    type = ieee754_typeof(0.0);
    _test_case.assert(ieee754_typeof_t::ieee754_zero == type, __FUNCTION__, "zero");

    type = ieee754_typeof(-0.0);
    _test_case.assert(ieee754_typeof_t::ieee754_zero == type, __FUNCTION__, "zero");

    type = ieee754_typeof(fp32_from_binary32(fp32_pinf));
    _test_case.assert(ieee754_typeof_t::ieee754_pinf == type, __FUNCTION__, "inf");

    type = ieee754_typeof(fp32_from_binary32(fp32_ninf));
    _test_case.assert(ieee754_typeof_t::ieee754_ninf == type, __FUNCTION__, "-inf");

    type = ieee754_typeof(fp32_from_binary32(fp32_nan));
    _test_case.assert(ieee754_typeof_t::ieee754_nan == type, __FUNCTION__, "nan");

    type = ieee754_typeof(fp64_from_binary64(fp64_pinf));
    _test_case.assert(ieee754_typeof_t::ieee754_pinf == type, __FUNCTION__, "inf");

    type = ieee754_typeof(fp64_from_binary64(fp64_ninf));
    _test_case.assert(ieee754_typeof_t::ieee754_ninf == type, __FUNCTION__, "-inf");

    type = ieee754_typeof(fp64_from_binary64(fp64_nan));
    _test_case.assert(ieee754_typeof_t::ieee754_nan == type, __FUNCTION__, "nan");
}

void test_basic_stream() {
    _test_case.begin("ieee754");
    basic_stream bs;

    bs.printf("%f", -0.0f);
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("-0.000000") == bs, __FUNCTION__, "-0.0");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp32_from_binary32(fp32_pinf));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("inf") == bs, __FUNCTION__, "inf");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp32_from_binary32(fp32_ninf));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("-inf") == bs, __FUNCTION__, "-inf");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp32_from_binary32(fp32_nan));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("nan") == bs, __FUNCTION__, "nan");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp64_from_binary64(fp64_pinf));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("inf") == bs, __FUNCTION__, "inf");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp64_from_binary64(fp64_ninf));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("-inf") == bs, __FUNCTION__, "-inf");
        _logger->writeln(bs);
        bs.clear();
    }

    bs.printf("%f", fp64_from_binary64(fp64_nan));
    {
        test_case_notimecheck notimecheck(_test_case);
        _test_case.assert(basic_stream("nan") == bs, __FUNCTION__, "nan");
        _logger->writeln(bs);
        bs.clear();
    }
}

void test_as_small_as_possible() {
    _test_case.begin("ieee754");
    // ieee754_as_small_as_possible
    // RFC 7049 Concise Binary Object Representation (CBOR)
    // RFC 8949 Concise Binary Object Representation (CBOR)

    struct testvector {
        variant var;
        uint16 fp16;
        float f;
    } _table[] = {
        {variant(0.0f), 0x0000, 0.0},
        {variant(-0.0f), 0x8000, -0.0},
        {variant(1.0f), 0x3c00, 1.0},
        {variant(-1.0f), 0xbc00, -1.0},
        {variant(1.5f), 0x3e00, 1.5},
        {variant(-1.5f), 0xbe00, -1.5},
        {variant(2.0f), 0x4000, 2.0},
        {variant(-2.0f), 0xc000, -2.0},
        {variant(4.0f), 0x4400, 4.0},
        {variant(0.00006103515625f), 0x0400, 0.000061},    // float
        {variant(-0.00006103515625f), 0x8400, -0.000061},  // float
        {variant(0.00006103515625), 0x0400, 0.000061},     // double
        {variant(0.00006103515625), 0x0400, 0.000061},     // double
        {variant(5.960464477539063e-8), 0001, 0.000000},   // 0.000000059604644775390625
    };

    for (auto item : _table) {
        variant var;
        std::string tostr;
        binary_t bin;
        uint8 len = 0;

        switch (item.var.type()) {
            case TYPE_FLOAT:
                len = ieee754_as_small_as_possible(var, item.var.content().data.f);
                break;
            case TYPE_DOUBLE:
                len = ieee754_as_small_as_possible(var, item.var.content().data.d);
                break;
        }
        float f = float_from_fp16(item.fp16);
        double d = double_from_fp16(item.fp16);
        item.var.to_string(tostr);
        item.var.dump(bin, true);
        _logger->writeln(tostr);
        _logger->dump(bin);
        bool expect = (var.content().data.ui16 == item.fp16);
        _test_case.assert(expect, __FUNCTION__, "ieee754_as_small_as_possible %s fp16 %04x fp32 %f fp64 %lf", tostr.c_str(), item.fp16, f, d);
    }
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
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test_ieee754();
    test_basic_stream();
    test_as_small_as_possible();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
