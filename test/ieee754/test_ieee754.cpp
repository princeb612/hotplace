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

void test_ieee754() {
    _test_case.begin("ieee754_typeof");

    {
        struct {
            uint16 half;
            ieee754_typeof_t type;
        } _table[] = {
            {0x0000, ieee754_typeof_t::ieee754_zero},    {0x8000, ieee754_typeof_t::ieee754_zero},    {0x3c00, ieee754_typeof_t::ieee754_half_precision},
            {fp16_pinf, ieee754_typeof_t::ieee754_pinf}, {fp16_ninf, ieee754_typeof_t::ieee754_ninf}, {fp16_nan, ieee754_typeof_t::ieee754_nan},
            {fp16_qnan, ieee754_typeof_t::ieee754_nan},  {fp16_snan, ieee754_typeof_t::ieee754_nan},
        };

        for (auto item : _table) {
            ieee754_typeof_t type = ieee754_typeof(item.half);
            _test_case.assert(type == item.type, __FUNCTION__, "%f", float_from_fp16(item.half));
        }
    }
    {
        struct {
            float f;
            ieee754_typeof_t type;
        } _table[] = {
            {0.0, ieee754_typeof_t::ieee754_zero},
            {-0.0, ieee754_typeof_t::ieee754_zero},
            {1.0, ieee754_typeof_t::ieee754_single_precision},
            {fp32_from_binary32(fp32_pinf), ieee754_typeof_t::ieee754_pinf},
            {fp32_from_binary32(fp32_ninf), ieee754_typeof_t::ieee754_ninf},
            {fp32_from_binary32(fp32_nan), ieee754_typeof_t::ieee754_nan},
            {fp32_from_binary32(fp32_qnan), ieee754_typeof_t::ieee754_nan},
            {fp32_from_binary32(fp32_snan), ieee754_typeof_t::ieee754_nan},
        };

        for (auto item : _table) {
            ieee754_typeof_t type = ieee754_typeof(item.f);
            _test_case.assert(type == item.type, __FUNCTION__, "%f", item.f);
        }
    }
    {
        struct {
            double d;
            ieee754_typeof_t type;
        } _table[] = {
            {0.0, ieee754_typeof_t::ieee754_zero},
            {-0.0, ieee754_typeof_t::ieee754_zero},
            {1.0, ieee754_typeof_t::ieee754_double_precision},
            {fp64_from_binary64(fp64_pinf), ieee754_typeof_t::ieee754_pinf},
            {fp64_from_binary64(fp64_ninf), ieee754_typeof_t::ieee754_ninf},
            {fp64_from_binary64(fp64_nan), ieee754_typeof_t::ieee754_nan},
            {fp64_from_binary64(fp64_qnan), ieee754_typeof_t::ieee754_nan},
            {fp64_from_binary64(fp64_snan), ieee754_typeof_t::ieee754_nan},
        };

        for (auto item : _table) {
            ieee754_typeof_t type = ieee754_typeof(item.d);
            _test_case.assert(type == item.type, __FUNCTION__, "%lf", item.d);
        }
    }
}

void test_frexp() {
    _test_case.begin("frexp vs. ieee754_exp");
    float ftable[] = {0.0, 1.0, -1.0, 1.5, -1.5, 2.0, -2.0, 4.0, -4.0, 0.00006103515625, -0.00006103515625};
    for (auto item : ftable) {
        int s1 = 0;
        int s2 = 0;
        int e1 = 0;
        int e2 = 0;
        float m1 = 0;
        float m2 = 0;
        s1 = (item < 0) ? 1 : 0;
        m1 = frexp(item, &e1);
        ieee754_exp(item, &s2, &e2, &m2);
        bool test = (s1 == s2) && (e1 == e2) && (m1 == m2);
        _test_case.assert(test, __FUNCTION__, "frexp %f sign %i exponent %i mantissa %f", item, s2, e2, m2);
    }
    double dtable[] = {0.0, 1.0, -1.0, 1.5, -1.5, 2.0, -2.0, 4.0, -4.0, 0.00006103515625, -0.00006103515625};
    for (auto item : dtable) {
        int s1 = 0;
        int s2 = 0;
        int e1 = 0;
        int e2 = 0;
        double m1 = 0;
        double m2 = 0;
        s1 = (item < 0) ? 1 : 0;
        m1 = frexp(item, &e1);
        ieee754_exp(item, &s2, &e2, &m2);
        bool test = (s1 == s2) && (e1 == e2) && (m1 == m2);
        _test_case.assert(test, __FUNCTION__, "frexp %lf sign %i exponent %i mantissa %lf", item, s2, e2, m2);
    }
}

void test_basic_stream() {
    _test_case.begin("basic_stream");
    basic_stream bs;

    {
        struct testvector {
            float f;
            basic_stream bs;
        } _table[] = {
            {0.0, "0.000000"},
            {-0.0, "-0.000000"},
            {fp32_from_binary32(fp32_pinf), "inf"},
            {fp32_from_binary32(fp32_ninf), "-inf"},
            {fp32_from_binary32(fp32_nan), "nan"},
            {fp32_from_binary32(fp32_qnan), "nan"},
            {fp32_from_binary32(fp32_snan), "nan"},
        };

        for (auto item : _table) {
            bs.printf("%f", item.f);
            _logger->writeln(bs);
            _test_case.assert(item.bs == bs, __FUNCTION__, "float %s", item.bs.c_str());
            bs.clear();
        }
    }
    {
        struct testvector {
            double f;
            basic_stream bs;
        } _table[] = {
            {0.0, "0.000000"},
            {-0.0, "-0.000000"},
            {fp64_from_binary64(fp64_pinf), "inf"},
            {fp64_from_binary64(fp64_ninf), "-inf"},
            {fp64_from_binary64(fp64_nan), "nan"},
            {fp64_from_binary64(fp64_qnan), "nan"},
            {fp64_from_binary64(fp64_snan), "nan"},
        };

        for (auto item : _table) {
            bs.printf("%lf", item.f);
            _logger->writeln(bs);
            _test_case.assert(item.bs == bs, __FUNCTION__, "double %s", item.bs.c_str());
            bs.clear();
        }
    }
}

void test_as_small_as_possible() {
    _test_case.begin("ieee754_as_small_as_possible");
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
        item.var.to_binary(bin, variant_convendian);
        _logger->writeln(tostr);
        _logger->dump(bin);
        bool expect = (var.content().data.ui16 == item.fp16);
        _test_case.assert(expect, __FUNCTION__, "ieee754_as_small_as_possible %s fp16 %04x fp32 %f fp64 %lf", tostr.c_str(), item.fp16, f, d);
    }
}
