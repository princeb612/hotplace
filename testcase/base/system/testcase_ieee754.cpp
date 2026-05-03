/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_ieee754.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_typeof_ieee754() {
    _test_case.begin("ieee754");
    {
        struct {
            uint16 half;
            ieee754_typeof_t type;
        } _table[] = {
            {0x0000, ieee754_typeof_t::ieee754_zero},            // 0.000000
            {0x8000, ieee754_typeof_t::ieee754_zero},            // -0.000000
            {0x3c00, ieee754_typeof_t::ieee754_half_precision},  // 1.000000
            {fp16_pinf, ieee754_typeof_t::ieee754_pinf},         // inf
            {fp16_ninf, ieee754_typeof_t::ieee754_ninf},         // -inf
            {fp16_nan, ieee754_typeof_t::ieee754_nan},           // nan
            {fp16_qnan, ieee754_typeof_t::ieee754_nan},          // nan
            {fp16_snan, ieee754_typeof_t::ieee754_nan},          // nan
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
            {0.0, ieee754_typeof_t::ieee754_zero},                            // 0.000000
            {-0.0, ieee754_typeof_t::ieee754_zero},                           // -0.000000
            {1.0, ieee754_typeof_t::ieee754_single_precision},                // 1.000000
            {fp32_from_binary32(fp32_pinf), ieee754_typeof_t::ieee754_pinf},  // inf
            {fp32_from_binary32(fp32_ninf), ieee754_typeof_t::ieee754_ninf},  // -inf
            {fp32_from_binary32(fp32_nan), ieee754_typeof_t::ieee754_nan},    // nan
            {fp32_from_binary32(fp32_qnan), ieee754_typeof_t::ieee754_nan},   // nan
            {fp32_from_binary32(fp32_snan), ieee754_typeof_t::ieee754_nan},   // nan
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
            {0.0, ieee754_typeof_t::ieee754_zero},                            // 0.000000
            {-0.0, ieee754_typeof_t::ieee754_zero},                           // -0.000000
            {1.0, ieee754_typeof_t::ieee754_double_precision},                // 1.000000
            {fp64_from_binary64(fp64_pinf), ieee754_typeof_t::ieee754_pinf},  // inf
            {fp64_from_binary64(fp64_ninf), ieee754_typeof_t::ieee754_ninf},  // -inf
            {fp64_from_binary64(fp64_nan), ieee754_typeof_t::ieee754_nan},    // nan
            {fp64_from_binary64(fp64_qnan), ieee754_typeof_t::ieee754_nan},   // nan
            {fp64_from_binary64(fp64_snan), ieee754_typeof_t::ieee754_nan},   // nan
        };

        for (auto item : _table) {
            ieee754_typeof_t type = ieee754_typeof(item.d);
            _test_case.assert(type == item.type, __FUNCTION__, "%lf", item.d);
        }
    }
}

void test_frexp() {
    _test_case.begin("ieee754");
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

void test_float_printf() {
    _test_case.begin("ieee754");
    {
        struct testvector {
            float f;
            const char* print;
        } _table[] = {
            {0.0, "0.000000"},
            {-0.0, "-0.000000"},
            {fp32_from_binary32(fp32_pinf), "inf"},
            {fp32_from_binary32(fp32_ninf), "-inf"},
            {fp32_from_binary32(fp32_nan), "nan"},
            {fp32_from_binary32(fp32_qnan), "nan"},
            {fp32_from_binary32(fp32_snan), "nan"},
        };

        for (const auto& item : _table) {
            basic_stream bs;
            bs.printf("%f", item.f);
            _logger->writeln(bs);
            _test_case.assert(bs == item.print, __FUNCTION__, "float %f", item.f);
        }
    }
    {
        struct testvector {
            double f;
            const char* print;
        } _table[] = {
            {0.0, "0.000000"},
            {-0.0, "-0.000000"},
            {fp64_from_binary64(fp64_pinf), "inf"},
            {fp64_from_binary64(fp64_ninf), "-inf"},
            {fp64_from_binary64(fp64_nan), "nan"},
            {fp64_from_binary64(fp64_qnan), "nan"},
            {fp64_from_binary64(fp64_snan), "nan"},
        };

        for (const auto& item : _table) {
            basic_stream bs;
            bs.printf("%lf", item.f);
            _logger->writeln(bs);
            _test_case.assert(bs == item.print, __FUNCTION__, "double %lf", item.f);
        }
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
        {variant(-0.00006103515625), 0x8400, -0.000061},   // double
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
            default:
                break;
        }
        float f = float_from_fp16(item.fp16);
        double d = double_from_fp16(item.fp16);
        item.var.to_string(tostr);
        item.var.to_binary(bin, variant_convendian);
        _logger->writeln(tostr);
        _logger->dump(bin);
        bool expect = (var.content().data.ui16 == item.fp16);
        _test_case.assert(expect, __FUNCTION__, "ieee754_as_small_as_possible [len %u] %s fp16 %04x fp32 %f fp64 %lf", len, tostr.c_str(), item.fp16, f, d);
    }
}

// https://baseconvert.com/ieee-754-floating-point
void test_ieee754_conversion() {
    _test_case.begin("ieee754");
    struct testvector_fpconv {
        const char* text;
        uint16 fp16;
        uint32 fp32;
        uint64 fp64;
        bool loss;
    } table[] = {
        {"0.0", 0x0000, 0x00000000, 0x0000000000000000, false},
        {"0.00006103515625", 0x0400, 0x38800000, 0x3f10000000000000, false},
        {"1.0", 0x3c00, 0x3f800000, 0x3ff0000000000000, false},
        {"1.5", 0x3e00, 0x3fc00000, 0x3ff8000000000000, false},
        {"2.0", 0x4000, 0x40000000, 0x4000000000000000, false},
        {"4.0", 0x4400, 0x40800000, 0x4010000000000000, false},
        {"32.625", 0x5014, 0x42028000, 0x4040500000000000, false},
        {"65504.0", 0x7bff, 0x477fe000, 0x40effc0000000000, false},

        {"-0.0", 0x8000, 0x80000000, 0x8000000000000000, false},
        {"-0.00006103515625", 0x8400, 0xb8800000, 0xbf10000000000000, false},
        {"-1.0", 0xbc00, 0xbf800000, 0xbff0000000000000, false},
        {"-1.5", 0xbe00, 0xbfc00000, 0xbff8000000000000, false},
        {"-2.0", 0xc000, 0xc0000000, 0xc000000000000000, false},
        {"-4.0", 0xc400, 0xc0800000, 0xc010000000000000, false},
        {"-32.625", 0xd014, 0xc2028000, 0xc040500000000000, false},
        {"-65504.0", 0xfbff, 0xc77fe000, 0xc0effc0000000000, false},

        {"inf", 0x7c00, 0x7f800000, 0x7ff0000000000000, false},
        {"nan", 0x7e00, 0x7fc00000, 0x7ff8000000000000, false},

        {"3.4028234663852886e+38", 0x7c00, 0x7f7fffff, 0x47efffffe0000000, true},  // NaN
        {"1.0e+300", 0x7c00, 0x7f800000, 0x7e37e43c8800759c, true},                // NaN
        {"100000.0", 0x7c00, 0x47c35000, 0x40f86a0000000000, true},                // NaN

        {"5.960464477539063e-8", 0x0001, 0x33800000, 0x3e70000000000000, true},
        {"-5.960464477539063e-8", 0x8001, 0xb3800000, 0xbe70000000000000, true},
        {"0.3333333333333333", 0x3555, 0x3eaaaaab, 0x3fd5555555555555, true},
        {"-0.3333333333333333", 0xb555, 0xbeaaaaab, 0xbfd5555555555555, true},
        {"4.1", 0x441a, 0x40833333, 0x4010666666666666, true},
        {"-4.1", 0xc41a, 0xc0833333, 0xc010666666666666, true},
    };

    for (auto item : table) {
        float f = fp32_from_binary32(item.fp32);
        double d = fp64_from_binary64(item.fp64);
        _logger->writeln("single precision %f %g double precision %lf %lg", f, f, d, d);

        {
            uint16 fp16 = fp16_from_fp32(item.fp32);
            _test_case.assert(fp16 == item.fp16, __FUNCTION__, "fp32 to fp16 %s", item.text);
            uint32 fp32 = binary32_from_fp32(fp64_from_binary64(item.fp64));  // (float)double
            _test_case.assert(fp32 == item.fp32, __FUNCTION__, "fp32 to fp16 %s", item.text);
        }

        {
            variant vt;
            uint8 l = 0;
            double d = fp64_from_binary64(item.fp64);
            l = ieee754_as_small_as_possible(vt, d);
            if (8 == l) {
            } else if (4 == l) {
                _test_case.assert(vt.get().data.ui32 == item.fp32, __FUNCTION__, "fp64 to fp32 %s", item.text);
            } else if (2 == l) {
                _test_case.assert(vt.get().data.ui16 == item.fp16, __FUNCTION__, "fp64 to fp16 %s", item.text);
            }
        }

        if (false == item.loss) {
            uint32 fp32 = binary32_from_fp32(float_from_fp16(item.fp16));
            uint64 fp64 = binary64_from_fp64(double_from_fp16(item.fp16));
            f = fp32_from_binary32(fp32);
            d = fp64_from_binary64(fp64);
            _logger->writeln("fp16 to single precision %f %g double precision %lf %lg", f, f, d, d);
            _test_case.assert(fp32 == item.fp32, __FUNCTION__, "fp16 to fp32 %s", item.text);
            _test_case.assert(fp64 == item.fp64, __FUNCTION__, "fp16 to fp64 %s", item.text);
        }
    }
}

void testcase_ieee754() {
    test_typeof_ieee754();
    test_frexp();
    test_float_printf();
    test_as_small_as_possible();
    test_ieee754_conversion();
}
