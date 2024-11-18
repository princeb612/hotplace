/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  The IEEE Standard for Floating-Point Arithmetic (IEEE 754)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_IEEE754__
#define __HOTPLACE_SDK_BASE_BASIC_IEEE754__

#include <sdk/base/basic/types.hpp>
#include <sdk/base/basic/variant.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   convert single precision floating point to half precision one and vice versa
 * @desc
 *          The IEEE Standard for Floating-Point Arithmetic (IEEE 754)
 *          https://en.wikipedia.org/wiki/IEEE_754
 *          https://en.wikipedia.org/wiki/Floating-point_arithmetic
 *          https://en.wikipedia.org/wiki/Half-precision_floating-point_format
 *          https://en.wikipedia.org/wiki/Single-precision_floating-point_format
 *          https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
 *          https://www.cl.cam.ac.uk/teaching/1011/FPComp/fpcomp10slides.pdf
 *          https://www.youtube.com/watch?v=8afbTaA-gOQ
 *          https://www.corsix.org/content/converting-fp32-to-fp16
 *          https://blog.fpmurphy.com/2008/12/half-precision-floating-point-format_14.html
 *
 *          online converter
 *          https://www.h-schmidt.net/FloatConverter/IEEE754.html
 *          https://baseconvert.com/ieee-754-floating-point
 *          https://www.omnicalculator.com/other/floating-point
 `
 *                              bits  sign    exponent    fraction(mantissa)
 *          half precision      16    1           5           10
 *          single precision    32    1           8           23
 *          double precision    64    1          11           52
 *          quadruple           128   1          15          112
 *          octuple             256   1          19          236
 *
 *          bias-ed representation
 *              n = no of exponent bits
 *              bias = 2^(n-1) - 1
 *
 *          understanding conversion
 *              single-precision 1 10000100 00000101000000000000000
 *              S(1)  : (-1)^1 = -1
 *              E(8)  : 2^7+2^2 = 128 + 4
 *                      exponent = 132 - bias(127) = 5
 *              M(23) : 1.00000101_2
 *              -1 * 1.00000101_2 * 2^5 = -1 * 100000.101_2 = -32 + ((2^-1)*1) + ((2^-2)*0) + ((2^-3)*1) = -32.625
 *
 *              convert to double-precision
 *              -32.625 = -1 * 32.625 = -1 * 2^5 + (((2^-1)*1) + ((2^-2)*0) + ((2^-3)*1))
 *                                    = -1 * 100000.101 = -1 * 1.00000101 * 2^5
 *              S(1) = (-1)^1
 *              E(11) = 5 + bias = 1024 + 4 = 10000000100
 *              M(52) = 0000010100000000000000000000000000000000000000000000
 *              1 10000000100 0000010100000000000000000000000000000000000000000000
 *
 *
 *                           10987654 32109876 54321098 76543210
 *          half precision                     seeeeeff ffffffff
 *          single precision seeeeeee efffffff ffffffff ffffffff
 *          ...
 *
 *                   FP16        FP32        FP64
 *            Inf    7c00        7f800000    7ff0000000000000
 *            NaN    7e00        7fc00000    7ff8000000000000
 *           -Inf    fc00        ff800000    fff0000000000000
 */

enum ieee754_t : uint64  // c++11
{
    /*
     * abbr.
     * pinf : positive infinity
     * nan  : Not a Number
     * qnan : quiet NaN
     * snan : signaling NaN
     * ninf : negative infinity
     */
    fp16_pinf = 0x7c00,              // 0111110000000000
    fp16_nan = 0x7e00,               // 0111111000000000
    fp16_qnan = 0x7e01,              // 0111111000000001
    fp16_snan = 0x7c01,              // 0111110000000001
    fp16_ninf = 0xfc00,              // 1111110000000000
    fp32_pinf = 0x7f800000,          // 0111111110000000000000000000000000000
    fp32_nan = 0x7fc00000,           // 0111111111000000000000000000000000000
    fp32_qnan = 0x7fc00001,          // 0111111111000000000000000000000000001
    fp32_snan = 0x7f800001,          // 0111111110000000000000000000000000001
    fp32_ninf = 0xff800000,          // 1111111110000000000000000000000000000
    fp64_pinf = 0x7ff0000000000000,  // 0111111111110000000000000000000000000000000000000000000000000000
    fp64_nan = 0x7ff8000000000000,   // 0111111111111000000000000000000000000000000000000000000000000000
    fp64_qnan = 0x7ff8000000000001,  // 0111111111111000000000000000000000000000000000000000000000000001
    fp64_snan = 0x7ff0000000000001,  // 0111111111110000000000000000000000000000000000000000000000000001
    fp64_ninf = 0xfff0000000000000,  // 1111111111110000000000000000000000000000000000000000000000000000
};

typedef union _fp16_t {
    uint16 storage;
} fp16_t;

typedef union _fp32_t {
    uint32 storage;
    float fp;
} fp32_t;

typedef union _fp64_t {
    uint64 storage;
    double fp;
} fp64_t;

static inline uint32 binary32_from_fp32(float fp) {
    fp32_t temp;

    temp.fp = fp;
    return temp.storage;
}
static inline uint64 binary64_from_fp64(double fp) {
    fp64_t temp;

    temp.fp = fp;
    return temp.storage;
}
static inline float fp32_from_binary32(uint32 bin) {
    fp32_t temp;

    temp.storage = bin;
    return temp.fp;
}
static inline double fp64_from_binary64(uint64 bin) {
    fp64_t temp;

    temp.storage = bin;
    return temp.fp;
}

/**
 * @brief   size as small as possible
 * @param   variant& vt [out]
 * @param   float fp [in]
 */
uint8 ieee754_as_small_as_possible(variant& vt, float fp);
uint8 ieee754_as_small_as_possible(variant& vt, double fp);

uint16 fp16_from_float(float single);
/**
 * @brief    Fast Half Float Conversions
 * @refer   http://www.fox-toolkit.org/ftp/fasthalffloatconversion.pdf
 */
float float_from_fp16(uint16 half);
double double_from_fp16(uint16 half);

/**
 * @brief   single precision to half precision
 * @refer   https://www.corsix.org/content/converting-fp32-to-fp16
 */
uint16 fp16_from_fp32(uint32 single);

enum ieee754_typeof_t {
    ieee754_finite = 0,
    ieee754_pinf,
    ieee754_ninf,
    ieee754_nan,
    ieee754_zero,
    ieee754_half_precision,
    ieee754_single_precision,
    ieee754_double_precision,
    ieee754_quadruple_precision,
};
ieee754_typeof_t ieee754_typeof(uint16 f);
ieee754_typeof_t ieee754_typeof(float f);
ieee754_typeof_t ieee754_typeof(double d);
// understanding frexpf, frexp
ieee754_typeof_t ieee754_exp(uint16 value, int* s, int* e, uint* m);
ieee754_typeof_t ieee754_exp(float value, int* s, int* e, float* m);
ieee754_typeof_t ieee754_exp(double value, int* s, int* e, double* m);

}  // namespace hotplace

#endif
