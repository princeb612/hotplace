/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      printf mbs/wcs
 *
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_IEEE754__
#define __HOTPLACE_SDK_BASE_BASIC_IEEE754__

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/callback.hpp>
#include <hotplace/sdk/base/basic/stream.hpp>
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
 *                               sign    exponent    fraction
 *          half precision       1           5           10
 *          single precision     1           8           23
 *          double precision     1          11           52
 *          quadruple            1          15          112
 *
 *                           10987654 32109876 54321098 76543210
 *          half precision                     seeeeeff fffffff
 *          single precision seeeeeee efffffff ffffffff fffffff
 *          ...
 *
 *                   FP16        FP32        FP64
 *            Inf    7c00        7f800000    7ff0000000000000
 *            NaN    7e00        7fc00000    7ff8000000000000
 *           -Inf    fc00        ff800000    fff0000000000000
 */

enum ieee754_t : uint64 // c++11
{
    /*
     * abbr.
     * pinf : positive infinity
     * nan  : Not a Number
     * qnan : quiet NaN
     * snan : signaling NaN
     * ninf : negative infinity
     */
    fp16_pinf   = 0x7c00,               // 0b0111110000000000
    fp16_nan    = 0x7e00,               // 0b0111111000000000
    fp16_qnan   = 0x7e01,               // 0b0111111000000001
    fp16_snan   = 0x7c01,               // 0b0111110000000001
    fp16_ninf   = 0xfc00,               // 0b1111110000000000
    fp32_pinf   = 0x7f800000,           // 0b0111111110000000000000000000000000000
    fp32_nan    = 0x7fc00000,           // 0b0111111111000000000000000000000000000
    fp32_qnan   = 0xffc00001,           // 0b0111111111000000000000000000000000001
    fp32_snan   = 0xff800001,           // 0b0111111110000000000000000000000000001
    fp32_ninf   = 0xff800000,           // 0b1111111110000000000000000000000000000
    fp64_pinf   = 0x7ff0000000000000,   // 0b0111111111110000000000000000000000000000000000000000000000000000
    fp64_nan    = 0x7ff8000000000000,   // 0b0111111111111000000000000000000000000000000000000000000000000000
    fp64_qnan   = 0x7ff8000000000001,   // 0b0111111111111000000000000000000000000000000000000000000000000001
    fp64_snan   = 0x7ff0000000000001,   // 0b0111111111110000000000000000000000000000000000000000000000000001
    fp64_ninf   = 0xfff0000000000000,   // 0b1111111111110000000000000000000000000000000000000000000000000000
};

typedef union _fp32_t {
    uint32 storage;
    float fp;
} fp32_t;

typedef union _fp64_t {
    uint64 storage;
    double fp;
} fp64_t;

static inline uint32 binary32_from_fp32 (float fp)
{
    fp32_t temp;

    temp.fp = fp;
    return temp.storage;
}
static inline uint64 binary64_from_fp64 (double fp)
{
    fp64_t temp;

    temp.fp = fp;
    return temp.storage;
}
static inline float fp32_from_binary32 (uint32 bin)
{
    fp32_t temp;

    temp.storage = bin;
    return temp.fp;
}
static inline double fp64_from_binary64 (uint64 bin)
{
    fp64_t temp;

    temp.storage = bin;
    return temp.fp;
}

/**
 * @brief   size as small as possible
 * @param   variant_t& vt [out]
 * @param   float fp [in]
 */
uint8 ieee754_format_as_small_as_possible (variant_t& vt, float fp);
uint8 ieee754_format_as_small_as_possible (variant_t& vt, double fp);

uint16 fp16_from_fp32 (float single);
/**
 * @from    Fast Half Float Conversions (http://www.fox-toolkit.org/ftp/fasthalffloatconversion.pdf)
 */
float fp32_from_fp16 (uint16 half);
/**
 * @brief   single precision to half precision
 * @desc    I'd probably try to figure it out on my own... but this is math.
 * @from    https://www.corsix.org/content/converting-fp32-to-fp16
 */
uint16 fp16_ieee_from_fp32_value (uint32 single);

}

#endif
