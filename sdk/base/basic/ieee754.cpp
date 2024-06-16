/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.12   Soo Han, Kim        CBOR (codename.hotplace)
 */

#include <sdk/base/basic/ieee754.hpp>

namespace hotplace {

/**
 * @brief   IEEE754
 * @desc
 *                           sign    exponent    fraction
 *      half precision       1           5           10
 *      single precision     1           8           23
 *      double precision     1          11           52
 *      quadruple            1          15          112
 *
 *      Single Precision
 *          Positive Infinity: 7F800000
 *          Negative Infinity: FF800000
 *          Signaling NaN: 7F8000001~ 7FBFFFFF or FF800001 ~ FFBFFFFF
 *          Quiet NaN: 7FC00000 ~ 7FFFFFFF or FFC00000 ~ FFFFFFFF
 *
 *      Double Precision
 *          Positive Infinity: 7FF0000000000000
 *          Negative Infinity: FFF0000000000000
 *          Signaling NaN: 7FF0000000000001 ~ 7FF7FFFFFFFFFFFF or FFF0000000000001 ~ FFF7FFFFFFFFFFFF
 *          Quiet NaN: 7FF8000000000000 ~ 7FFFFFFFFFFFFFFF or FFF8000000000000 ~ FFFFFFFFFFFFFFFF
 *
 *      ieee754_as_small_as_possible
 *          return size of floating point (2 half, 4 single, 8 double)
 *      fp16_from_fp32, fp32_from_fp16
 *          convert single precision floating point to half one and vice versa
 *      fp16_ieee_from_fp32_value
 *          do not call directly
 *          see ieee754_as_small_as_possible
 */
uint8 ieee754_as_small_as_possible(variant& vt, float fp) {
    uint8 ret = 4;
    fp32_t fp32;

    vt.set_fp32(fp);
    fp32.fp = fp;
    if ((0 == (0x3ff & fp32.storage)) && (0x7f800000 != (0x7f800000 & fp32.storage))) {
        uint16 bin16 = fp16_ieee_from_fp32_value(fp32.storage);
        if (0x7c00 != (0x7c00 & bin16)) {
            vt.set_fp16(bin16);
            ret = 2;
        }
    }
    return ret;
}

uint8 ieee754_as_small_as_possible(variant& vt, double fp) {
    uint8 ret = 8;
    fp64_t fp64;

    vt.set_fp64(fp);
    fp64.fp = fp;
    bool cond1 = (0 == (0x7fffff & fp64.storage));
    bool cond2 = (0x7ff0000000000000 == (0x7ff0000000000000 & fp64.storage));
    if (cond1 && !cond2) {
        fp32_t fp32;
        fp32.fp = fp;
        if (0x7f800000 != (0x7f800000 & fp32.storage)) {
            // variant_set_float (fp32.fp);
            // ret = 4;
            ret = ieee754_as_small_as_possible(vt, fp32.fp);
        }
    }
    return ret;
}

uint16 fp16_from_fp32(float single) {
    fp32_t fp32;

    fp32.fp = single;
    return fp16_ieee_from_fp32_value(fp32.storage);
}

/**
 * @from    Fast Half Float Conversions (http://www.fox-toolkit.org/ftp/fasthalffloatconversion.pdf)
 */
float fp32_from_fp16(uint16 h) {
    uint32 bin32 = ((h & 0x8000) << 16) | (((h & 0x7c00) + 0x1C000) << 13) | ((h & 0x03FF) << 13);
    fp32_t fp32;

    fp32.storage = bin32;
    return fp32.fp;
}

/**
 * @brief   single precision to half precision
 * @refer   https://www.corsix.org/content/converting-fp32-to-fp16
 */
uint16 fp16_ieee_from_fp32_value(uint32 x) {
    uint32 x_sgn = x & 0x80000000u;
    uint32 x_exp = x & 0x7f800000u;

    x_exp = (x_exp < 0x38800000u) ? 0x38800000u : x_exp;  // max(e, -14)
    x_exp += 15u << 23;                                   // e += 15
    x &= 0x7fffffffu;                                     // Discard sign

    fp32_t f;
    fp32_t magic;
    f.storage = x;
    magic.storage = x_exp;

    // If 15 < e then inf, otherwise e += 2
    // f.fp = (f.fp * 0x1.0p+112f) * 0x1.0p-110f;
    f.fp = (f.fp * fp32_from_binary32(0x77800000)) * fp32_from_binary32(0x08800000);

    // If we were in the x_exp >= 0x38800000u case:
    // Replace f's exponent with that of x_exp, and discard 13 bits of
    // f's significand, leaving the remaining bits in the low bits of
    // f, relying on FP addition being round-to-nearest-even. If f's
    // significand was previously `a.bcdefghijk`, then it'll become
    // `1.000000000000abcdefghijk`, from which `bcdefghijk` will become
    // the FP16 mantissa, and `a` will add onto the exponent. Note that
    // rounding might add one to all this.
    // If we were in the x_exp < 0x38800000u case:
    // Replace f's exponent with the minimum FP16 exponent, discarding
    // however many bits are required to make that happen, leaving
    // whatever is left in the low bits.
    f.fp += magic.fp;

    uint32 h_exp = (f.storage >> 13) & 0x7c00u;   // low 5 bits of exponent
    uint32 h_sig = f.storage & 0x0fffu;           // low 12 bits (10 are mantissa)
    h_sig = (x > 0x7f800000u) ? 0x0200u : h_sig;  // any NaN -> qNaN
    return (x_sgn >> 16) + h_exp + h_sig;
}

ieee754_typeof_t is_typeof(float f) {
    ieee754_typeof_t ret = ieee754_typeof_t::ieee754_single_precision;
    uint32 b32 = binary32_from_fp32(f);
    if (b32 & ~0x80000000) {
        if (ieee754_t::fp32_pinf == (b32 & ieee754_t::fp32_pinf)) {
            if (b32 & 0x80000000) {
                ret = ieee754_typeof_t::ieee754_ninf;
            } else if (b32 & ~fp32_ninf) {
                ret = ieee754_typeof_t::ieee754_nan;
            } else {
                ret = ieee754_typeof_t::ieee754_pinf;
            }
        }
    } else {
        ret = ieee754_typeof_t::ieee754_zero;
    }
    return ret;
}

ieee754_typeof_t is_typeof(double d) {
    ieee754_typeof_t ret = ieee754_typeof_t::ieee754_double_precision;
    uint64 b64 = binary64_from_fp64(d);
    if (b64 & ~0x8000000000000000) {
        if (ieee754_t::fp64_pinf == (b64 & ieee754_t::fp64_pinf)) {
            uint32 b32 = (b64 >> 32);
            if (b32 & 0x80000000) {
                ret = ieee754_typeof_t::ieee754_ninf;
            } else if (b32 & 0x000fffff) {
                ret = ieee754_typeof_t::ieee754_nan;
            } else {
                ret = ieee754_typeof_t::ieee754_pinf;
            }
        }
    } else {
        ret = ieee754_typeof_t::ieee754_zero;
    }
    return ret;
}

// to unserstand IEEE754
ieee754_typeof_t ieee754_exp(float value, int* s, int* e, float* m) {
    ieee754_typeof_t type = is_typeof(value);

    uint32 b32 = binary32_from_fp32(value);
    int sign = (b32 >> 31);
    int bias = (1 << 7) - 1;
    int exponent = 0;
    float mantissa = 0.0;
    uint32 bias_m1 = bias - 1;

    switch (type) {
        case ieee754_zero:
            break;
        case ieee754_pinf:
            mantissa = fp32_from_binary32(fp32_pinf);
            break;
        case ieee754_ninf:
            mantissa = fp32_from_binary32(fp32_ninf);
            break;
        case ieee754_nan:
            mantissa = fp32_from_binary32(fp32_nan);
            break;
        default:
            exponent = ((b32 >> 23) & 0x000000ff) - bias_m1;
            mantissa = fp32_from_binary32((b32 & 0x807fffff) | (bias_m1 << 23));
            break;
    }
    if (s) {
        *s = sign;
    }
    if (e) {
        *e = exponent;
    }
    if (m) {
        *m = mantissa;
    }

    return type;
}

// to unserstand IEEE754
ieee754_typeof_t ieee754_exp(double value, int* s, int* e, double* m) {
    ieee754_typeof_t type = is_typeof(value);

    uint64 b64 = binary64_from_fp64(value);
    int sign = (b64 >> 63);
    int bias = (1 << 10) - 1;
    int exponent = 0;
    double mantissa = 0.0;
    uint64 bias_m1 = bias - 1;

    switch (type) {
        case ieee754_zero:
            break;
        case ieee754_pinf:
            mantissa = fp64_from_binary64(fp64_pinf);
            break;
        case ieee754_ninf:
            mantissa = fp64_from_binary64(fp64_ninf);
            break;
        case ieee754_nan:
            mantissa = fp64_from_binary64(fp64_nan);
            break;
        default:
            exponent = ((b64 >> 52) & 0x000007ff) - bias_m1;
            mantissa = fp64_from_binary64((b64 & 0x800fffffffffffff) | (bias_m1 << 52));
            break;
    }
    if (s) {
        *s = sign;
    }
    if (e) {
        *e = exponent;
    }
    if (m) {
        *m = mantissa;
    }

    return type;
}

}  // namespace hotplace
