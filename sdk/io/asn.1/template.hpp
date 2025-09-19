/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_TEMPLATE__
#define __HOTPLACE_SDK_IO_ASN1_TEMPLATE__

#include <math.h>

#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/base/inline.hpp>
#include <hotplace/sdk/base/template.hpp>
#include <hotplace/sdk/io/asn.1/asn1.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>
#include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   length octets
 * @sa
 *          X.690 8.1.3 Length octets
 */
template <typename type>
uint32 t_asn1_length_octets(binary_t& bin, type len, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }

    uint32 size_encode = 0;
    if (len > 0x7f) {
        int bytesize = byte_capacity(len);
        type temp = convert_endian(len);
        bin.insert(bin.begin() + pos, 0x80 | bytesize);  // X.690 8.1.3.5
        bin.insert(bin.begin() + pos + 1, (byte_t*)&temp + sizeof(type) - bytesize, (byte_t*)&temp + sizeof(type));
        size_encode = 1 + bytesize;
    } else {
        // X.690 8.1.3.4
        bin.insert(bin.begin() + pos, (byte_t)len);
        size_encode = 1;
    }
    return size_encode;
}

// X.690 8.19.2
template <typename type>
size_t t_asn1_oid_value(binary_t& bin, type v, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }
    size_t len = 0;
    uint8 m = 0;
    while (v > 0x7f) {
        bin.insert(bin.begin() + pos, ((byte_t)v & 0x7f) | m);
        v >>= 7;
        m = 0x80;
        len++;
    }
    bin.insert(bin.begin() + pos, v | m);
    return len + 1;
}

template <typename type>
uint32 t_asn1_integer_value(binary_t& bin, type v, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }
    uint32 len = byte_capacity(v);
    type temp = convert_endian(v);
    bin.insert(bin.begin() + pos, (byte_t*)&temp + sizeof(type) - len, (byte_t*)&temp + sizeof(type));
    return len;
}

// X.690 8.3 encoding of an integer value
template <typename type>
void t_asn1_encode_integer(binary_t& bin, type value) {
    bin.insert(bin.end(), asn1_tag_integer);  // X.690 8.1.2 identifier octets
    size_t pos = bin.size();
    size_t size_encode = t_asn1_integer_value<type>(bin, value, pos);  // X.690 8.3.3
    t_asn1_length_octets<size_t>(bin, size_encode, pos);
}

// first contents octet
enum asn1_real_info_octet {
    asn1_real_binary = 0x80,           // bit 8-7 10
    asn1_real_binary_neg = 0xc0,       // bit 8-7 11
    asn1_real_decimal = 0x00,          // bit 8-7 00
    asn1_real_special = 0x40,          // bit 8-7 01
    asn1_real_base_2 = 0x00,           // bit 6-5 00
    asn1_real_base_8 = 0x10,           // bit 6-5 01
    asn1_real_base_16 = 0x20,          // bit 6-5 10
    asn1_real_reserved_future = 0x30,  // bit 6-5 11
    asn_real_scaling_f_mask = 0x0c,    // bit 4-3
    asn_real_scaling_f_0 = 0x00,
    asn1_real_exp_1oct = 0x00,  // bit 2-1 00
    asn1_real_exp_2oct = 0x01,  // bit 2-1 01
    asn1_real_exp_3oct = 0x02,  // bit 2-1 10
    asn1_real_exp_octs = 0x03,  // bit 2-1 11
};

static inline uint32 binary_from_fp(float fp) { return binary32_from_fp32(fp); }
static inline uint64 binary_from_fp(double fp) { return binary64_from_fp64(fp); }
static inline float ieee754_fabs(float v) { return fabsf(v); }
static inline double ieee754_fabs(double v) { return fabs(v); }

/**
 * @refer   ASN.1 by simple words - Chapter 2. Encoding of REAL type
 * @remarks
 *          0.15625 = 2^-3 + 2^-5 = 0.00101b = 1.01b * 2^-3 = S(0) E(-3) M(010...0) (IEEE754)
 *          1) base 2
 *             101b * 2^-5 -> (09 03 80 FB 05)
 *             info (80) binary format (80), base 2 (00), 1 exponent octet (00)
 *             exponent -5(FB)
 *             mantissa 5(05)
 *          2) base 8
 *             8^-1 + 2 * 8^-2 -> 00.12 -> 012 * 8^-2 -> (09 03 90 FE 0A)
 *             info (90) binary format (80), base 8 (10), 1 exponent octet (00)
 *             exponent -2(FE)
 *             mantissa 10(0a)
 *          3) base 16
 *             2*16^-1 + 8*16^-2 = 0x0.28 = 0x28 * 16^-2 -> M(0x28) = N * 2^F (N=5, F=3) -> (09 03 AC FE 05)
 *             info (AC) binary format (80), base 16 (20), scaling factor 11(0c), 1 exponent octet (00)
 *             exponent -2(FE)
 *             N 5(5)
 */
template <typename fptype, typename bintype>
size_t t_asn1_encode_real(binary_t& bin, fptype value) {
    // Step.1
    // ASN.1 by simple words - Chapter 2. Encoding of REAL type

    // Step.2 X.690 11.3 Real Values
    //   11.3.1 If the encoding represents a real value whose base B is 2, then binary encoding employing base 2 shall be used.
    //          Before encoding, the mantissa M and exponent E are chosen so that M is either 0 or is odd.
    //          NOTE – This is necessary because the same real value can be regarded as both {M, 2, E} and {M', 2, E'} with M ≠ M' if, for some non-zero integer
    //          n:
    //            M' = M × 2^–n
    //            E' = E + n
    //          In encoding the value, the binary scaling factor F shall be zero, and M and E shall each be represented in the fewest octets necessary.
    //   11.3.2 If the encoding represents a real value whose base B is 10, then decimal encoding shall be used. In forming the encoding, the following applies:
    //   11.3.2.1 The ISO 6093 NR3 form shall be used (see 8.5.8).
    //   11.3.2.2 SPACE shall not be used within the encoding.
    //   11.3.2.3 If the real value is negative, then it shall begin with a MINUS SIGN (–), otherwise, it shall begin with a digit.
    //   11.3.2.4 Neither the first nor the last digit of the mantissa may be a 0.
    //   11.3.2.5 The last digit in the mantissa shall be immediately followed by FULL STOP (.), followed by the exponentmark "E".
    //   11.3.2.6 If the exponent has the value 0, it shall be written "+0", otherwise the exponent's first digit shall not be zero, and PLUS SIGN shall not be
    //   used.

    size_t size_before = bin.size();

    int sign = 0;
    int exponent = 0;
    float mantissa = 0;
    ieee754_typeof_t type = ieee754_exp(value, &sign, &exponent, &mantissa);  // ieee754_typeof and frexpf

    auto isint = [](fptype v) -> bool { return 0.0 == fmod(v, 1); };

    while (ieee754_single_precision == ieee754_typeof(mantissa)) {
#if 0
        {
            basic_stream bs;
            bs << "FP" << (sizeof(fptype) << 3) << " : " << value << " exponent " << exponent << " mantissa " << mantissa;
            std::cout << bs << std::endl;
        }
#endif

        // break if either M is zero or odd
        if (isint(mantissa)) {
            break;
        }

        mantissa *= 2;
        exponent--;
    }

    bin.insert(bin.end(), asn1_tag_real);
    size_t pos = bin.size();
    uint32 size_exponent = 0;
    uint32 size_mantissa = 0;
    switch (type) {
        case ieee754_zero:
            if (sign) {
                // X.690 8.5.9 minus zero
                bin.insert(bin.end(), 0x01);
                bin.insert(bin.end(), 0x43);
            } else {
                // X.690 8.5.2 plus zero
                bin.insert(bin.end(), 0x00);
            }
            break;
        case ieee754_pinf:
            // X.690 8.5.9 PLUS-INFINITY
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x40);
            break;
        case ieee754_ninf:
            // X.690 8.5.9 MINUS-INFINITY
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x41);
            break;
        case ieee754_nan:
            // X.690 8.5.9 NOT-A-NUMBER
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x42);
            break;
        default:
            // V(e m)
            size_exponent = t_asn1_integer_value<int>(bin, exponent);
            size_mantissa = t_asn1_integer_value<int>(bin, ieee754_fabs(mantissa));
            // T(info_octet)
            uint8 info = sign ? asn1_real_binary_neg : asn1_real_binary;
            switch (size_exponent) {
                case 1:
                    info |= asn1_real_exp_1oct;  // 00
                    break;
                case 2:
                    info |= asn1_real_exp_2oct;  // 01
                    break;
                case 3:
                    info |= asn1_real_exp_3oct;  // 02
                    break;
                default:
                    // T:83 L:elen V(e m)
                    info |= asn1_real_exp_octs;  // 03
                    size_exponent = t_asn1_integer_value<size_t>(bin, size_exponent, pos);
                    break;
            }

            // T(info_octet) L
            bin.insert(bin.begin() + pos, info);
            t_asn1_integer_value<uint32>(bin, size_exponent + size_mantissa + 1, pos);
            break;
    }
    return bin.size() - size_before;
}

}  // namespace io
}  // namespace hotplace

#endif
