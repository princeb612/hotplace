/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <math.h>

#include <sdk/io/asn.1/asn1.hpp>

namespace hotplace {
namespace io {

asn1_encode::asn1_encode() {}

asn1_encode& asn1_encode::null(binary_t& bin) {
    // X.690 8.8 encoding of a null value
    bin.insert(bin.end(), asn1_tag_null);
    bin.insert(bin.end(), 0x00);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, bool value) {
    // X.690 8.2 encoding of a boolean value
    bin.insert(bin.end(), asn1_tag_boolean);
    bin.insert(bin.end(), 1);
    if (value) {
        bin.insert(bin.end(), 0xff);
    } else {
        bin.insert(bin.end(), 0x00);
    }
    return *this;
}

// X.690 8.3 encoding of an integer value
template <typename type>
void t_asn1_encode_integer(binary_t& bin, type value) {
    bin.insert(bin.end(), asn1_tag_integer);  // X.690 8.1.2 identifier octets
    size_t pos = bin.size();
    size_t size_encode = t_asn1_encode_integer_value<type>(bin, value, pos);  // X.690 8.3.3
    t_asn1_length_octets<size_t>(bin, size_encode, pos);
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int16 value) {
    t_asn1_encode_integer<int32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint16 value) {
    t_asn1_encode_integer<uint32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int32 value) {
    t_asn1_encode_integer<int64>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint32 value) {
    t_asn1_encode_integer<uint64>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int64 value) {
    t_asn1_encode_integer<int128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint64 value) {
    t_asn1_encode_integer<uint128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int128 value) {
    t_asn1_encode_integer<int128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint128 value) {
    t_asn1_encode_integer<uint128>(bin, value);
    return *this;
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

template <typename fptype, typename bintype>
void t_asn1_encode_real(binary_t& bin, fptype value) {
    // ASN.1 by simple words - Chapter 2. Encoding of REAL type
    //
    // 0.15625 = 2^-3 + 2^-5 = 0b0.00101 = 0b1.01 * 2^-3 = S(0) E(-3) M(010...0) (IEEE754)
    // 1) base 2
    //    0b101 * 2^-5 -> (09 03 80 FB 05)
    //    info (80) binary format (80), base 2 (00), 1 exponent octet (00)
    //    exponent -5(FB)
    //    mantissa 5(05)
    // 2) base 8
    //    8^-1 + 2 * 8^-2 -> 00.12 -> 012 * 8^-2 -> (09 03 90 FE 0A)
    //    info (90) binary format (80), base 8 (10), 1 exponent octet (00)
    //    exponent -2(FE)
    //    mantissa 10(0a)
    // 3) base 16
    //    2*16^-1 + 8*16^-2 = 0x0.28 = 0x28 * 16^-2 -> M(0x28) = N * 2^F (N=5, F=3) -> (09 03 AC FE 05)
    //    info (AC) binary format (80), base 16 (20), scaling factor 11(0c), 1 exponent octet (00)
    //    exponent -2(FE)
    //    N 5(5)

    int sign = 0;
    int exponent = 0;
    float mantissa = 0;
    ieee754_typeof_t type = ieee754_exp(value, &sign, &exponent, &mantissa);  // is_typeof and frexpf

    auto isint = [](fptype v) -> bool { return 0.0 == fmod(v, 1); };

    while (ieee754_single_precision == is_typeof(mantissa)) {
        if (isint(mantissa)) {
            break;
        }

        mantissa *= 2;
        exponent--;
    }

#if 0
    {
        basic_stream bs;
        bs << "FP" << (sizeof(fptype) << 3) << " : " << value << " exponent " << exponent << " mantissa " << mantissa << "\n";
        printf("%s", bs.c_str());
    }
#endif

    bin.insert(bin.end(), asn1_tag_real);
    size_t pos = bin.size();
    uint32 size_exponent = 0;
    uint32 size_mantissa = 0;
    switch (type) {
        case ieee754_zero:
            if (sign) {
                // // X.690 8.5.9 minus zero
                bin.insert(bin.end(), 0x01);
                bin.insert(bin.end(), 0x43);
            } else {
                // X.690 8.5.2 plus zero
                bin.insert(bin.end(), 0x00);
            }
            break;
        case ieee754_pinf:
            // // X.690 8.5.9 PLUS-INFINITY
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x40);
            break;
        case ieee754_ninf:
            // // X.690 8.5.9 MINUS-INFINITY
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x41);
            break;
        case ieee754_nan:
            // // X.690 8.5.9 NOT-A-NUMBER
            bin.insert(bin.end(), 0x01);
            bin.insert(bin.end(), 0x42);
            break;
        default:
            // V(e m)
            size_exponent = t_asn1_encode_integer_value<int>(bin, exponent);
            size_mantissa = t_asn1_encode_integer_value<int>(bin, ieee754_fabs(mantissa));
            // T(info_octet)
            uint8 info = sign ? asn1_real_binary_neg : asn1_real_binary;
            switch (size_exponent) {
                case 1:
                    info |= asn1_real_exp_1oct;
                    break;
                case 2:
                    info |= asn1_real_exp_2oct;
                    break;
                case 3:
                    info |= asn1_real_exp_3oct;
                    break;
                default:
                    // T:83 L:elen V(e m)
                    info |= asn1_real_exp_octs;
                    size_exponent = t_asn1_encode_integer_value<size_t>(bin, size_exponent, pos);
                    break;
            }

            // T(info_octet) L
            bin.insert(bin.begin() + pos, info);
            t_asn1_encode_integer_value<uint32>(bin, size_exponent + size_mantissa + 1, pos);
            break;
    }
}

asn1_encode& asn1_encode::primitive(binary_t& bin, float value) {
    t_asn1_encode_real<float, uint32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, double value) {
    t_asn1_encode_real<double, uint64>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, oid_t oid) {
    uint32 size_encode = 0;
    size_t pos = -1;
    bin.insert(bin.end(), asn1_tag_objid);
    pos = bin.size();
    size_encode += t_asn1_oid_value<uint32>(bin, (oid.node1 * 40) + oid.node2);
    size_t size = RTL_NUMBER_OF_FIELD(oid_t, node);
    for (size_t i = 0; i < size; i++) {
        uint32 node = oid.node[i];
        if (0 == node) {
            break;
        } else if (node <= 127) {
            binary_push(bin, node);
            size_encode++;
        } else {
            size_encode += t_asn1_oid_value<uint32>(bin, node);
        }
    }
    t_asn1_length_octets<uint32>(bin, size_encode, pos);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, reloid_t oid) {
    uint32 size_encode = 0;
    size_t pos = -1;
    bin.insert(bin.end(), asn1_tag_relobjid);
    pos = bin.size();
    size_t size = RTL_NUMBER_OF_FIELD(reloid_t, node);
    for (size_t i = 0; i < size; i++) {
        uint32 node = oid.node[i];
        if (0 == node) {
            break;
        } else if (node <= 127) {
            binary_push(bin, node);
            size_encode++;
        } else {
            size_encode += t_asn1_oid_value<uint32>(bin, node);
        }
    }
    t_asn1_length_octets<uint32>(bin, size_encode, pos);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, asn1_tag_t c, const std::string& value) {
    binary_push(bin, c);
    t_asn1_length_octets<size_t>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::encode(binary_t& bin, const variant& value) {
    switch (value.type()) {
        case TYPE_NULL:
            null(bin);
            break;
        case TYPE_BOOL:
            primitive(bin, value.content().data.b);
            break;
        case TYPE_INT8:
            primitive(bin, value.content().data.i8);
            break;
        case TYPE_UINT8:
            primitive(bin, value.content().data.ui8);
            break;
        case TYPE_INT16:
            primitive(bin, value.content().data.i16);
            break;
        case TYPE_UINT16:
            primitive(bin, value.content().data.ui16);
            break;
        case TYPE_INT32:
            primitive(bin, value.content().data.i32);
            break;
        case TYPE_UINT32:
            primitive(bin, value.content().data.ui32);
            break;
        case TYPE_INT64:
            primitive(bin, value.content().data.i64);
            break;
        case TYPE_UINT64:
            primitive(bin, value.content().data.ui64);
            break;
        case TYPE_INT128:
            primitive(bin, value.content().data.i128);
            break;
        case TYPE_UINT128:
            primitive(bin, value.content().data.ui128);
            break;
        case TYPE_FLOAT:
            primitive(bin, value.content().data.f);
            break;
        case TYPE_DOUBLE:
            primitive(bin, value.content().data.d);
            break;
    }
    return *this;
}

asn1_encode& asn1_encode::encode(binary_t& bin, int tag, int class_number, const std::string& value) {
    switch (tag) {
        case asn1_tag_application:
        case asn1_tag_context:
        case asn1_tag_private:
        case (asn1_tag_context | asn1_tag_constructed):
            binary_push(bin, tag | class_number);
            break;
        case asn1_tag_universal:
        default:
            binary_push(bin, tag);
            break;
    }
    t_asn1_length_octets<size_t>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::generalstring(binary_t& bin, const std::string& value) { return primitive(bin, asn1_tag_generalstring, value); }

asn1_encode& asn1_encode::ia5string(binary_t& bin, const std::string& value) {
    return primitive(bin, asn1_tag_ia5string, value);
    return *this;
}

asn1_encode& asn1_encode::visiblestring(binary_t& bin, const std::string& value) {
    return primitive(bin, asn1_tag_visiblestring, value);
    return *this;
}

asn1_encode& asn1_encode::bitstring(binary_t& bin, const std::string& value) {
    // X.690 8.6 encoding of a bitstring value
    // X.690 8.6.2.2 The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant bit,
    // the number of unused bits in the final subsequent octet. The number shall be in the range zero to seven.

    bool is_odd = (value.size() % 2) ? true : false;
    uint8 pad = is_odd ? 4 : 0;
    std::string temp = value;
    if (is_odd) {
        temp += "0";
    }
    binary_push(bin, asn1_tag_bitstring);
    t_asn1_length_octets<uint16>(bin, 1 + (temp.size() / 2));
    binary_push(bin, pad);
    binary_append(bin, base16_decode(temp));
    return *this;
}

asn1_encode& asn1_encode::generalized_time(basic_stream& bs, const datetime_t& dt) {
    if (dt.milliseconds) {
        bs.printf("%04d%02d%02d%02d%02d%02d.%dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.milliseconds);
    } else {
        bs.printf("%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    }
    return *this;
}

asn1_encode& asn1_encode::utctime(basic_stream& obj, const datetime_t& dt) {
    //
    return *this;
}

asn1_encode& asn1_encode::indef(binary_t& bin) {
    // X.690 8.1.5 end-of-contents octets
    // see end_contents
    binary_push(bin, 0x80);
    return *this;
}

asn1_encode& asn1_encode::end_contents(binary_t& bin) {
    // X.690 8.1.5 end-of-contents octets

    // 8.1.3.6 For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5),
    // and shall consist of a single octet.

    // 8.1.3.6.1 The single octet shall have bit 8 set to one, and bits 7 to 1 set to zero.

    // X.690 8.1.3.6 For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5),
    // and shall consist of a single octet.

    // 0x80 infinite length
    // ...
    // 0x00 0x00 (EOC)

    binary_push(bin, 0x00);
    binary_push(bin, 0x00);
    return *this;
}

}  // namespace io
}  // namespace hotplace
