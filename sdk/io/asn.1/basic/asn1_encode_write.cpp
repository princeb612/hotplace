/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_encode_write.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *  X.690 8 Basic encoding rules
 *  X.690 9 Canonical Encoding Rules
 *  X.690 10 Distinguished encoding rules
 *  X.690 11 Restrictions on BER employed by both CER and DER
 */

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/encoding/base128.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1_encode& asn1_encode::write(binary_t& bin, asn1_entity_t entity, const variant& vt, bool& do_len) {
    do_len = true;
    const auto& v = vt.get();
    switch (entity) {
        case asn1_entity_boolean:
            // X.690 8.2 encoding of a boolean value
            // ASN.1 - Communication between Heterogeneous Systems 18.2.1 BOOLEAN value
            if (v.data.b) {
                bin.insert(bin.end(), 0xff);  // any single not-null octet
            } else {
                bin.insert(bin.end(), 0x00);
            }
            break;
        case asn1_entity_integer: {
            // ASN.1 - Communication between Heterogeneous Systems 18.2.3 INTEGER value
            switch (vt.type()) {
                case vartype_t::TYPE_INT8:
                    write(bin, v.data.i8);
                    break;
                case vartype_t::TYPE_UINT8:
                    write(bin, v.data.ui8);
                    break;
                case vartype_t::TYPE_INT16:
                    write(bin, v.data.i16);
                    break;
                case vartype_t::TYPE_UINT16:
                    write(bin, v.data.ui16);
                    break;
                case vartype_t::TYPE_INT32:
                    write(bin, v.data.i32);
                    break;
                case vartype_t::TYPE_UINT32:
                    write(bin, v.data.ui32);
                    break;
                case vartype_t::TYPE_INT64:
                    write(bin, v.data.i64);
                    break;
                case vartype_t::TYPE_UINT64:
                    write(bin, v.data.ui64);
                    break;
#if defined __SIZEOF_INT128__
                case vartype_t::TYPE_INT128:
                    write(bin, v.data.i128);
                    break;
                case vartype_t::TYPE_UINT128:
                    write(bin, v.data.ui128);
                    break;
#endif
                default:
                    write(bin, vt.t_toi<int64>());
                    break;
            }
        } break;
        case asn1_entity_null:
            // X.690 8.8 encoding of a null value

            // ASN.1 - Communication between Heterogeneous Systems 18.2.2 NULL value
            // encoded without value octet
            break;
        case asn1_entity_real: {
            ieee754_typeof_t type = {};
            switch (vt.type()) {
                case vartype_t::TYPE_FLOAT:
                    type = write(bin, v.data.f);
                    break;
                case vartype_t::TYPE_DOUBLE:
                    type = write(bin, v.data.d);
                    break;
                default:
                    break;
            }
            switch (type) {
                case ieee754_typeof_t::ieee754_zero:
                case ieee754_typeof_t::ieee754_pinf:
                case ieee754_typeof_t::ieee754_ninf:
                case ieee754_typeof_t::ieee754_nan:
                    break;
                default:
                    break;
            }
        } break;
        case asn1_entity_utctime: {
            // YYMMDDhhmm[ss]Z
            auto size = v.size ? v.size : strlen(v.data.str);
            binary_append(bin, v.data.str, size);
        } break;
        case asn1_entity_generalizedtime: {
            switch (v.type) {
                case vartype_t::TYPE_STRING:
                case vartype_t::TYPE_NSTRING: {
                    // YYYYMMDDhhmm[ss[.fff]]Z
                    // YYYYMMDDhhmm[ss[.fff]]+hhmm
                    auto size = v.size ? v.size : strlen(v.data.str);
                    binary_append(bin, v.data.str, size);
                } break;
                case vartype_t::TYPE_DATETIME: {
                    basic_stream bs;
                    generalized_time(bs, *v.data.dt);
                    bin.insert(bin.end(), bs.data(), bs.data() + bs.size());
                } break;
                default:
                    break;
            }
        } break;
        case asn1_entity_bitstring: {
            // ASN.1 - Communication between Heterogeneous Systems 18.2.6 BIT STRING value
            char* p = v.data.str;
            auto size = v.size ? v.size : strlen(p);
            uint8 unused = (8 - (size & 7)) & 7;  // 13 = 8 + 5 ununsed 3
            bin.insert(bin.end(), unused);
            uint8 b = 0;
            for (size_t idx = 0; idx < size;) {
                char c = p[idx++];
                b <<= 1;
                if (c == '1') b |= 1;
                if (idx % 8 == 0) {
                    bin.insert(bin.end(), b);
                    b = 0;
                }
            }
            if (unused) {
                b <<= unused;
                bin.insert(bin.end(), b);
            }
        } break;
        case asn1_entity_octstring: {
            auto size = v.size ? v.size : strlen(v.data.str);
            binary_t oct = base16_decode(v.data.bstr, size);
            binary_append(bin, oct);
        } break;
        case asn1_entity_cstring:
        case asn1_entity_generalstring:
        case asn1_entity_ia5string:
        case asn1_entity_printstring:
        case asn1_entity_t61string:
        case asn1_entity_universalstring:
        case asn1_entity_visiblestring: {
            auto size = v.size ? v.size : (v.data.str ? strlen(v.data.str) : 0);
            if (size) binary_append(bin, v.data.str, size);
        } break;
        case asn1_entity_oid: {
            oid_t oid;
            str_to_oid(v.data.str, oid);

            // X.690 8.19.2
            if (oid.size() >= 2) {
                base128_encode((oid[0] * 40) + oid[1], bin);
                size_t size = oid.size();
                for (size_t i = 2; i < size; ++i) {
                    auto node = oid[i];
                    if (0 == node) {
                        break;
                    } else {
                        base128_encode(node, bin);
                    }
                }
            }
        } break;
        case asn1_entity_reloid: {
            oid_t oid;
            if (v.data.str) str_to_oid(v.data.str, oid);

            size_t size = oid.size();
            for (size_t i = 0; i < size; ++i) {
                auto node = oid[i];
                if (0 == node) {
                    break;
                } else {
                    base128_encode(node, bin);
                }
            }
        } break;
        default:
            break;
    }
    return *this;
}

}  // namespace io
}  // namespace hotplace
