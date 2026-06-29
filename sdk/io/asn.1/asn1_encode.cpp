/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_encode.cpp
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
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1_encode::asn1_encode() {}

return_t asn1_encode::write_ident_octets(binary_t& bin, uint8 enc, uint64 tag, size_t pos) {
    if ((size_t)-1 == pos) {
        pos = bin.size();
    }

    binary_t temp;
    if (tag >= 31) {
        std::vector<uint8> v;
        while (tag >= 0x80) {
            v.push_back(tag & 0x7f);
            tag >>= 7;
        }
        if (tag) v.push_back(tag & 0x7f);

        temp.reserve(temp.size() + v.size() + 1);
        temp.push_back(enc | 0x1f);
        for (auto i = v.size(); i > 0; --i) {
            size_t idx = i - 1;
            uint8 contflag = (idx == 0) ? 0x00 : 0x80;
            temp.push_back(contflag | v[idx]);
        }
    } else {
        temp.push_back(enc | (uint8)tag);
    }

    bin.reserve(bin.size() + temp.size());
    bin.insert(bin.begin() + pos, temp.begin(), temp.end());

    return errorcode_t::success;
}

return_t asn1_encode::write_ident_octets2(binary_t& bin, asn1_object* object, size_t pos) {
    return_t ret = errorcode_t::success;
    if (nullptr == object) return errorcode_t::invalid_parameter;
    ret = write_ident_octets(bin, object->get_ident(), object->get_entity(), pos);
    return ret;
}

return_t asn1_encode::read_asn1_ident_octets(const byte_t* stream, size_t size, uint8& ident, uint64& tag) {
    if (nullptr == stream || 0 == size) {
        return errorcode_t::invalid_parameter;
    }

    size_t pos = 0;
    uint8 b = stream[pos];
    ident = b & ~asn1_tag_number_mask;
    tag = 0;

    uint8 val = b & asn1_tag_number_mask;
    uint8 iscont = (asn1_tag_number_mask == val);
    size_t que = 0;
    if (iscont) {
        ++que;
        if (pos + 1 < size) {
            if (0x80 == stream[pos + 1]) return errorcode_t::bad_data;
        }
        while (++pos < size) {
            b = stream[pos];
            uint8 m = (b & 0x80);
            uint8 c = (b & 0x7f);
            if (m) ++que;
            tag <<= 7;
            tag += c;
            --que;
            if (0 == m) break;
        }
        if (que) return errorcode_t::bad_data;
    } else {
        tag = val;
    }
    return errorcode_t::success;
}

asn1_encode& asn1_encode::encode(binary_t& bin, asn1_entity_t entity, const variant& vt) {
    write_ident_octets(bin, asn1_class_universal | asn1_tag_primitive, entity);
    auto pos = bin.size();
    bool do_len = true;
    encode_value(bin, entity, vt, do_len);
    if (do_len) {
        asn1_encode::t_asn1_length_octets<size_t>(bin, bin.size() - pos, pos);
    }
    return *this;
}

asn1_encode& asn1_encode::encode_value(binary_t& bin, asn1_entity_t entity, const variant& vt, bool& do_len) {
    do_len = true;
    const auto& v = vt.content();
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
                    t_asn1_integer_value(bin, v.data.i8);
                    break;
                case vartype_t::TYPE_UINT8:
                    t_asn1_integer_value(bin, v.data.ui8);
                    break;
                case vartype_t::TYPE_INT16:
                    t_asn1_integer_value(bin, v.data.i16);
                    break;
                case vartype_t::TYPE_UINT16:
                    t_asn1_integer_value(bin, v.data.ui16);
                    break;
                case vartype_t::TYPE_INT32:
                    t_asn1_integer_value(bin, v.data.i32);
                    break;
                case vartype_t::TYPE_UINT32:
                    t_asn1_integer_value(bin, v.data.ui32);
                    break;
                case vartype_t::TYPE_INT64:
                    t_asn1_integer_value(bin, v.data.i64);
                    break;
                case vartype_t::TYPE_UINT64:
                    t_asn1_integer_value(bin, v.data.ui64);
                    break;
#if defined __SIZEOF_INT128__
                case vartype_t::TYPE_INT128:
                    t_asn1_integer_value(bin, v.data.i128);
                    break;
                case vartype_t::TYPE_UINT128:
                    t_asn1_integer_value(bin, v.data.ui128);
                    break;
#endif
                default:
                    t_asn1_integer_value(bin, vt.t_toi<int64>());
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
                    type = t_asn1_encode_real<float, uint32>(bin, v.data.f);
                    break;
                case vartype_t::TYPE_DOUBLE:
                    type = t_asn1_encode_real<double, uint64>(bin, v.data.d);
                    break;
                default:
                    break;
            }
            switch (type) {
                case ieee754_typeof_t::ieee754_zero:
                case ieee754_typeof_t::ieee754_pinf:
                case ieee754_typeof_t::ieee754_ninf:
                case ieee754_typeof_t::ieee754_nan:
                    do_len = false;
                    break;
                default:
                    break;
            }
        } break;
        case asn1_entity_utctime: {
            // YYMMDDhhmm[ss]Z
            auto size = v.size ? v.size : strlen(v.data.str);
            if (0) t_asn1_length_octets(bin, size);
            binary_append(bin, v.data.str, size);
        } break;
        case asn1_entity_generalizedtime: {
            switch (v.type) {
                case vartype_t::TYPE_STRING:
                case vartype_t::TYPE_NSTRING: {
                    // YYYYMMDDhhmm[ss[.fff]]Z
                    // YYYYMMDDhhmm[ss[.fff]]+hhmm
                    auto size = v.size ? v.size : strlen(v.data.str);
                    if (0) t_asn1_length_octets(bin, size);
                    binary_append(bin, v.data.str, size);
                } break;
                case vartype_t::TYPE_DATETIME: {
                    basic_stream bs;
                    generalized_time(bs, *v.data.dt);
                    // t_asn1_length_octets<uint16>(bin, t_narrow_cast(bs.size()));
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
            if (0) t_asn1_length_octets<uint16>(bin, t_narrow_cast(oct.size()));
            binary_append(bin, oct);
        } break;
        case asn1_entity_cstring:
        case asn1_entity_generalstring:
        case asn1_entity_ia5string:
        case asn1_entity_printstring:
        case asn1_entity_t61string:
        case asn1_entity_universalstring:
        case asn1_entity_visiblestring: {
            auto size = v.size ? v.size : strlen(v.data.str);
            if (0) t_asn1_length_octets(bin, size);
            binary_append(bin, v.data.str, size);
        } break;
        case asn1_entity_oid: {
            oid_t oid;
            str_to_oid(v.data.str, oid);

            if (oid.size() >= 2) {
                uint32 size_encode = 0;
                auto pos = bin.size();

                size_encode += t_asn1_oid_value<uint32>(bin, (oid[0] * 40) + oid[1]);
                size_t size = oid.size();
                for (size_t i = 2; i < size; i++) {
                    uint32 node = oid[i];
                    if (0 == node) {
                        break;
                    } else if (node <= 127) {
                        binary_push(bin, node);
                        size_encode++;
                    } else {
                        size_encode += t_asn1_oid_value<uint32>(bin, node);
                    }
                }
                if (0) t_asn1_length_octets<uint32>(bin, size_encode, pos);
            }
        } break;
        case asn1_entity_reloid: {
            uint32 size_encode = 0;
            auto pos = bin.size();

            oid_t oid;
            str_to_oid(v.data.str, oid);

            size_t size = oid.size();
            for (size_t i = 0; i < size; i++) {
                uint32 node = oid[i];
                if (0 == node) {
                    break;
                } else if (node <= 127) {
                    binary_push(bin, node);
                    size_encode++;
                } else {
                    size_encode += t_asn1_oid_value<uint32>(bin, node);
                }
            }
            if (0) t_asn1_length_octets<uint32>(bin, size_encode, pos);
        } break;
        default:
            break;
    }
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

asn1_encode& asn1_encode::utctime(binary_t& bin, const datetime_t& dt, int tzoffset) {
    basic_stream bs;
    utctime(bs, dt, tzoffset);
    binary_push(bin, asn1_tag_utctime);
    t_asn1_length_octets<uint16>(bin, t_narrow_cast(bs.size()));
    bin.insert(bin.end(), bs.data(), bs.data() + bs.size());
    return *this;
}

asn1_encode& asn1_encode::utctime(basic_stream& bs, const datetime_t& dt, int tzoffset) {
    // Z indicates that local time is GMT, + indicates that local time is later than GMT, and - indicates that local time is earlier than GMT
    datetime d(dt);
    datetime_t utc;
    timespan_t ts;

    timespan_m(ts, tzoffset);
    d -= ts;
    d.gettime(&utc);
    if (utc.milliseconds) {
        bs.printf("%02d%02d%02d%02d%02d%02d.%dZ", utc.year % 100, utc.month, utc.day, utc.hour, utc.minute, utc.second, utc.milliseconds);
    } else {
        bs.printf("%02d%02d%02d%02d%02d%02dZ", utc.year % 100, utc.month, utc.day, utc.hour, utc.minute, utc.second);
    }
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
