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
 *  X.690 8 Basic encoding rules
 *  X.690 9 Canonical Encoding Rules
 *  X.690 10 Distinguished encoding rules
 *  X.690 11 Restrictions on BER employed by both CER and DER
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/template.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

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

asn1_encode& asn1_encode::primitive(binary_t& bin, int8 value) {
    t_asn1_encode_integer<int8>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint8 value) {
    t_asn1_encode_integer<uint8>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int16 value) {
    t_asn1_encode_integer<int16>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint16 value) {
    t_asn1_encode_integer<uint16>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int32 value) {
    t_asn1_encode_integer<int32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint32 value) {
    t_asn1_encode_integer<uint32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, int64 value) {
    t_asn1_encode_integer<int64>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint64 value) {
    t_asn1_encode_integer<uint64>(bin, value);
    return *this;
}

#if defined __SIZEOF_INT128__
asn1_encode& asn1_encode::primitive(binary_t& bin, int128 value) {
    t_asn1_encode_integer<int128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint128 value) {
    t_asn1_encode_integer<uint128>(bin, value);
    return *this;
}
#endif

asn1_encode& asn1_encode::primitive(binary_t& bin, float value) {
    t_asn1_encode_real<float, uint32>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, double value) {
    t_asn1_encode_real<double, uint64>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, asn1_type_t type, const std::string& value) {
    if (type < asn1_type_special) {
        binary_push(bin, type);
    }
    t_asn1_length_octets<size_t>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, asn1_tag_t type, const std::string& value) {
    binary_push(bin, type);
    t_asn1_length_octets<size_t>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::oid(binary_t& bin, const std::string& value) {
    oid_t oid;
    str_to_oid(value, oid);

    if (oid.size() >= 2) {
        uint32 size_encode = 0;
        size_t pos = -1;
        bin.insert(bin.end(), asn1_tag_objid);
        pos = bin.size();

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
        t_asn1_length_octets<uint32>(bin, size_encode, pos);
    }
    return *this;
}

asn1_encode& asn1_encode::reloid(binary_t& bin, const std::string& value) {
    uint32 size_encode = 0;
    size_t pos = -1;
    bin.insert(bin.end(), asn1_tag_relobjid);
    pos = bin.size();

    oid_t oid;
    str_to_oid(value, oid);

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
    t_asn1_length_octets<uint32>(bin, size_encode, pos);
    return *this;
}

asn1_encode& asn1_encode::encode(binary_t& bin, asn1_type_t type, const binary_t& value) {
    t_asn1_length_octets<uint32>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::encode(binary_t& bin, asn1_type_t type, const variant& value) {
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
        case TYPE_STRING:
            primitive(bin, type, value.content().data.str);
            break;
        case TYPE_DATETIME:
            switch (type) {
                case asn1_type_generalizedtime:
                    generalized_time(bin, *value.content().data.dt);
                    break;
                default:
                    break;
            }
            break;
    }
    return *this;
}

asn1_encode& asn1_encode::encode(binary_t& bin, int tag, int class_number) {
    switch (tag) {
        case asn1_class_universal:
            binary_push(bin, tag);
            break;
        case asn1_class_application:
        case asn1_class_context:
        case asn1_class_private:
        case (asn1_class_context | asn1_tag_constructed):
        default:
            binary_push(bin, tag | class_number);
            break;
    }
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

asn1_encode& asn1_encode::generalstring(binary_t& bin, const std::string& value) {
    primitive(bin, asn1_tag_generalstring, value);
    return *this;
}

asn1_encode& asn1_encode::ia5string(binary_t& bin, const std::string& value) {
    primitive(bin, asn1_tag_ia5string, value);
    return *this;
}

asn1_encode& asn1_encode::octstring(binary_t& bin, const std::string& value) {
    binary_t oct = std::move(base16_decode(value));
    binary_push(bin, asn1_tag_octstring);
    t_asn1_length_octets<uint16>(bin, oct.size());
    binary_append(bin, oct);
    return *this;
}

asn1_encode& asn1_encode::printablestring(binary_t& bin, const std::string& value) {
    binary_push(bin, asn1_tag_printstring);
    t_asn1_length_octets<uint16>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::t61string(binary_t& bin, const std::string& value) {
    binary_push(bin, asn1_tag_teletexstring);
    t_asn1_length_octets<uint16>(bin, value.size());
    binary_append(bin, value);
    return *this;
}

asn1_encode& asn1_encode::visiblestring(binary_t& bin, const std::string& value) {
    primitive(bin, asn1_tag_visiblestring, value);
    return *this;
}

asn1_encode& asn1_encode::generalized_time(binary_t& bin, const datetime_t& dt) {
    basic_stream bs;
    generalized_time(bs, dt);
    binary_push(bin, asn1_tag_generalizedtime);
    t_asn1_length_octets<uint16>(bin, bs.size());
    bin.insert(bin.end(), bs.data(), bs.data() + bs.size());
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
    t_asn1_length_octets<uint16>(bin, bs.size());
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
