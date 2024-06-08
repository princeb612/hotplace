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

asn1_encode& asn1_encode::primitive(binary_t& bin, int128 value) {
    t_asn1_encode_integer<int128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, uint128 value) {
    t_asn1_encode_integer<uint128>(bin, value);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, float value) {
    //
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, double value) {
    //
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, oid_t oid) {
    unsigned size_encode = 0;
    size_t pos = -1;
    bin.insert(bin.end(), asn1_tag_objid);
    pos = bin.size();
    size_encode += t_asn1_variable_length<uint32>(bin, (oid.node1 * 40) + oid.node2);
    size_t size = RTL_NUMBER_OF_FIELD(oid_t, node);
    for (size_t i = 0; i < size; i++) {
        uint32 node = oid.node[i];
        if (0 == node) {
            break;
        } else if (node <= 127) {
            binary_push(bin, node);
            size_encode++;
        } else {
            size_encode += t_asn1_variable_length<uint32>(bin, node);
        }
    }
    t_asn1_variable_length<unsigned>(bin, size_encode, pos);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, reloid_t oid) {
    unsigned size_encode = 0;
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
            size_encode += t_asn1_variable_length<uint32>(bin, node);
        }
    }
    t_asn1_variable_length<unsigned>(bin, size_encode, pos);
    return *this;
}

asn1_encode& asn1_encode::primitive(binary_t& bin, asn1_tag_t c, const std::string& value) {
    binary_push(bin, c);
    t_asn1_encode_length<size_t>(bin, value.size());
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
    t_asn1_encode_length<size_t>(bin, value.size());
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
    t_asn1_encode_length<uint16>(bin, 1 + (temp.size() / 2));
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
