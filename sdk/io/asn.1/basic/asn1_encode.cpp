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

asn1_encode::asn1_encode() {}

return_t asn1_encode::write_identifier(binary_t& bin, uint8 enc, uint64 tag, size_t pos) {
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

return_t asn1_encode::write_identifier2(binary_t& bin, const asn1_object* object, size_t pos) {
    return_t ret = errorcode_t::success;
    if (nullptr == object) return errorcode_t::invalid_parameter;
    ret = write_identifier(bin, object->get_ident(), object->get_entity(), pos);
    return ret;
}

return_t asn1_encode::read_identifier(const byte_t* stream, size_t size, size_t& pos, uint8& ident, uint64& tag) {
    if (nullptr == stream || 0 == size || (pos >= size)) {
        return errorcode_t::invalid_parameter;
    }

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
        ++pos;
        if (que) return errorcode_t::bad_data;
    } else {
        ++pos;
        tag = val;
    }
    return errorcode_t::success;
}

return_t asn1_encode::write_length(binary_t& bin, uint64 len, size_t pos) {
    if ((size_t)-1 == pos) {
        pos = bin.size();
    }

    size_t size = bin.size();
    if (pos > size) return errorcode_t::out_of_range;

    if (len > 0x7f) {
        int bytesize = byte_capacity(len);
        auto temp = convert_endian(len);
        bin.insert(bin.begin() + pos, 0x80 | bytesize);  // X.690 8.1.3.5
        bin.insert(bin.begin() + pos + 1, (byte_t*)&temp + sizeof(temp) - bytesize, (byte_t*)&temp + sizeof(temp));
    } else {
        // X.690 8.1.3.4
        bin.insert(bin.begin() + pos, (byte_t)len);
    }
    return errorcode_t::success;
}

return_t asn1_encode::read_length(const byte_t* stream, size_t size, size_t& pos, uint64& len) {
    if (pos == size) return errorcode_t::do_nothing;
    if (nullptr == stream || 0 == size || pos > size) return errorcode_t::invalid_parameter;

    auto msb = stream[pos];
    ++pos;
    if (0x80 & msb) {
        uint8 bytesize = msb & ~0x80;
        if (0 == bytesize) return errorcode_t::bad_data;
        if (bytesize > sizeof(uint64)) return errorcode_t::insufficient;
        if (pos + bytesize > size) return errorcode_t::bad_data;

        bignumber bn(stream + pos, bytesize);
        len = bn.t_bntoi<uint64>();

        if (len > 0x7f) {
            int capacity = byte_capacity(len);
            if (capacity != bytesize) return errorcode_t::bad_data;
        } else {
            if (bytesize != 0) return errorcode_t::bad_data;
        }

        pos += bytesize;
    } else {
        len = msb;
    }

    return errorcode_t::success;
}

asn1_encode& asn1_encode::write_tlv(binary_t& bin, asn1_entity_t entity, const variant& vt) {
    write_identifier(bin, asn1_class_universal | asn1_tag_primitive, entity);
    auto pos = bin.size();
    bool do_len = true;
    write(bin, entity, vt, do_len);
    if (do_len) {
        asn1_encode::write_length(bin, bin.size() - pos, pos);
    }
    return *this;
}

asn1_encode& asn1_encode::generalized_time(basic_stream& bs, const datetime_t& dt, bool isutc) {
    bs.printf("%04d%02d%02d%02d%02d%02d", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);

    if (dt.milliseconds) bs.printf(".%d", dt.milliseconds);
    if (isutc) bs.printf("Z");
    return *this;
}

asn1_encode& asn1_encode::utctime(binary_t& bin, const datetime_t& dt, int tzoffset) {
    basic_stream bs;
    utctime(bs, dt, tzoffset);
    binary_push(bin, asn1_tag_utctime);
    write_length(bin, t_narrow_cast(bs.size()));
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
