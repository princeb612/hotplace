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
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
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
    if (nullptr == stream || 0 == size || pos >= size) return errorcode_t::invalid_parameter;

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

return_t asn1_encode::read(const byte_t* stream, size_t size, size_t& pos, asn1_entity_t entity, size_t len, asn1_value* value) {
    return_t ret = errorcode_t::success;
    const std::string name;
    switch (entity) {
        case asn1_entity_null: {
            // pos += len;  // len == 0
        } break;
        case asn1_entity_boolean: {
            if (1 != len) {
                ret = errorcode_t::bad_format;
                break;
            }
            auto b = stream[pos++];
            // value->set(name, b ? true : false);
            if (0xff == b)
                value->set(name, true);
            else if (0 == b)
                value->set(name, false);
            else
                ret = errorcode_t::bad_format;
        } break;
        case asn1_entity_integer: {
            bignumber bn(stream + pos, len, false);  // signed integer
            auto i = bn.t_bntoi<int64>();
            value->set(name, i);
            pos += len;
        } break;
        case asn1_entity_real: {
            if (0 == len) {
                value->set(name, 0.0);
            } else {
                auto b = stream[pos++];
                switch (b) {
                    case 0x40:
                        value->set(name, fp32_from_binary32(fp32_pinf));
                        break;
                    case 0x41:
                        value->set(name, fp32_from_binary32(fp32_ninf));
                        break;
                    case 0x42:
                        value->set(name, fp32_from_binary32(fp32_nan));
                        break;
                    case 0x43:
                        value->set(name, -0.0);
                        break;
                    default: {
                        if (b & asn1_real_binary) {
                            bool isneg = false;
                            if (asn1_real_binary_neg == (b & asn1_real_binary_neg)) {
                                isneg = true;
                            }
                            int32 exponent = 0;
                            int64 mantissa = 0;
                            auto exp_oct = b & 0x3;
                            size_t exp_len = 0;
                            size_t exp_pos = pos;
                            switch (exp_oct) {
                                case asn1_real_exp_1oct:
                                    exp_len = 1;
                                    pos += 1;
                                    break;
                                case asn1_real_exp_2oct:
                                    exp_len = 2;
                                    pos += 2;
                                    break;
                                case asn1_real_exp_3oct:
                                    exp_len = 3;
                                    pos += 3;
                                    break;
                                default:
                                    asn1_encode::read_length(stream, size, pos, exp_len);
                                    break;
                            }
                            if (exp_pos + exp_len < size) {
                                bignumber bn_exp(stream + exp_pos, exp_len, false);
                                exponent = bn_exp.t_bntoi<int32>();

                                size_t size_mantissa = size - (exp_pos + exp_len);
                                bignumber bn_mant(stream + pos, size_mantissa);
                                mantissa = bn_mant.t_bntoi<int64>();
                                auto capacity = bn_mant.unsigned_byte_capacity();

#if defined DEBUG
                                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
                                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                                        dbs << ANSI_ESCAPE << "1;36m" << "REAL" << " : " << "exponent " << exponent << " mantissa " << mantissa << ANSI_ESCAPE << "0m"
                                            << "\n";
                                    });
                                }
#endif

                                if (capacity <= 4) {
                                    float f = ldexpf((float)mantissa, exponent);
                                    if (isneg) f = -f;
                                    value->set(name, f);
                                } else {
                                    double d = ldexp((double)mantissa, exponent);
                                    if (isneg) d = -d;
                                    value->set(name, d);
                                }

                                pos += size_mantissa;
                            } else {
                                ret = errorcode_t::bad_format;
                            }
                        }
                    } break;
                }
            }
        } break;
        case asn1_entity_octstring: {
            auto p = stream + pos;
            auto ostr = base16_encode(p, len);
            value->set(name, std::move(ostr));
            pos += len;
        } break;
        case asn1_entity_generalizedtime: {
            // ^\d{4}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:[01]\d|2[0-3])(?:[0-5]\d)(?:[0-5]\d)?(?:\.\d+)?(?:Z|[+\-](?:0\d|1[0-2])[0-5]\d)$
            // ^(\d{4})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])([0-5]\d)([0-5]\d)?(\.\d+)?(Z|[+\-](0\d|1[0-2])[0-5]\d)$
            const char* expr = R"(^\d{4}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:[01]\d|2[0-3])(?:[0-5]\d)(?:[0-5]\d)?(?:\.\d+)?(?:Z|[+\-](?:0\d|1[0-2])[0-5]\d)$)";
            size_t rpos = 0;
            std::list<std::map<size_t, range_t>> tokens;

            regex_tokens((char*)stream + pos, len, expr, rpos, tokens);

            if (false == tokens.empty()) {
                auto match = *tokens.begin();
                if (match[0].end == len) {
                    char* p = (char*)stream + pos;
                    variant vt(p, len);
                    value->set(name, std::move(vt));
                }
            }
        } break;
        case asn1_entity_oid: {
            oid_t oid;
            auto limit = pos + len;
            while (pos < limit) {
                uint64 v = 0;
                ret = base128_decode(stream, limit, pos, v);
                if (errorcode_t::success != ret) return ret;
                oid.push_back(v);
            }
            if (oid.empty()) return errorcode_t::bad_data;

            auto v = *oid.begin();
            auto first = v / 40;
            auto second = v % 40;

            oid.erase(oid.begin());
            oid.insert(oid.begin(), second);
            oid.insert(oid.begin(), first);

            basic_stream bs;
            oid_to_str(oid, bs);

            variant vt(bs);
            value->set(name, std::move(vt));
        } break;
        case asn1_entity_reloid: {
            oid_t oid;
            auto limit = pos + len;
            while (pos < limit) {
                uint64 v = 0;
                ret = base128_decode(stream, limit, pos, v);
                if (errorcode_t::success != ret) return ret;
                oid.push_back(v);
            }
            if (oid.empty()) return errorcode_t::bad_data;

            basic_stream bs;
            oid_to_str(oid, bs);

            variant vt(bs);
            value->set(name, std::move(vt));
        } break;
        case asn1_entity_printstring:
        case asn1_entity_teletexstring:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring:
        case asn1_entity_bmpstring: {
            char* p = (char*)stream + pos;
            variant vt(p, len);
            value->set(name, std::move(vt));
        } break;
        default: {
        } break;
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
            auto size = v.size ? v.size : strlen(v.data.str);
            binary_append(bin, v.data.str, size);
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
            str_to_oid(v.data.str, oid);

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
