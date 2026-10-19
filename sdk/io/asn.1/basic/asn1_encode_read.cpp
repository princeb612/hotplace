/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_encode_read.cpp
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

return_t asn1_encode::read(const byte_t* stream, size_t size, size_t& pos, asn1_entity_t entity, size_t len, const std::string& name, asn1_value* value) {
    return_t ret = errorcode_t::success;
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
            if (bn.signed_byte_capacity() > 8)
                value->set(name, bn);
            else
                value->set(name, bn.t_bntoi<int64>());
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
        case asn1_entity_bitstring:
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
            pos += len;
        } break;
        case asn1_entity_utctime: {
            char* p = (char*)stream + pos;
            variant vt(p, len);
            value->set(name, std::move(vt));
            pos += len;
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
        case asn1_entity_utf8string:
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
            pos += len;
        } break;
        default: {
            auto p = stream + pos;
            auto ostr = base16_encode(p, len);
            value->set(name, std::move(ostr));
            pos += len;
        } break;
    }

    return errorcode_t::success;
}

}  // namespace io
}  // namespace hotplace
