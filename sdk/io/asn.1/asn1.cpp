/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/encoding/base128.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>
#include <hotplace/sdk/io/asn.1/asn1.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1::asn1() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::asn1(const asn1& other) : asn1() {
    for (auto item : other._types) {
        add(item->clone());
    }
}

asn1::~asn1() { clear(); }

asn1& asn1::operator=(const asn1& other) {
    for (auto item : other._types) {
        add(item->clone());
    }
    return *this;
}

asn1* asn1::clone() { return new asn1(*this); }

asn1_object* asn1::build(asn1_entity_t entity, std::function<void(asn1_object*)> f) {
    asn1_object* object = nullptr;
    switch (entity) {
        case asn1_entity_integer:
            object = new asn1_integer;
            break;
        case asn1_entity_bitstring:
            object = new asn1_bitstring;
            break;
        case asn1_entity_boolean:
        case asn1_entity_octstring:
        case asn1_entity_null:
        case asn1_entity_oid:
        case asn1_entity_objdesc:
        case asn1_entity_extern:
        case asn1_entity_real:
        case asn1_entity_enum:
        case asn1_entity_embedpdv:
        case asn1_entity_utf8string:
        case asn1_entity_reloid:
        case asn1_entity_sequence:
        case asn1_entity_set:
        case asn1_entity_numstring:
        case asn1_entity_printstring:
        case asn1_entity_teletexstring:
        // case asn1_entity_t61string:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_utctime:
        case asn1_entity_generalizedtime:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        // case asn1_entity_iso646string:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring:
        case asn1_entity_bmpstring:
        case asn1_entity_date:
        case asn1_entity_timeofday:
        case asn1_entity_datetime:
        case asn1_entity_duration:
            object = new asn1_builtin_type(entity);
            break;
        default:
            break;
    }
    if (object && f) {
        f(object);
    }
    return object;
}

asn1& asn1::add(asn1_object* item) {
    if (item) {
        _types.push_back(item);
        const std::string& name = item->get_name();
        if (false == name.empty()) {
            _dictionary.emplace(name, item);
        }
    }
    return *this;
}

asn1& asn1::add(asn1_object* item, std::function<void(asn1_object*)> f) {
    if (item && f) {
        f(item);
        add(item);
    }
    return *this;
}

asn1& asn1::operator<<(asn1_object* item) { return add(item); }

return_t asn1::read(const byte_t* stream, size_t size, size_t& pos) { return read(nullptr, stream, size, pos); }

return_t asn1::read(asn1_object* parent, const byte_t* stream, size_t size, size_t& pos) {
    // without notation, weakly-typed raw TLV tree
    return_t ret = errorcode_t::success;

    if (pos >= size) return errorcode_t::bad_data;

    uint8 ident = 0;
    uint64 tag = 0;
    size_t len = 0;

    ret = asn1_encode::read_ident_octets(stream, size, pos, ident, tag);  // T
    if (errorcode_t::success != ret) return ret;
    ret = asn1_encode::read_length_octets(stream, size, pos, len);  // L
    if (errorcode_t::success != ret) return ret;

    if (pos + len > size) return errorcode_t::bad_data;

    asn1_object* object = nullptr;
    asn1_value* value = nullptr;

    uint8 class_value = ident & asn1_class_mask;
    uint8 pcbit = ident & asn1_tag_mask;
    if (asn1_class_universal == class_value) {
        // UNIVERSAL
        object = build((asn1_entity_t)tag);
    } else {
        // APPLICATION, PRIVATE, Context-specific
        object = new asn1_tagged_type(class_value, tag, asn1_automatic, new asn1_any);

        // check IMPLICIT
        if (asn1_tag_primitive == pcbit) {
            // Primitive and APPLICATION, PRIVATE, Context-specific
            // cf. EXPLICIT has Constructed bit
            object->get_tag()->as_implicit();
        } else if (asn1_tag_constructed == pcbit) {
            object->as_constructed();

            return_t test = errorcode_t::success;
            size_t tpos = pos;
            uint8 tident = 0;
            uint64 ttag = 0;
            size_t tlen = 0;
            __try2 {
                test = asn1_encode::read_ident_octets(stream, size, tpos, tident, ttag);
                if (errorcode_t::success != test) __leave2;
                test = asn1_encode::read_length_octets(stream, size, tpos, tlen);
                if (errorcode_t::success != test) __leave2;

                if (asn1_class_application == class_value || asn1_class_private == class_value) {
                    if (asn1_class_universal == (tident & asn1_class_mask)) {
                        object->get_tag()->as_explicit();
                    } else {
                        // maybe implicit (not 100%)
                    }
                }
            }
            __finally2 {}
        }
    }

    value = object->instantiate();

    _types.push_back(object);
    _values.push_back(value);

    auto name = object->get_name();
    // size_t snapshot = pos;

    if (asn1_class_universal != class_value) {
        if (asn1_tag_primitive == pcbit) {
            variant vt(stream + pos, len);
            value->set(name, std::move(vt));
            pos += len;
        } else {
#if 0
            // TODO TL TLV
            size_t limit = pos + len;
            while (pos < limit) {
                ret = read(object, stream, size, pos);
                if (errorcode_t::success != ret) return ret;
            }
            pos = limit;
#else
            // temporary
            variant vt(stream + pos, len);
            value->set(name, std::move(vt));
            pos += len;
#endif
        }
    } else {
        switch (tag) {
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
                                        asn1_encode::read_length_octets(stream, size, pos, exp_len);
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
                                            dbs << ANSI_ESCAPE
                                                "1;36m"
                                                "REAL"
                                                << " : " << "exponent " << exponent << " mantissa " << mantissa
                                                << ANSI_ESCAPE
                                                "0m"
                                                "\n";
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
        }
    }

    return ret;
}

void asn1::for_each(std::function<void(asn1_object*)> f) {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1::for_each(std::function<void(asn1_value*)> f) {
    for (const auto& item : _values) {
        f(item);
    }
}

void asn1::notation(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (auto item : _types) {
        item->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (auto item : _values) {
        asn1_notation_visitor notation(s, item);
        item->get_schema()->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(binary_t* b) {
    for (auto item : _values) {
        asn1_der_visitor encoder(b, item);
        item->get_schema()->accept(&encoder);
    }
}

void asn1::clear() {
    for (auto item : _types) item->release();
    for (auto item : _values) item->release();
    _types.clear();
    _values.clear();
}

void asn1::addref() { _shared.addref(); }

void asn1::release() { _shared.delref(); }

// parser& asn1::get_parser() { return _parser; }
//
// const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
