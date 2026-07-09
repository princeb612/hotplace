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

#include <hotplace/sdk/io/asn.1/asn1.hpp>
#include <hotplace/sdk/io/asn.1/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>

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

return_t asn1::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    uint8 ident = 0;
    uint64 tag = 0;
    size_t len = 0;
    asn1_encode::read_ident_octets(stream, size, pos, ident, tag);  // T
    asn1_encode::read_length_octets(stream, size, pos, len);        // L
    asn1_object* object = nullptr;
    asn1_value* value = nullptr;

    object = asn1_builder::build((asn1_entity_t)tag);
    value = object->instantiate();

    _types.push_back(object);
    _values.push_back(value);

    switch (tag) {
        case asn1_entity_null: {
        } break;
        case asn1_entity_boolean: {
            if (pos < size) {
                auto b = stream[pos++];
                // value->set(b ? true : false);
                if (0xff == b) {
                    value->set(true);
                } else if (0 == b)
                    value->set(false);
                else {
                    ret = errorcode_t::bad_format;
                }
            } else {
                ret = errorcode_t::bad_data;
            }
        } break;
        case asn1_entity_integer: {
            if (pos < size) {
                bignumber bn(stream + pos, len, false);  // signed integer
                auto i = bn.t_bntoi<int64>();
                value->set(i);
                pos += len;
            } else {
                ret = errorcode_t::bad_data;
            }
        } break;
        case asn1_entity_real: {
            if (0 == len) {
                value->set(0.0);
            } else {
                if (pos + len <= size) {
                    auto b = stream[pos++];
                    switch (b) {
                        case 0x40:
                            value->set(fp32_from_binary32(fp32_pinf));
                            break;
                        case 0x41:
                            value->set(fp32_from_binary32(fp32_ninf));
                            break;
                        case 0x42:
                            value->set(fp32_from_binary32(fp32_nan));
                            break;
                        case 0x43:
                            value->set(-0.0);
                            break;
                        default: {
                            if (b & asn1_real_binary) {
                                bool isneg = false;
                                if (asn1_real_binary_neg == (b & asn1_real_binary_neg)) {
                                    isneg = true;
                                }
                                int32 exponent = 0;
                                int32 mantissa = 0;
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
                                    bignumber bn_mant(stream + pos, size_mantissa, false);
                                    mantissa = bn_mant.t_bntoi<int32>();
                                    if (size_mantissa <= 4) {
                                        float f = ldexpf((float)mantissa, exponent);
                                        if (isneg) f = -f;
                                        value->set(f);
                                    } else {
                                        double d = ldexp((double)mantissa, exponent);
                                        if (isneg) d = -d;
                                        value->set(d);
                                    }
                                } else {
                                    ret = errorcode_t::bad_format;
                                }
                            }
                        } break;
                    }
                } else {
                    ret = errorcode_t::bad_data;
                }
            }
        } break;
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
