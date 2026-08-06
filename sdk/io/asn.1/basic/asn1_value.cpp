/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_value.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/bit_set.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>
#include <set>

namespace hotplace {
namespace io {

asn1_value::asn1_value(asn1_object* schema) : _schema(schema) {
    if (schema) schema->addref();
    _shared.make_share(this);
}

asn1_value::asn1_value(const asn1_value& other) {
    *this = other;
    _shared.make_share(this);
}

asn1_value::~asn1_value() {
    if (_schema) _schema->release();
}

asn1_value& asn1_value::operator=(const asn1_value& other) {
    set_schema(other._schema);
    _values = other._values;
    return *this;
}

void asn1_value::set_schema(asn1_object* schema) {
    if (_schema) {
        _schema->release();
        _schema = nullptr;
    }
    if (schema) {
        _schema = schema->clone();
    }
}

asn1_object* asn1_value::get_schema() { return _schema; }

asn1_value& asn1_value::set(const variant& vt) {
    _values.emplace("", vt);
    return *this;
}

asn1_value& asn1_value::set(std::initializer_list<variant> items) {
    for (const auto& item : items) {
        _values.emplace("", item);
    }
    return *this;
}

asn1_value& asn1_value::set(const std::string& name, const variant& vt) {
    _values.emplace(name, vt);
    return *this;
}

asn1_value& asn1_value::set(const std::string& name, std::initializer_list<variant> items) {
    for (const auto& item : items) {
        _values.emplace(name, item);
    }
    return *this;
}

asn1_value& asn1_value::set(const std::string& name, variant&& vt) {
    _values.emplace(name, std::move(vt));
    return *this;
}

void asn1_value::publish(binary_t* b) {
    asn1_der_visitor encoder(b, this);
    encoder.visit(get_schema());
}

void asn1_value::publish(stream_t* s) {
    asn1_notation_visitor notation(s, this);
    notation.visit(get_schema());
}

void asn1_value::write(stream_t* s, const std::string& name) const {
    if (nullptr == s) return;
    auto iter = _values.find(name);
    if (_values.end() != iter) {
        const variant& v = iter->second;
        vtprintf(s, v, vtprintf_style_t::vtprintf_style_asn1);
    }
}

bool asn1_value::find(const std::string& name) const { return _values.count(name) > 0; }

bool asn1_value::find(const std::string& name, std::list<variant>& values, uint16 vtflags) const {
    bool ret = false;
    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        const auto& v = iter->second;
        auto flag = v.flag();
        if (vtflags & flag) {
            values.push_back(v);
            ret = true;
        }
    }
    return ret;
}

bool asn1_value::find(const std::string& name, std::list<std::string>& values, uint16 vtflags) const {
    bool ret = false;
    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        const auto& v = iter->second;
        auto flag = v.flag();
        if (vtflags & flag) {
            std::string key;
            v.to_string(key);
            values.push_back(key);
            ret = true;
        }
    }
    return ret;
}

void asn1_value::write(binary_t& bin, const asn1_object* object, const std::string& name, bool& do_len) const {
    if (nullptr == object) return;

    asn1_encode enc;
    auto entity = object->get_entity();

    auto iter = _values.find(name);
    if (_values.end() != iter) {
        const variant& v = iter->second;
        enc.write(bin, entity, v, do_len);
    } else {
        if (asn1_entity_null == entity) {
            enc.write(bin, entity, variant(), do_len);
        } else if (object->is_default()) {
            const auto& v = object->get_default_value();
            enc.write(bin, entity, v, do_len);
        } else {
            variant v;
            enc.write(bin, entity, v, do_len);
        }
    }
}

void asn1_value::encode_sequenceof_value(binary_t& bin, const asn1_object* object, const std::string& name) const {
    if (nullptr == object) return;

    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        // auto ident = object->get_ident();
        auto entity = object->get_entity();

        const variant& v = iter->second;

        asn1_encode enc;
        bool do_len = false;

        asn1_encode::write_identifier2(bin, object);  // T
        auto pos = bin.size();
        enc.write(bin, entity, v, do_len);                      // V
        asn1_encode::write_length(bin, bin.size() - pos, pos);  // insert L between T and V
    }
}

void asn1_value::encode_setof_value(binary_t& bin, const asn1_object* object, const std::string& name) const {
    if (nullptr == object) return;

    std::set<binary_t> ordered;

    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        // auto ident = object->get_ident();
        auto entity = object->get_entity();

        const variant& v = iter->second;

        binary_t b;
        asn1_encode enc;
        bool do_len = false;

        asn1_encode::write_identifier2(b, object);  // T
        auto pos = b.size();
        enc.write(b, entity, v, do_len);                    // V
        asn1_encode::write_length(b, b.size() - pos, pos);  // insert L between T and V

        ordered.insert(std::move(b));
    }

    for (const auto& item : ordered) {
        bin.insert(bin.end(), item.begin(), item.end());
    }
}

bool asn1_value::encode_namedlist(binary_t& bin, const asn1_object* object, const std::string& name, const std::map<std::string, asn1_native_int_t>& namedlist) const {
    if (nullptr == object) return false;

    auto entity = object->get_entity();

    auto lambda_enum2eval = [&](const std::string& ename, asn1_native_int_t& evalue) -> bool {
        evalue = 0;
        bool ret = false;
        auto iter = namedlist.find(ename);
        if (namedlist.end() != iter) {
            evalue = iter->second;
            ret = true;
        }
        return ret;
    };

    uint16 vtflags = 0;
    switch (entity) {
        case asn1_entity_bitstring:
        case asn1_entity_enum:
            vtflags = vt_flag_string;
            break;
        case asn1_entity_integer:
            vtflags = vt_flag_string | vt_flag_int;
            break;
        default:
            break;
    }

    switch (entity) {
        case asn1_entity_bitstring: {
            std::list<std::string> values;
            std::set<asn1_native_int_t> evalues;
            find(name, values, vtflags);
            for (const auto& item : values) {
                asn1_native_int_t evalue = 0;
                auto check = lambda_enum2eval(item, evalue);
                if (check & (evalue >= 0)) {
                    evalues.insert(evalue);
                }
            }
            if (false == evalues.empty()) {
                // std::bit_set
                asn1_native_int_t minvalue = *evalues.begin();
                asn1_native_int_t maxvalue = *evalues.rbegin();
                t_bit_set<asn1_native_int_t> bs(minvalue, maxvalue);
                for (const auto& item : evalues) {
                    bs.add(item);
                }
                binary_t temp = bs.get();
                bin.insert(bin.end(), bs.unused_bit());
                bin.insert(bin.end(), temp.begin(), temp.end());
            } else {
                return false;
            }
        } break;
        case asn1_entity_enum:
        case asn1_entity_integer: {
            std::list<variant> values;
            auto test = find(name, values, vtflags);
            if (test && (values.size() == 1)) {
                const auto& v = *values.begin();
                auto flag = v.flag();
                asn1_native_int_t evalue = 0;
                asn1_encode enc;
                if (vt_flag_string & flag) {
                    std::string key;
                    v.to_string(key);
                    auto test = lambda_enum2eval(key, evalue);
                    if (test) {
                        enc.write(bin, evalue);
                    }
                } else if (vt_flag_int & flag) {
                    evalue = v.t_toi<asn1_native_int_t>();
                    enc.write(bin, evalue);
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } break;
        default:
            break;
    }

    return true;
}

void asn1_value::for_each(std::function<void(const std::string& name, const variant& vt)> f) {
    for (const auto& pair : _values) {
        f(pair.first, pair.second);
    }
}

void asn1_value::addref() { _shared.addref(); }

void asn1_value::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
