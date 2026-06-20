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

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <set>

namespace hotplace {
namespace io {

asn1_value::asn1_value(asn1_object* schema) : _schema(schema) {
    if (schema)
        schema->addref();
    else
        throw exception(errorcode_t::not_specified);
    _shared.make_share(this);
}

asn1_value::~asn1_value() { _schema->release(); }

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

void asn1_value::write(stream_t* s, const std::string& name) {
    if (nullptr == s) return;
    auto iter = _values.find(name);
    if (_values.end() != iter) {
        const variant& v = iter->second;
        vtprintf(s, v, vtprintf_style_t::vtprintf_style_asn1);
    }
}

bool asn1_value::find(const std::string& name) { return _values.count(name) > 0; }

void asn1_value::encode_value(binary_t& bin, asn1_object* object, const std::string& name, bool& do_len) {
    if (nullptr == object) return;

    auto iter = _values.find(name);
    if (_values.end() != iter) {
        auto entity = object->get_entity();
        const variant& v = iter->second;
        asn1_encode enc;
        enc.encode_value(bin, entity, v, do_len);
    } else {
    }
}

void asn1_value::encode_sequenceof_value(binary_t& bin, asn1_object* object, const std::string& name) {
    if (nullptr == object) return;

    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        auto ident = object->get_ident();
        auto entity = object->get_entity();

        const variant& v = iter->second;

        asn1_encode enc;
        bool do_len = false;

        asn1_encode::asn1_ident_octets(bin, ident, entity);  // T
        auto pos = bin.size();
        enc.encode_value(bin, entity, v, do_len);                               // V
        asn1_encode::t_asn1_length_octets<size_t>(bin, bin.size() - pos, pos);  // insert L between T and V
    }
}

void asn1_value::encode_setof_value(binary_t& bin, asn1_object* object, const std::string& name) {
    if (nullptr == object) return;

    std::set<binary_t> ordered;

    auto liter = _values.lower_bound(name);
    auto uiter = _values.upper_bound(name);
    for (auto iter = liter; iter != uiter; ++iter) {
        auto ident = object->get_ident();
        auto entity = object->get_entity();

        const variant& v = iter->second;

        binary_t b;
        asn1_encode enc;
        bool do_len = false;

        asn1_encode::asn1_ident_octets(b, ident, entity);  // T
        auto pos = b.size();
        enc.encode_value(b, entity, v, do_len);                             // V
        asn1_encode::t_asn1_length_octets<size_t>(b, b.size() - pos, pos);  // insert L between T and V

        ordered.insert(std::move(b));
    }

    for (const auto& item : ordered) {
        bin.insert(bin.end(), item.begin(), item.end());
    }
}

void asn1_value::addref() { _shared.addref(); }

void asn1_value::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
