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

#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

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
    _values[""] = vt;
    return *this;
}

asn1_value& asn1_value::set(const std::string& name, const variant& vt) {
    _values[name] = vt;
    return *this;
}

asn1_value& asn1_value::set(const std::string& name, variant&& vt) {
    _values[name] = std::move(vt);
    return *this;
}

void asn1_value::publish(binary_t* b) {
    asn1_der_visitor encoder(b, this);
    encoder.visit(get_schema());
}

void asn1_value::publish(stream_t* s) {
    asn1_notation_visitor notation(s);
    notation.visit(get_schema());
}

void asn1_value::encode_value(binary_t& bin, asn1_object* object, const std::string& name, bool& do_len) {
    if (nullptr == object) return;

    auto iter = _values.find(name);
    if (_values.end() != iter) {
        auto entity = object->get_entity();
        const variant& v = iter->second;
        asn1_encode enc;
        enc.encode_value(bin, entity, v, do_len);
    }
}

void asn1_value::addref() { _shared.addref(); }

void asn1_value::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
