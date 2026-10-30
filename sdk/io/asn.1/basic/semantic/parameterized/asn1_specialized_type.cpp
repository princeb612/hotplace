/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_specialized_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_specialized_type.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>

namespace hotplace {
namespace io {

asn1_specialized_type::asn1_specialized_type(asn1_parameterized_type* templ, const asn1_paramvalues& values, const std::string& name, asn1_object* object)
    : asn1_type(asn1_entity_specialized_type, name, object), _templ(templ), _values(values) {
    if (nullptr == templ) throw exception(errorcode_t::not_specified);
    templ->addref();

    if (object) {
        auto temp = object->clone();  // resolve asn1_parameter
        set_object(temp);
    }
}

asn1_specialized_type::asn1_specialized_type(const asn1_specialized_type& other) : asn1_type(other) { *this = other; }

asn1_specialized_type::~asn1_specialized_type() { _templ->release(); }

asn1_specialized_type& asn1_specialized_type::operator=(const asn1_specialized_type& other) {
    asn1_type::operator=(other);
    _templ = other._templ;
    _values = other._values;
    _templ->addref();
    return *this;
}

asn1_specialized_type* asn1_specialized_type::clone() { return new asn1_specialized_type(*this); }

void asn1_specialized_type::represent(stream_t* s, const asn1_value* value) const {
    s->printf("%s", get_name().c_str());
    s->printf(" ::= ");
    s->printf("%s", _templ->get_name().c_str());
    s->printf(" {");
    size_t idx = 0;
    for (const auto& v : _values) {
        if (idx) s->printf(", ");
        v.represent(s, nullptr);
        ++idx;
    }
    s->printf("}");
}

bool asn1_specialized_type::represent(binary_t* b, const asn1_value* value, uint16 flags) const { return get_object()->represent(b, value, flags); }

asn1_parameterized_type* asn1_specialized_type::get_parameterized_type() const { return _templ; }

asn1_paramvalues& asn1_specialized_type::get_values() { return _values; }

bool asn1_specialized_type::lookup_name(const std::string& name, std::string& value) const {
    bool matched = false;
    const auto& types = _templ->get_types();
    size_t idx = 0;
    if (_values.size() == types.size()) {
        for (const auto& type : types) {
            if (type.name.empty() && (type.type == name)) {
                matched = true;
            }
            if (matched) {
                const auto& paramvalue = _values[idx];
                value = paramvalue.name;
                break;
            }
            ++idx;
        }
    }
    return matched;
}

bool asn1_specialized_type::lookup_value(const std::string& name, asn1_paramvalue& value) const {
    bool matched = false;
    const auto& types = _templ->get_types();
    size_t idx = 0;
    if (_values.size() == types.size()) {
        for (const auto& type : types) {
            if (type.name.empty() && (type.type == name)) {
                matched = true;
            } else if (type.name == name) {
                matched = true;
            }
            if (matched) {
                value = _values[idx];
                break;
            }
            ++idx;
        }
    }
    return matched;
}

}  // namespace io
}  // namespace hotplace
