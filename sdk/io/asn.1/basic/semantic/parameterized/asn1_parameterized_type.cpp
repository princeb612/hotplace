/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parameterized_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_specialized_type.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>

namespace hotplace {
namespace io {

asn1_parameterized_type::asn1_parameterized_type(const asn1_paramtypes& types, const std::string& name, asn1_object* object)
    : asn1_type(asn1_entity_parameterized_type, name, object), _types(types) {}

asn1_parameterized_type::asn1_parameterized_type(const asn1_parameterized_type& other) : asn1_type(other) { _types = other._types; }

asn1_parameterized_type::~asn1_parameterized_type() {}

asn1_parameterized_type& asn1_parameterized_type::operator=(const asn1_parameterized_type& other) {
    asn1_type::operator=(other);
    _types = other._types;
    return *this;
}

asn1_parameterized_type* asn1_parameterized_type::clone() { return new asn1_parameterized_type(*this); }

asn1_parameterized_type* asn1_parameterized_type::define(const asn1_paramtypes& types, const std::string& name, asn1_object* object) {
    auto obj = new asn1_parameterized_type(types, name, object);
    return obj;
}

asn1_parameterized_type* asn1_parameterized_type::define(const std::string& name, std::function<asn1_object*(asn1_parameterized_type*)> func) {
    auto templ = new asn1_parameterized_type({}, name, nullptr);
    if (func) {
        auto obj = func(templ);
        templ->set_object(obj);
    }
    return templ;
}

asn1_specialized_type* asn1_parameterized_type::specialize(const std::string& name, asn1_parameterized_type* type, const asn1_paramvalues& values) {
    if (type) {
        return type->specialize(name, values);
    } else {
        return nullptr;
    }
}

asn1_specialized_type* asn1_parameterized_type::specialize(const std::string& name, const asn1_paramvalues& values) {
    auto obj = new asn1_specialized_type(this, values, name, get_object()->clone());
    auto lambda = [this](asn1_object* item) -> void { item->get_constraints().update(); };
    asn1_visitor visitor(_module, lambda);
    visitor.visit(obj);
    return obj;
}

void asn1_parameterized_type::set_module(asn1_module* module) { _module = module; }

asn1_module* asn1_parameterized_type::get_module() const { return _module; }

asn1_paramtypes& asn1_parameterized_type::get_types() { return _types; }

asn1_parameterized_type& asn1_parameterized_type::add_paramtype(const std::string& paramtype, const std::string& paramname) {
    auto lambda = [](asn1_parameterized_type* p, const asn1_paramtype& item) -> return_t {
        return_t ret = errorcode_t::success;
        for (const auto& type : p->_types) {
            if (type == item) {
                ret = errorcode_t::already_exist;
                break;
            }
        }
        return ret;
    };

    asn1_paramtype item{paramtype, paramname};
    auto test = lambda(this, item);
    if (errorcode_t::success == test) {
        _types.push_back(std::move(item));
    }
    return *this;
}

void asn1_parameterized_type::clear() {
    _types.clear();
    // _deferred.clear();
}

void asn1_parameterized_type::represent(stream_t* s, const asn1_value*) const {
    s->printf("%s", get_name().c_str());
    s->printf(" {");
    size_t idx = 0;
    for (const auto& type : _types) {
        if (idx) s->printf(", ");
        type.represent(s, nullptr);
        ++idx;
    }
    s->printf("}");
    s->printf(" ::= ");
    get_object()->represent(s, nullptr);
}

bool asn1_parameterized_type::represent(binary_t* b, const asn1_value* value, uint16 flags) const { return true; }

}  // namespace io
}  // namespace hotplace
