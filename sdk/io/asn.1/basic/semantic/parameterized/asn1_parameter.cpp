/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parameter.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameter.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_specialized_type.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>

namespace hotplace {
namespace io {

asn1_parameter::asn1_parameter(asn1_parameterized_type* templ, const std::string& name, const std::string& param)
    : asn1_type(asn1_entity_parameter, name), _templ(templ), _param(param) {
    if (nullptr == templ) {
        throw exception(errorcode_t::not_specified);
    }
    templ->add_paramtype(param);
    // templ->add(this);
    _module = templ->get_module();
}

asn1_parameter::asn1_parameter(const asn1_parameter& other) : asn1_type(other) { *this = other; }

asn1_parameter::~asn1_parameter() {}

asn1_parameter& asn1_parameter::operator=(const asn1_parameter& other) {
    asn1_type::operator=(other);
    _templ = other._templ;
    _param = other._param;
    _vt = other._vt;
    _module = other._module;
    return *this;
}

asn1_object* asn1_parameter::clone() {
    auto root = get_root();
    if (is_kind_of(root, asn1_entity_specialized_type)) {
        auto spec = (asn1_specialized_type*)root;
        auto advisor = asn1_advisor::get_instance();
        asn1_object* obj = nullptr;
        std::string specname;
        auto test = spec->lookup_name(_param, specname);
        if (test) {
            auto entity = advisor->get_entity(specname);
            if (asn1_entity_unknown != entity) {
                obj = asn1_builder::build(get_name(), entity);
            } else {
                auto module = get_module();
                if (module) {
                    obj = module->get(specname);
                }
            }
        }
        return obj;
    } else {
        return new asn1_parameter(*this);
    }
}

asn1_parameterized_type* asn1_parameter::get_parameterized_type() const { return _templ; }

void asn1_parameter::represent(stream_t* s, const asn1_value* value) const { s->printf("%s %s", get_name().c_str(), _param.c_str()); }

bool asn1_parameter::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    //
    return true;
}

void asn1_parameter::set(asn1_specialized_type* spec) { _spec = spec; }

asn1_specialized_type* asn1_parameter::get_specialized_type() const { return _spec; }

void asn1_parameter::set_module(asn1_module* module) { _module = module; }

asn1_module* asn1_parameter::get_module() const { return _module; }

}  // namespace io
}  // namespace hotplace
