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
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>

namespace hotplace {
namespace io {

asn1_parameter::asn1_parameter(asn1_parameterized_type* templ, const std::string& name, const std::string& param)
    : asn1_type(asn1_entity_parameter, name), _templ(templ), _param(param) {
    if (nullptr == templ) {
        throw exception(errorcode_t::not_specified);
    }
    templ->add_paramtype(param);
}

asn1_parameter::asn1_parameter(const asn1_parameter& other) : asn1_type(other) { *this = other; }

asn1_parameter::~asn1_parameter() {}

asn1_parameter& asn1_parameter::operator=(const asn1_parameter& other) {
    asn1_type::operator=(other);
    _templ = other._templ;
    _param = other._param;
    _vt = other._vt;
    return *this;
}

asn1_object* asn1_parameter::clone() { return new asn1_parameter(*this); }

// asn1_object* asn1_parameter::bind(asn1_module* module) {
//     asn1_object* obj = nullptr;
//     const auto& types = get_parameterized_type()->get_types();
//     const auto& values = get_parameterized_type()->get_values();
//     auto advisor = asn1_advisor::get_instance();
//     if (types.size() == values.size()) {
//         size_t idx = 0;
//         for (const auto& type : types) {
//             if (type.name == _param) {
//                 auto entity = advisor->get_entity(type.name);
//                 if (asn1_entity_unknown != entity) {
//                     obj = asn1_builder::build(get_name(), entity);
//                 } else if (module) {
//                     obj = module->get(type.name);
//                 }
//                 break;
//             }
//             ++idx;
//         }
//     }
//     return obj;
// }

asn1_parameterized_type* asn1_parameter::get_parameterized_type() const { return _templ; }

void asn1_parameter::represent(stream_t* s, const asn1_value* value) const { s->printf("%s %s", get_name().c_str(), _param.c_str()); }

bool asn1_parameter::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    //
    return true;
}

}  // namespace io
}  // namespace hotplace
