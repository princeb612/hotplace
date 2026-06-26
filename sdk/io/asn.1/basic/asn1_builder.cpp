/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>

namespace hotplace {
namespace io {

asn1_builtin_type* asn1_builder::build(asn1_entity_t entity, std::function<void(asn1_builtin_type*)> f) { return build("", entity, f); }

asn1_builtin_type* asn1_builder::build(const std::string& name, asn1_entity_t entity, std::function<void(asn1_builtin_type*)> f) {
    asn1_builtin_type* object = nullptr;
    if (entity < asn1_entity_syntax) {
        object = new asn1_builtin_type(name, entity);
        if (object && f) {
            f(object);
        }
    }
    return object;
}

asn1_object* build(asn1_object* object, std::function<void(asn1_object*)> f) {
    if (object && f) {
        f(object);
    }
    return object;
}

}  // namespace io
}  // namespace hotplace
