/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_referenced_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_referenced_type.hpp>

namespace hotplace {
namespace io {

asn1_referenced_type::asn1_referenced_type(asn1_entity_t entity, const std::string& name, asn1_object* object) : asn1_type(entity, name, object, nullptr) {}

asn1_referenced_type::asn1_referenced_type(const std::string& name) : asn1_type(asn1_entity_referenced_type, name, nullptr, nullptr) {}

asn1_referenced_type::~asn1_referenced_type() {}

asn1_referenced_type* asn1_referenced_type::clone() { return new asn1_referenced_type(*this); }

asn1_referenced_type* asn1_referenced_type::addref() {
    asn1_object::addref();
    return this;
}

asn1_referenced_type* asn1_referenced_type::define(const std::string& name, asn1_entity_t entity) {
    return new asn1_referenced_type(asn1_entity_referenced_type, name, new asn1_builtin_type(entity));
}

asn1_referenced_type* asn1_referenced_type::define(const std::string& name, asn1_object* object) {
    return new asn1_referenced_type(asn1_entity_referenced_type, name, object);
}

bool asn1_referenced_type::is_reference() const { return get_object() ? false : true; }

bool asn1_referenced_type::is_definition() const { return get_object() ? true : false; }

void asn1_referenced_type::represent(uint32 depth, stream_t* s, asn1_value* value) {
    s->printf("%s", get_name().c_str());

    if ((nullptr == get_parent()) && is_definition()) {
        auto obj = get_object();
        s->printf(" ::= ");
        obj->represent(depth + 1, s, value);
    }
}

bool asn1_referenced_type::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    debug_print(depth);

    if (is_definition()) get_object()->represent(depth + 1, b, value);

    return true;
}

}  // namespace io
}  // namespace hotplace
