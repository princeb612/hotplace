/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_named_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/asn1_named_type.hpp>

namespace hotplace {
namespace io {

asn1_named_type::asn1_named_type(const std::string& name, asn1_entity_t entity) : asn1_object(asn1_entity_named_type, name, new asn1_builtin_type(entity)) {}

asn1_named_type::asn1_named_type(const std::string& name, asn1_type* object) : asn1_object(asn1_entity_named_type, name, object) {}

asn1_named_type::~asn1_named_type() {}

asn1_named_type* asn1_named_type::clone() { return new asn1_named_type(*this); }

void asn1_named_type::represent(uint32 depth, stream_t* s) {
    s->printf("%s ", get_name().c_str());

    auto obj = get_object();
    if (obj) obj->represent(depth + 1, s);
}

void asn1_named_type::represent(uint32 depth, binary_t* b, asn1_value* value) {
    auto obj = get_object();
    if (obj) obj->represent(depth + 1, b, value);
}

}  // namespace io
}  // namespace hotplace
