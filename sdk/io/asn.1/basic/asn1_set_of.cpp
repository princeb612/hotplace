/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_set_of.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_set_of.hpp>

namespace hotplace {
namespace io {

asn1_set_of::asn1_set_of(asn1_entity_t entity) : asn1_set_of("", entity) {}

asn1_set_of::asn1_set_of(asn1_object* object) : asn1_set_of("", object) {}

asn1_set_of::asn1_set_of(const std::string& name, asn1_entity_t entity) : asn1_set_of(name, new asn1_builtin_type(entity)) {}

asn1_set_of::asn1_set_of(const std::string& name, asn1_object* object) : asn1_container_of(asn1_entity_set, name, object) {}

asn1_set_of::~asn1_set_of() {}

asn1_set_of* asn1_set_of::clone() { return new asn1_set_of(*this); }

asn1_set_of* asn1_set_of::addref() {
    asn1_container_of::addref();
    return this;
}

asn1_entity_t asn1_set_of::get_component_entity() const { return asn1_entity_set_of; }

}  // namespace io
}  // namespace hotplace
