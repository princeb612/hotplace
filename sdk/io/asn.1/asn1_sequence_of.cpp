/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_sequence_of.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <stdarg.h>

#include <hotplace/sdk/io/asn.1/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/asn1_sequence_of.hpp>

namespace hotplace {
namespace io {

asn1_sequence_of::asn1_sequence_of(asn1_entity_t entity) : asn1_sequence_of("", entity) {}

asn1_sequence_of::asn1_sequence_of(asn1_object* object) : asn1_sequence_of("", object) {}

asn1_sequence_of::asn1_sequence_of(const std::string& name, asn1_entity_t entity) : asn1_sequence_of(name, new asn1_builtin_type(entity)) {}

asn1_sequence_of::asn1_sequence_of(const std::string& name, asn1_object* object) : asn1_container_of(asn1_entity_sequence, name, object) {}

asn1_sequence_of::~asn1_sequence_of() {}

asn1_sequence_of* asn1_sequence_of::clone() { return new asn1_sequence_of(*this); }

asn1_sequence_of* asn1_sequence_of::addref() {
    asn1_container_of::addref();
    return this;
}

asn1_entity_t asn1_sequence_of::get_component_entity() const { return asn1_entity_sequence_of; }

}  // namespace io
}  // namespace hotplace
