/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

asn1_constraints::asn1_constraints(asn1_entity_t entity) : _entity(entity) { _shared.make_share(this); }

asn1_constraints::~asn1_constraints() {}

bool asn1_constraints::is_applicable(asn1_object* object) { return object ? is_applicable(object->get_entity()) : false; }

bool asn1_constraints::is_applicable(asn1_entity_t entity) { return false; }

asn1_entity_t asn1_constraints::get_entity() { return _entity; }

void asn1_constraints::addref() { _shared.addref(); }

void asn1_constraints::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
