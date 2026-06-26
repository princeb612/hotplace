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

#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

asn1_constraints::asn1_constraints(asn1_entity_t entity) : _entity(entity), _parent(nullptr) { _shared.make_share(this); }

asn1_constraints::~asn1_constraints() {}

asn1_constraints::asn1_constraints(const asn1_constraints& other) { *this = other; }

asn1_constraints& asn1_constraints::operator=(const asn1_constraints& other) {
    _entity = other._entity;
    return *this;
}

asn1_constraints* asn1_constraints::clone() { return new asn1_constraints(*this); }

bool asn1_constraints::is_applicable(asn1_object* object) { return object ? is_applicable(object->get_component_entity()) : false; }

bool asn1_constraints::is_applicable(asn1_entity_t entity) { return false; }

asn1_entity_t asn1_constraints::get_entity() { return _entity; }

bool asn1_constraints::is_set_family() {
    bool ret = false;
    switch (_entity) {
        case asn1_entity_constraints_union:
        case asn1_entity_constraints_intersection:
        case asn1_entity_constraints_except:
        case asn1_entity_constraints_all_except:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

asn1_constraints* asn1_constraints::get_parent() { return _parent; }

void asn1_constraints::set_parent(asn1_constraints* parent) { _parent = parent; }

void asn1_constraints::addref() { _shared.addref(); }

void asn1_constraints::release() { _shared.delref(); }

void asn1_constraints::accept(asn1_constraints_visitor* v) { v->visit(this); }

void asn1_constraints::represent(stream_t* s, asn1_value* value) {}

}  // namespace io
}  // namespace hotplace
