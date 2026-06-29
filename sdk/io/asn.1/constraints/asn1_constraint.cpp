/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint.cpp
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
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

asn1_constraint::asn1_constraint(asn1_entity_t entity) : _entity(entity), _parent(nullptr) { _shared.make_share(this); }

asn1_constraint::~asn1_constraint() {}

asn1_constraint::asn1_constraint(const asn1_constraint& other) { *this = other; }

asn1_constraint& asn1_constraint::operator=(const asn1_constraint& other) {
    _entity = other._entity;
    return *this;
}

asn1_constraint* asn1_constraint::clone() { return new asn1_constraint(*this); }

bool asn1_constraint::is_applicable(asn1_object* object) { return object ? is_applicable(object->get_component_entity()) : false; }

bool asn1_constraint::is_applicable(asn1_entity_t entity) { return false; }

asn1_entity_t asn1_constraint::get_entity() { return _entity; }

bool asn1_constraint::is_set_family() {
    bool ret = false;
    switch (_entity) {
        case asn1_entity_constraint_union:
        case asn1_entity_constraint_intersection:
        case asn1_entity_constraint_except:
        case asn1_entity_constraint_all_except:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

asn1_constraint* asn1_constraint::get_parent() { return _parent; }

void asn1_constraint::set_parent(asn1_constraint* parent) { _parent = parent; }

void asn1_constraint::addref() { _shared.addref(); }

void asn1_constraint::release() { _shared.delref(); }

void asn1_constraint::accept(asn1_constraint_visitor* v) { v->visit(this); }

void asn1_constraint::represent(stream_t* s, asn1_object* object, asn1_value* value) {}

}  // namespace io
}  // namespace hotplace
