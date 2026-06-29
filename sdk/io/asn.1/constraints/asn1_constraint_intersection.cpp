/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_intersection.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_intersection.hpp>

namespace hotplace {
namespace io {

asn1_constraint_intersection::asn1_constraint_intersection(asn1_constraint* lhs, asn1_constraint* rhs)
    : asn1_constraint(asn1_entity_constraint_intersection), _lhs(lhs), _rhs(rhs) {
    if (nullptr == lhs || nullptr == rhs) {
        // throw exception(errorcode_t::invalid_parameter);
    }
    _lhs->set_parent(this);
    _rhs->set_parent(this);
}

asn1_constraint_intersection::~asn1_constraint_intersection() {}

asn1_constraint_intersection::asn1_constraint_intersection(const asn1_constraint_intersection& other) : asn1_constraint(asn1_entity_constraint_intersection) {
    *this = other;
}

asn1_constraint_intersection& asn1_constraint_intersection::operator=(const asn1_constraint_intersection& other) {
    _lhs = other._lhs->clone();
    _rhs = other._rhs->clone();
    _lhs->set_parent(this);
    _rhs->set_parent(this);
    return *this;
}

asn1_constraint_intersection* asn1_constraint_intersection::clone() { return new asn1_constraint_intersection(*this); }

bool asn1_constraint_intersection::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_constraint_single:
        case asn1_entity_constraint_size:
        case asn1_entity_constraint_range:
        case asn1_entity_constraint_from:
        case asn1_entity_constraint_pattern:
        case asn1_entity_constraint_including:
        case asn1_entity_constraint_containing:
        case asn1_entity_constraint_union:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraint_intersection::addref() {
    asn1_constraint::addref();
    _lhs->addref();
    _rhs->addref();
}

void asn1_constraint_intersection::release() {
    _lhs->release();
    _rhs->release();
    asn1_constraint::release();
}

void asn1_constraint_intersection::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    _lhs->represent(s, object, value);
    s->printf(" INTERSECTION ");
    _rhs->represent(s, object, value);
}

}  // namespace io
}  // namespace hotplace
