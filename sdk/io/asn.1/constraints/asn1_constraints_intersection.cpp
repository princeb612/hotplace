/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_intersection.cpp
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
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints_intersection.hpp>

namespace hotplace {
namespace io {

asn1_constraints_intersection::asn1_constraints_intersection(asn1_constraints* lhs, asn1_constraints* rhs)
    : asn1_constraints(asn1_entity_constraints_intersection), _lhs(lhs), _rhs(rhs) {
    if (nullptr == lhs || nullptr == rhs) {
        // throw exception(errorcode_t::invalid_parameter);
    }
    _lhs->set_parent(this);
    _rhs->set_parent(this);
}

asn1_constraints_intersection::~asn1_constraints_intersection() {}

asn1_constraints_intersection::asn1_constraints_intersection(const asn1_constraints_intersection& other) : asn1_constraints(asn1_entity_constraints_intersection) {
    *this = other;
}

asn1_constraints_intersection& asn1_constraints_intersection::operator=(const asn1_constraints_intersection& other) {
    _lhs = other._lhs->clone();
    _rhs = other._rhs->clone();
    _lhs->set_parent(this);
    _rhs->set_parent(this);
    return *this;
}

asn1_constraints_intersection* asn1_constraints_intersection::clone() { return new asn1_constraints_intersection(*this); }

bool asn1_constraints_intersection::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_constraints_single:
        case asn1_entity_constraints_size:
        case asn1_entity_constraints_range:
        case asn1_entity_constraints_from:
        case asn1_entity_constraints_pattern:
        case asn1_entity_constraints_including:
        case asn1_entity_constraints_containing:
        case asn1_entity_constraints_union:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraints_intersection::addref() {
    asn1_constraints::addref();
    _lhs->addref();
    _rhs->addref();
}

void asn1_constraints_intersection::release() {
    asn1_constraints::release();
    _lhs->release();
    _rhs->release();
}

void asn1_constraints_intersection::represent(stream_t* s, asn1_value* value) {
    _lhs->represent(s, value);
    s->printf(" INTERSECTION ");
    _rhs->represent(s, value);
}

}  // namespace io
}  // namespace hotplace
