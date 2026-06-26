/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_except.cpp
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
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints_except.hpp>

namespace hotplace {
namespace io {

asn1_constraints_except::asn1_constraints_except(asn1_constraints* lhs, asn1_constraints* rhs) : asn1_constraints(asn1_entity_constraints_except), _lhs(lhs), _rhs(rhs) {
    if (nullptr == lhs || nullptr == rhs) {
        // throw exception(errorcode_t::invalid_parameter);
    }
    _lhs->set_parent(this);
    _rhs->set_parent(this);
}

asn1_constraints_except::~asn1_constraints_except() {}

asn1_constraints_except::asn1_constraints_except(const asn1_constraints_except& other) : asn1_constraints(asn1_entity_constraints_except) { *this = other; }

asn1_constraints_except& asn1_constraints_except::operator=(const asn1_constraints_except& other) {
    _lhs = other._lhs->clone();
    _rhs = other._rhs->clone();
    _lhs->set_parent(this);
    _rhs->set_parent(this);
    return *this;
}

asn1_constraints_except* asn1_constraints_except::clone() { return new asn1_constraints_except(*this); }

bool asn1_constraints_except::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_constraints_single:
        case asn1_entity_constraints_size:
        case asn1_entity_constraints_range:
        case asn1_entity_constraints_from:
        case asn1_entity_constraints_pattern:
        case asn1_entity_constraints_including:
        case asn1_entity_constraints_containing:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraints_except::addref() {
    asn1_constraints::addref();
    _lhs->addref();
    _rhs->addref();
}

void asn1_constraints_except::release() {
    asn1_constraints::release();
    _lhs->release();
    _rhs->release();
}

void asn1_constraints_except::represent(stream_t* s, asn1_value* value) {
    auto lparenthesis = _lhs->is_set_family();
    auto rparenthesis = _rhs->is_set_family();

    if (lparenthesis) s->printf("(");
    _lhs->represent(s, value);
    if (lparenthesis) s->printf(")");
    s->printf(" EXCEPT ");
    if (rparenthesis) s->printf("(");
    _rhs->represent(s, value);
    if (rparenthesis) s->printf(")");
}

}  // namespace io
}  // namespace hotplace
