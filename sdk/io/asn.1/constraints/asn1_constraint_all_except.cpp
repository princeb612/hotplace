/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_all_except.cpp
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
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_all_except.hpp>

namespace hotplace {
namespace io {

asn1_constraint_all_except::asn1_constraint_all_except(asn1_constraint* cons) : asn1_constraint(asn1_entity_constraint_except), _cons(cons) {
    if (nullptr == cons) {
        // throw exception(errorcode_t::invalid_parameter);
    }
    _cons->set_parent(this);
}

asn1_constraint_all_except::~asn1_constraint_all_except() {}

asn1_constraint_all_except::asn1_constraint_all_except(const asn1_constraint_all_except& other) : asn1_constraint(asn1_entity_constraint_except) { *this = other; }

asn1_constraint_all_except& asn1_constraint_all_except::operator=(const asn1_constraint_all_except& other) {
    _cons = other._cons->clone();
    _cons->set_parent(this);
    return *this;
}

asn1_constraint_all_except* asn1_constraint_all_except::clone() { return new asn1_constraint_all_except(*this); }

bool asn1_constraint_all_except::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_constraint_single:
        case asn1_entity_constraint_size:
        case asn1_entity_constraint_range:
        case asn1_entity_constraint_from:
        case asn1_entity_constraint_pattern:
        case asn1_entity_constraint_including:
        case asn1_entity_constraint_containing:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraint_all_except::addref() {
    asn1_constraint::addref();
    _cons->addref();
}

void asn1_constraint_all_except::release() {
    _cons->release();
    asn1_constraint::release();
}

void asn1_constraint_all_except::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    auto rparenthesis = _cons->is_set_family();

    s->printf("ALL EXCEPT ");
    if (rparenthesis) s->printf("(");
    _cons->represent(s, object, value);
    if (rparenthesis) s->printf(")");
}

}  // namespace io
}  // namespace hotplace
