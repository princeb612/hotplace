/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_from.cpp
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
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_from.hpp>

namespace hotplace {
namespace io {

asn1_constraint_from::asn1_constraint_from(asn1_constraint* cons) : asn1_constraint(asn1_entity_constraint_size), _cons(cons) {
    if (nullptr == cons) {
        throw exception(errorcode_t::not_specified);
    }
}

asn1_constraint_from::~asn1_constraint_from() {}

asn1_constraint_from::asn1_constraint_from(const asn1_constraint_from& other) : asn1_constraint(asn1_entity_constraint_size) { *this = other; }

asn1_constraint_from& asn1_constraint_from::operator=(const asn1_constraint_from& other) {
    _cons = other._cons->clone();
    return *this;
}

asn1_constraint_from* asn1_constraint_from::clone() { return new asn1_constraint_from(*this); }

bool asn1_constraint_from::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_bitstring:
        case asn1_entity_octstring:
        case asn1_entity_cstring:
        case asn1_entity_sequence_of:
        case asn1_entity_set_of:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraint_from::addref() {
    asn1_constraint::addref();
    _cons->addref();
}

void asn1_constraint_from::release() {
    _cons->release();
    asn1_constraint::release();
}

void asn1_constraint_from::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    s->printf("FROM (");
    _cons->represent(s, object, value);
    s->printf(")");
}

}  // namespace io
}  // namespace hotplace
