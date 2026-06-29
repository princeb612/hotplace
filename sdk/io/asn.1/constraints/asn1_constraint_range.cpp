/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_range.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_range.hpp>

namespace hotplace {
namespace io {

asn1_constraint_range::asn1_constraint_range(t_range_value<int> low, t_range_value<int> high) : asn1_constraint(asn1_entity_constraint_range), _low(low), _high(high) {}

asn1_constraint_range::~asn1_constraint_range() {}

asn1_constraint_range::asn1_constraint_range(const asn1_constraint_range& other) : asn1_constraint(asn1_entity_constraint_range) {
    _low = other._low;
    _high = other._high;
}

asn1_constraint_range& asn1_constraint_range::operator=(const asn1_constraint_range& other) {
    _low = other._low;
    _high = other._high;
    return *this;
}

asn1_constraint_range* asn1_constraint_range::clone() { return new asn1_constraint_range(*this); }

bool asn1_constraint_range::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_integer:
        case asn1_entity_real:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraint_range::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    auto parenthesis = false;
    auto parent = get_parent();
    if (parent) {
        auto entity = parent->get_entity();
        switch (entity) {
            case asn1_entity_constraint_intersection:
                parenthesis = true;
                break;
            default:
                break;
        }
    }

    if (parenthesis) {
        s->printf("(");
    }
    switch (_low.type) {
        case range_type_t::minvalue:
            s->printf("MIN");
            break;
        case range_type_t::value:
            s->printf("%i", _low.value);
            break;
        case range_type_t::maxvalue:
            s->printf("MAX");
            break;
    }
    if (_low != _high) {
        s->printf("..");
        switch (_high.type) {
            case range_type_t::minvalue:
                s->printf("MIN");
                break;
            case range_type_t::value:
                s->printf("%i", _high.value);
                break;
            case range_type_t::maxvalue:
                s->printf("MAX");
                break;
        }
    }
    if (parenthesis) {
        s->printf(")");
    }
}

}  // namespace io
}  // namespace hotplace
