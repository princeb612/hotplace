/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_range.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints_range.hpp>

namespace hotplace {
namespace io {

asn1_constraints_range::asn1_constraints_range(int begin, int end) : asn1_constraints(asn1_entity_constraints_range), _r(begin, end) {}

asn1_constraints_range::asn1_constraints_range(const t_range_t<int>& r) : asn1_constraints(asn1_entity_constraints_range), _r(r) {}

asn1_constraints_range::asn1_constraints_range(t_range_t<int>&& r) : asn1_constraints(asn1_entity_constraints_range), _r(std::move(r)) {}

asn1_constraints_range::~asn1_constraints_range() {}

asn1_constraints_range::asn1_constraints_range(const asn1_constraints_range& other) : asn1_constraints(asn1_entity_constraints_range) { *this = other; }

asn1_constraints_range& asn1_constraints_range::operator=(const asn1_constraints_range& other) {
    _r = other._r;
    return *this;
}

asn1_constraints_range* asn1_constraints_range::clone() { return new asn1_constraints_range(*this); }

bool asn1_constraints_range::is_applicable(asn1_entity_t entity) {
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

void asn1_constraints_range::represent(stream_t* s, asn1_value* value) {
    auto parenthesis = false;
    auto parent = get_parent();
    if (parent) {
        auto entity = parent->get_entity();
        switch (entity) {
            case asn1_entity_constraints_intersection:
                parenthesis = true;
                break;
            default:
                break;
        }
    }

    if (parenthesis) {
        s->printf("(");
    }
    s->printf("%i..%i", _r.begin, _r.end);
    if (parenthesis) {
        s->printf(")");
    }
}

}  // namespace io
}  // namespace hotplace
