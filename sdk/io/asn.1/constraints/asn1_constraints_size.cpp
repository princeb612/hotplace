/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_size.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints_size.hpp>

namespace hotplace {
namespace io {

asn1_constraints_size::asn1_constraints_size(int begin, int end) : asn1_constraints(asn1_entity_constraints_size), _r(begin, end) {}

asn1_constraints_size::asn1_constraints_size(const t_range_t<int>& r) : asn1_constraints(asn1_entity_constraints_size), _r(r) {}

asn1_constraints_size::asn1_constraints_size(t_range_t<int>&& r) : asn1_constraints(asn1_entity_constraints_size), _r(std::move(r)) {}

asn1_constraints_size::~asn1_constraints_size() {}

asn1_constraints_size::asn1_constraints_size(const asn1_constraints_size& other) : asn1_constraints(asn1_entity_constraints_size) { *this = other; }

asn1_constraints_size& asn1_constraints_size::operator=(const asn1_constraints_size& other) {
    _r = other._r;
    return *this;
}

asn1_constraints_size* asn1_constraints_size::clone() { return new asn1_constraints_size(*this); }

bool asn1_constraints_size::is_applicable(asn1_entity_t entity) {
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

void asn1_constraints_size::represent(stream_t* s, asn1_value* value) { s->printf("SIZE(%i..%i)", _r.begin, _r.end); }

}  // namespace io
}  // namespace hotplace
