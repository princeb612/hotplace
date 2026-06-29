/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_single_value.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_single_value.hpp>

namespace hotplace {
namespace io {

asn1_constraint_single_value::asn1_constraint_single_value(const variant& value) : asn1_constraint(asn1_entity_constraint_single), _v(value) {}

asn1_constraint_single_value::asn1_constraint_single_value(variant&& value) : asn1_constraint(asn1_entity_constraint_single), _v(std::move(value)) {}

asn1_constraint_single_value::~asn1_constraint_single_value() {}

asn1_constraint_single_value::asn1_constraint_single_value(const asn1_constraint_single_value& other) : asn1_constraint(asn1_entity_constraint_single) { *this = other; }

asn1_constraint_single_value& asn1_constraint_single_value::operator=(const asn1_constraint_single_value& other) {
    _v = other._v;
    return *this;
}

asn1_constraint_single_value* asn1_constraint_single_value::clone() { return new asn1_constraint_single_value(*this); }

bool asn1_constraint_single_value::is_applicable(asn1_entity_t entity) { return true; }

void asn1_constraint_single_value::represent(stream_t* s, asn1_object* object, asn1_value* value) { vtprintf(s, _v, vtprintf_style_t::vtprintf_style_asn1); }

}  // namespace io
}  // namespace hotplace
