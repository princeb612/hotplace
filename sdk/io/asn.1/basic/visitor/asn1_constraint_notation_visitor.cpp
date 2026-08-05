/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_notation_visitor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_constraint_visitor.hpp>

namespace hotplace {
namespace io {

asn1_constraint_notation_visitor::asn1_constraint_notation_visitor(stream_t* s, const asn1_object* object, const asn1_value* value)
    : _object(object), _s(s), _value(value) {}

asn1_constraint_notation_visitor::~asn1_constraint_notation_visitor() {}

void asn1_constraint_notation_visitor::visit(const asn1_constraint_t* cons) { cons->represent(get_stream(), _object, _value); }

stream_t* asn1_constraint_notation_visitor::get_stream() { return _s; }

}  // namespace io
}  // namespace hotplace
