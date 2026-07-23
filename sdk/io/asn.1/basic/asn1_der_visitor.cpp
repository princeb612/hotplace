/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_der_visitor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>

namespace hotplace {
namespace io {

asn1_der_visitor::asn1_der_visitor(binary_t* b, const asn1_value* value) : asn1_visitor(), _b(b), _value(value) {}

asn1_der_visitor::~asn1_der_visitor() {}

void asn1_der_visitor::visit(const asn1_object* object) { object->represent(get_binary(), _value); }

binary_t* asn1_der_visitor::get_binary() { return _b; }

}  // namespace io
}  // namespace hotplace
