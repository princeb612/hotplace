/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <sdk/io/asn.1/asn1_object.hpp>
#include <sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1_basic_encoding_visitor::asn1_basic_encoding_visitor(binary_t* b) : _b(b) {}

void asn1_basic_encoding_visitor::visit(asn1_object* object) { object->represent(get_binary()); }

binary_t* asn1_basic_encoding_visitor::get_binary() { return _b; }

asn1_notation_visitor::asn1_notation_visitor(stream_t* s) : _s(s) {}

void asn1_notation_visitor::visit(asn1_object* object) { object->represent(get_stream()); }

stream_t* asn1_notation_visitor::get_stream() { return _s; }

}  // namespace io
}  // namespace hotplace
