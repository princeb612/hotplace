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

#include <sdk/io/asn.1/asn1.hpp>

namespace hotplace {
namespace io {

asn1_encoder::asn1_encoder(binary_t* b) : _b(b) {}

void asn1_encoder::visit(asn1_object* object) { object->represent(get_binary()); }

binary_t* asn1_encoder::get_binary() { return _b; }

asn1_notation::asn1_notation(stream_t* s) : _s(s) {}

void asn1_notation::visit(asn1_object* object) { object->represent(get_stream()); }

stream_t* asn1_notation::get_stream() { return _s; }

}  // namespace io
}  // namespace hotplace
