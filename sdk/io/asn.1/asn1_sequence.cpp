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

asn1_sequence::asn1_sequence(asn1_tag* tag) : asn1_container(tag) { _type = asn1_type_sequence; }

asn1_sequence::asn1_sequence(const std::string& name, asn1_tag* tag) : asn1_container(name, tag) { _type = asn1_type_sequence; }

asn1_sequence::asn1_sequence(const asn1_sequence& rhs) : asn1_container(rhs) { _type = asn1_type_sequence; }

asn1_object* asn1_sequence::clone() { return new asn1_sequence(*this); }

void asn1_sequence::represent(binary_t* b) {}

asn1_sequence_of::asn1_sequence_of(asn1_tag* tag) : asn1_container(tag) { _type = asn1_type_sequence_of; }

asn1_sequence_of::asn1_sequence_of(const std::string& name, asn1_tag* tag) : asn1_container(name, tag) { _type = asn1_type_sequence_of; }

asn1_sequence_of::asn1_sequence_of(const asn1_sequence_of& rhs) : asn1_container(rhs) { _type = asn1_type_sequence_of; }

asn1_object* asn1_sequence_of::clone() { return new asn1_sequence_of(*this); }

void asn1_sequence_of::represent(binary_t* b) {}

}  // namespace io
}  // namespace hotplace
