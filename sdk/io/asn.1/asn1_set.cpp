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
 *  concept rule-based parser
 *
 */

#include <sdk/io/asn.1/asn1.hpp>

namespace hotplace {
namespace io {

asn1_set::asn1_set(const std::string& name, asn1_tagged* tag) : asn1_container(name, tag) { _type = asn1_type_set; }

void asn1_set::represent(binary_t* b) {}

asn1_set_of::asn1_set_of(const std::string& name, asn1_tagged* tag) : asn1_container(name, tag) { _type = asn1_type_set_of; }

void asn1_set_of::represent(binary_t* b) {}

}  // namespace io
}  // namespace hotplace
