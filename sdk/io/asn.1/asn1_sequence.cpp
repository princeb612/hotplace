/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_sequence.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <stdarg.h>

#include <hotplace/sdk/io/asn.1/asn1_sequence.hpp>

namespace hotplace {
namespace io {

asn1_sequence::asn1_sequence() : asn1_container(asn1_entity_sequence, "", nullptr) {}

asn1_sequence::asn1_sequence(const std::string& name) : asn1_container(asn1_entity_sequence, name, nullptr) {}

asn1_sequence::asn1_sequence(const std::initializer_list<asn1_entity_t>& items) : asn1_container(asn1_entity_sequence, "", items) {}

asn1_sequence::asn1_sequence(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items) : asn1_container(asn1_entity_sequence, "", items) {}

asn1_sequence::asn1_sequence(const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_sequence, "", items) {}

asn1_sequence::asn1_sequence(const std::string& name, const std::initializer_list<asn1_entity_t>& items) : asn1_container(asn1_entity_sequence, name, items) {}

asn1_sequence::asn1_sequence(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items)
    : asn1_container(asn1_entity_sequence, name, items) {}

asn1_sequence::asn1_sequence(const std::string& name, const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_sequence, name, items) {}

asn1_sequence::asn1_sequence(const asn1_sequence& other) : asn1_container(other) {}

asn1_sequence::~asn1_sequence() {}

asn1_sequence* asn1_sequence::clone() { return new asn1_sequence(*this); }

asn1_sequence_of::asn1_sequence_of() : asn1_container(asn1_entity_sequence_of, "", nullptr) {}

asn1_sequence_of::asn1_sequence_of(const std::string& name) : asn1_container(asn1_entity_sequence_of, name, nullptr) {}

asn1_sequence_of::asn1_sequence_of(const asn1_sequence_of& other) : asn1_container(other) {}

asn1_sequence_of* asn1_sequence_of::clone() { return new asn1_sequence_of(*this); }

}  // namespace io
}  // namespace hotplace
