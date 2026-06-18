/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_set.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_set.hpp>

namespace hotplace {
namespace io {

asn1_set::asn1_set() : asn1_container(asn1_entity_set, "", nullptr) {}

asn1_set::asn1_set(const std::string& name) : asn1_container(asn1_entity_set, name, nullptr) {}

asn1_set::asn1_set(const std::initializer_list<asn1_entity_t>& items) : asn1_container(asn1_entity_set, "", items) {}

asn1_set::asn1_set(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items) : asn1_container(asn1_entity_set, "", items) {}

asn1_set::asn1_set(const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_set, "", items) {}

asn1_set::asn1_set(const std::string& name, const std::initializer_list<asn1_entity_t>& items) : asn1_container(asn1_entity_set, name, items) {}

asn1_set::asn1_set(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items) : asn1_container(asn1_entity_set, name, items) {}

asn1_set::asn1_set(const std::string& name, const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_set, name, items) {}

asn1_set::asn1_set(const asn1_set& other) : asn1_container(other) {}

asn1_set::~asn1_set() {}

asn1_set* asn1_set::clone() { return new asn1_set(*this); }

asn1_set_of::asn1_set_of() : asn1_container(asn1_entity_set_of, "", nullptr) {}

asn1_set_of::asn1_set_of(const std::string& name) : asn1_container(asn1_entity_set_of, name, nullptr) {}

asn1_set_of::asn1_set_of(const asn1_set_of& other) : asn1_container(other) {}

asn1_set_of* asn1_set_of::clone() { return new asn1_set_of(*this); }

}  // namespace io
}  // namespace hotplace
