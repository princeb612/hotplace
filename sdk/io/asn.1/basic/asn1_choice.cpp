/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_choice.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_choice.hpp>

namespace hotplace {
namespace io {

asn1_choice::asn1_choice() : asn1_container(asn1_entity_choice, "", nullptr) {}

asn1_choice::asn1_choice(const std::string& name) : asn1_container(asn1_entity_choice, name, nullptr) {}

asn1_choice::asn1_choice(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items) : asn1_container(asn1_entity_choice, "", items) {}

asn1_choice::asn1_choice(const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_choice, "", items) {}

asn1_choice::asn1_choice(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items)
    : asn1_container(asn1_entity_choice, name, items) {}

asn1_choice::asn1_choice(const std::string& name, const std::initializer_list<asn1_object*>& items) : asn1_container(asn1_entity_choice, name, items) {}

asn1_choice::~asn1_choice() {}

asn1_choice* asn1_choice::clone() { return new asn1_choice(*this); }

asn1_choice* asn1_choice::addref() {
    asn1_container::addref();
    return this;
}

}  // namespace io
}  // namespace hotplace
