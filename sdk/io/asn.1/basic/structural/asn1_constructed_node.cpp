/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constructed_node.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/structural/asn1_constructed_node.hpp>

namespace hotplace {
namespace io {

asn1_constructed_node::asn1_constructed_node(uint8 identifier, uint64 tag, uint64 len) : asn1_node(identifier, tag, len) {}

asn1_constructed_node::asn1_constructed_node(const asn1_constructed_node& other) : asn1_node(other) { *this = other; }

asn1_constructed_node::~asn1_constructed_node() {}

asn1_constructed_node& asn1_constructed_node::operator=(const asn1_constructed_node& other) {
    asn1_node::operator=(other);
    return *this;
}

asn1_constructed_node* asn1_constructed_node::clone() { return new asn1_constructed_node(*this); }

bool asn1_constructed_node::is_leaf() const { return false; }

}  // namespace io
}  // namespace hotplace
