/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_primitive_node.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_primitive_node.hpp>

namespace hotplace {
namespace io {

asn1_primitive_node::asn1_primitive_node(uint8 identifier, uint64 tag, uint64 len, const byte_t* stream, size_t size, size_t pos) : asn1_node(identifier, tag, len) {
    if (stream && len && (pos < size) && (pos + len <= size)) {
        binary_append(_value, stream + pos, len);
    } else if (0 == len) {
        // do nothing
    } else {
        throw exception(errorcode_t::bad_data);
    }
}

asn1_primitive_node::asn1_primitive_node(const asn1_primitive_node& other) : asn1_node(other) { *this = other; }

asn1_primitive_node::~asn1_primitive_node() {}

asn1_primitive_node& asn1_primitive_node::operator=(const asn1_primitive_node& other) {
    asn1_node::operator=(other);
    _value = other._value;
    return *this;
}

asn1_primitive_node* asn1_primitive_node::clone() { return new asn1_primitive_node(*this); }

bool asn1_primitive_node::is_leaf() const { return true; }

const binary_t& asn1_primitive_node::get() const { return _value; }

bool asn1_primitive_node::is_container() { return false; }

}  // namespace io
}  // namespace hotplace
