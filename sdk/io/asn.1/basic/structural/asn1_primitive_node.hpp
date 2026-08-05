/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_primitive_node.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_STRUCTURAL_ASN1LEAFNODE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_STRUCTURAL_ASN1LEAFNODE__

#include <hotplace/sdk/io/asn.1/basic/structural/asn1_node.hpp>

namespace hotplace {
namespace io {

class asn1_primitive_node : public asn1_node {
   public:
    asn1_primitive_node(uint8 identifier, uint64 tag, uint64 len, const byte_t* stream, size_t size, size_t pos);
    asn1_primitive_node(const asn1_primitive_node& other);
    virtual ~asn1_primitive_node();

    asn1_primitive_node& operator=(const asn1_primitive_node& other);

    virtual asn1_primitive_node* clone();

    virtual bool is_leaf() const;
    const binary_t& get() const;

   protected:
    virtual bool is_container();

   private:
    binary_t _value;
};

}  // namespace io
}  // namespace hotplace

#endif
