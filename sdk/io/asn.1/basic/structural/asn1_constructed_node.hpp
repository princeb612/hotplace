/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constructed_node.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1CONTAINERNODE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1CONTAINERNODE__

#include <hotplace/sdk/io/asn.1/basic/structural/asn1_node.hpp>

namespace hotplace {
namespace io {

class asn1_constructed_node : public asn1_node {
   public:
    asn1_constructed_node(uint8 identifier, uint64 tag, uint64 len);
    asn1_constructed_node(const asn1_constructed_node& other);
    virtual ~asn1_constructed_node();

    asn1_constructed_node& operator=(const asn1_constructed_node& other);

    virtual asn1_constructed_node* clone();

    virtual bool is_leaf() const;

   protected:
   private:
};

}  // namespace io
}  // namespace hotplace

#endif
