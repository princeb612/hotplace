/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_der_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1DERVISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1DERVISOTOR__

#include <hotplace/sdk/io/asn.1/basic/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_der_visitor : public asn1_visitor {
   public:
    asn1_der_visitor(binary_t* b, const asn1_value* value = nullptr);
    virtual ~asn1_der_visitor();

    virtual void visit(const asn1_object* object);

   protected:
    binary_t* get_binary();

   private:
    binary_t* _b;
    const asn1_value* _value;
};

}  // namespace io
}  // namespace hotplace

#endif
