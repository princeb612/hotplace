/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_single_value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSSINGLE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSSINGLE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

/**
 */
class asn1_constraints_single_value : public asn1_constraints {
   public:
    asn1_constraints_single_value(const variant& value);
    asn1_constraints_single_value(variant&& value);
    virtual ~asn1_constraints_single_value();

    asn1_constraints_single_value* clone();

    virtual bool is_applicable(asn1_entity_t entity);

   protected:
    asn1_constraints_single_value(const asn1_constraints_single_value& other);
    asn1_constraints_single_value& operator=(const asn1_constraints_single_value& other);

    virtual void represent(stream_t* s, asn1_value* value = nullptr);

   private:
    variant _v;
};

}  // namespace io
}  // namespace hotplace

#endif
