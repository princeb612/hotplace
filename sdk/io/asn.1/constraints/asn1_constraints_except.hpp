/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_except.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSEXCEPT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSEXCEPT__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

/**
 */
class asn1_constraints_except : public asn1_constraints {
   public:
    asn1_constraints_except(asn1_constraints* lhs, asn1_constraints* rhs);
    virtual ~asn1_constraints_except();

    asn1_constraints_except* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraints_except(const asn1_constraints_except& other);
    asn1_constraints_except& operator=(const asn1_constraints_except& other);

    virtual void represent(stream_t* s, asn1_value* value = nullptr);

   private:
    asn1_constraints* _lhs;
    asn1_constraints* _rhs;
};

}  // namespace io
}  // namespace hotplace

#endif
