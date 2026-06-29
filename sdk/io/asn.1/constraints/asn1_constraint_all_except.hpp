/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_all_except.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTALLEXCEPT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTALLEXCEPT__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 */
class asn1_constraint_all_except : public asn1_constraint {
   public:
    asn1_constraint_all_except(asn1_constraint* cons);
    virtual ~asn1_constraint_all_except();

    asn1_constraint_all_except* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraint_all_except(const asn1_constraint_all_except& other);
    asn1_constraint_all_except& operator=(const asn1_constraint_all_except& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    asn1_constraint* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
