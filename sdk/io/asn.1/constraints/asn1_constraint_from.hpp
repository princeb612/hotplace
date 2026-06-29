/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_from.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTFROM__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTFROM__

#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * for each ch
 *     if ch not in alphabet
 *         reject
 */
class asn1_constraint_from : public asn1_constraint {
   public:
    asn1_constraint_from(asn1_constraint* range);
    virtual ~asn1_constraint_from();

    asn1_constraint_from* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraint_from(const asn1_constraint_from& other);
    asn1_constraint_from& operator=(const asn1_constraint_from& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    asn1_constraint* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
