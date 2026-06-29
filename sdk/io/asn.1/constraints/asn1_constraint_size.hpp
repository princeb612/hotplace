/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_size.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSIZE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSIZE__

#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

class asn1_constraint_size : public asn1_constraint {
   public:
    asn1_constraint_size(asn1_constraint* range);
    virtual ~asn1_constraint_size();

    asn1_constraint_size* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraint_size(const asn1_constraint_size& other);
    asn1_constraint_size& operator=(const asn1_constraint_size& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    asn1_constraint* _cons;
};

}  // namespace io
}  // namespace hotplace

#endif
