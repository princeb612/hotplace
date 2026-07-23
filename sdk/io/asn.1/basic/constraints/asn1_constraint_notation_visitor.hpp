/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_notation_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINTNOTATIONVISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_CONSTRAINTS_ASN1CONSTRAINTNOTATIONVISOTOR__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/asn1_constraint_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/constraints/types.hpp>

namespace hotplace {
namespace io {

class asn1_constraint_notation_visitor : public asn1_constraint_visitor {
   public:
    asn1_constraint_notation_visitor(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr);
    virtual ~asn1_constraint_notation_visitor();

    virtual void visit(const asn1_constraint_t* cons);

   protected:
    stream_t* get_stream();

   private:
    const asn1_object* _object;
    stream_t* _s;
    const asn1_value* _value;
};

}  // namespace io
}  // namespace hotplace

#endif
