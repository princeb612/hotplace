/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1CONSTRAINTVISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1CONSTRAINTVISOTOR__

#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/types.hpp>

namespace hotplace {
namespace io {

class asn1_constraint_visitor {
   public:
    ~asn1_constraint_visitor() = default;

    virtual void visit(const asn1_constraint_t* cons) = 0;
};

}  // namespace io
}  // namespace hotplace

#endif
