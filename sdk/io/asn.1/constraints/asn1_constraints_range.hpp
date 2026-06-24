/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSRANGE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSRANGE__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

class asn1_constraints_range : public asn1_constraints {
   public:
    asn1_constraints_range();
    virtual ~asn1_constraints_range();
};

}  // namespace io
}  // namespace hotplace

#endif
