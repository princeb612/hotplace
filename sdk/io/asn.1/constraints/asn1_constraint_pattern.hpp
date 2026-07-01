/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_pattern.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTPATTERN__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTPATTERN__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

template <typename T>
class asn1_constraint_pattern : public asn1_constraint_base<T> {
   public:
    asn1_constraint_pattern() : asn1_constraint_base<T>(asn1_entity_constraint_pattern) {}
    virtual ~asn1_constraint_pattern() = default;
};

}  // namespace io
}  // namespace hotplace

#endif
