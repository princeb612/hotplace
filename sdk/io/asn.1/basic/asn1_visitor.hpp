/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1VISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1VISOTOR__

#include <hotplace/sdk/base/nostd/set.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_visitor {
   public:
    asn1_visitor() = default;
    virtual ~asn1_visitor() = default;

    virtual void visit(asn1_object* object) = 0;
};

}  // namespace io
}  // namespace hotplace

#endif
