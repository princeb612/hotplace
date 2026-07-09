/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_builder.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1BUILDER__
#define __HOTPLACE_SDK_IO_ASN1_ASN1BUILDER__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_builder {
   public:
    asn1_builder();
    ~asn1_builder() = default;

    static asn1_object* build(asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);

   protected:
   private:
};

}  // namespace io
}  // namespace hotplace

#endif
