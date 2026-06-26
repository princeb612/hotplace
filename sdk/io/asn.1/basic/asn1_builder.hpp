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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1BUILDER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1BUILDER__

#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>

namespace hotplace {
namespace io {

class asn1_builder {
   public:
    static asn1_builtin_type* build(asn1_entity_t entity, std::function<void(asn1_builtin_type*)> f = nullptr);
    static asn1_builtin_type* build(const std::string& name, asn1_entity_t entity, std::function<void(asn1_builtin_type*)> f = nullptr);
    static asn1_object* build(asn1_object* object, std::function<void(asn1_object*)> f = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
