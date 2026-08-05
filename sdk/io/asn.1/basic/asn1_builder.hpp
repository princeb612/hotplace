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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1SEMANTICBUILDER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1SEMANTICBUILDER__

#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

/**
 * builder
 */

enum asn1_builder_flag_t : uint32 {
    flag_is_leaf = (1 << 0),         // children == 0
    flag_as_sequence = (1 << 1),     // constructed as sequence
    flag_as_constructed = (1 << 2),  // constructed
};

class asn1_builder {
   public:
    asn1_builder();

    static asn1_object* build(uint8 ident, uint64 tag, uint32 flags = 0);

    static asn1_object* build(asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);
    static asn1_object* build(const std::string& name, asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);

    static asn1_object* build(asn1_object* object, std::function<void(asn1_object*)> f = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
