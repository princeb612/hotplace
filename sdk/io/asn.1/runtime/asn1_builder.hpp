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

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1BUILDER__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1BUILDER__

#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

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
    static asn1_object* buildtag(uint8 ident, uint64 tag, uint8 mode = asn1_automatic);
    static asn1_object* buildtag(const std::string& type, uint64 tag, uint8 mode = asn1_automatic);

    static asn1_object* build(asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);
    static asn1_object* build(const std::string& name, asn1_entity_t entity, std::function<void(asn1_object*)> f = nullptr);

    static asn1_object* build(asn1_object* object, std::function<void(asn1_object*)> f = nullptr);

    static return_t build(const parse_tree* pt, asn1_object** object);
};

}  // namespace io
}  // namespace hotplace

#endif
