/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_named_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1NAMEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1NAMEDTYPE__

#include <hotplace/sdk/io/asn.1/asn1_object.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   NamedType ::= identifier Type
 * @example
 *          // name VisibleString
 *          auto name = new asn1_named_type("name", asn1_entity_visiblestring);
 *
 *          // SEQUENCE {name IA5String, ok BOOLEAN}
 *          auto seq = new asn1_sequence;
 *          *seq << new asn1_named_type("name", asn1_entity_ia5string) << new asn1_named_type("ok", asn1_entity_boolean);
 */
class asn1_named_type : public asn1_object {
   public:
    asn1_named_type(const std::string& name, asn1_entity_t entity);
    asn1_named_type(const std::string& name, asn1_type* object);
    virtual ~asn1_named_type();

    asn1_named_type* clone();

    virtual void represent(uint32 depth, stream_t* s);
    virtual void represent(uint32 depth, binary_t* b, asn1_value* value = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
