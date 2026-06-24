/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_builtin_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1BUILTINTYPE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1BUILTINTYPE__

#include <hotplace/sdk/io/asn.1/basic/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @remarks
 *          BuiltinType ::=
 *           BitStringType
 *           | BooleanType
 *           | CharacterStringType
 *           | ChoiceType
 *           | EmbeddedPDVType
 *           | EnumeratedType
 *           | ExternalType
 *           | InstanceOfType
 *           | IntegerType
 *           | NullType
 *           | ObjectClassFieldType
 *           | ObjectIdentifierType
 *           | OctetStringType
 *           | RealType
 *           | RelativeOIDType
 *           | SequenceType
 *           | SequenceOfType
 *           | SetType
 *           | SetOfType
 *           | TaggedType
 * @example
 *          // sketch
 *          auto type = asn1_referenced_type::define("Type1", new asn1_builtin_type(asn1_entity_visiblestring));
 *          type->publish(&bs);  // Type1 ::= VisibleString
 *          auto value = type->instantiate();
 *          value->set("Jones");
 *          value->publish(&bin);  // 1A 05 4A 6F 6E 65 73
 *          value->release();
 *          type->release();
 */
class asn1_builtin_type : public asn1_type {
   public:
    // INTEGER
    asn1_builtin_type(asn1_entity_t entity);
    // name UTF8String
    asn1_builtin_type(const std::string& name, asn1_entity_t entity);
    asn1_builtin_type(const std::string& name, asn1_entity_t entity, const variant& value);
    virtual ~asn1_builtin_type();

    virtual asn1_builtin_type* clone();
    virtual asn1_builtin_type* addref();

    virtual asn1_entity_t get_component_entity() const;

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);
};

}  // namespace io
}  // namespace hotplace

#endif
