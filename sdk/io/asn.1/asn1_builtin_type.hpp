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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1BUILTINTYPE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1BUILTINTYPE__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

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
 */
class asn1_builtin_type : public asn1_type {
   public:
    // INTEGER
    asn1_builtin_type(asn1_entity_t entity);
    // name UTF8String
    asn1_builtin_type(const std::string& name, asn1_entity_t entity);
    virtual ~asn1_builtin_type();

    virtual asn1_builtin_type* clone();
    virtual asn1_builtin_type* addref();

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);
};

}  // namespace io
}  // namespace hotplace

#endif
