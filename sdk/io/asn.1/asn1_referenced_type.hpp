/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_referenced_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1REFERENCEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1REFERENCEDTYPE__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ReferencedType ::= DefinedType | UsefulType | SelectionType | TypeFromObject | ValueSetFromObjects
 * @remarks
 *          // definitions
 *          // Type1 ::= VisibleString
 *          // Type2 ::= [Application 3] implicit Type1
 *          // Type3 ::= [2] Type2
 *          // Type4 ::= [Application 7] implicit Type3
 *          // Type5 ::= [2] implicit Type2
 *
 *          // reference
 *          Type1
 */
class asn1_referenced_type : public asn1_type {
   public:
    /**
     * reference
     */
    asn1_referenced_type(const std::string& name);
    virtual ~asn1_referenced_type();

    asn1_referenced_type* clone();

    /**
     * definition
     *
     */
    static asn1_referenced_type* define(const std::string& name, asn1_entity_t entity);
    static asn1_referenced_type* define(const std::string& name, asn1_object* object);

    bool is_reference() const;
    bool is_definition() const;

   protected:
    asn1_referenced_type(asn1_entity_t entity, const std::string& name = "", asn1_object* object = nullptr);

    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual void represent(uint32 depth, binary_t* b, asn1_value* value = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
