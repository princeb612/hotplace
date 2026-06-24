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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1REFERENCEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1REFERENCEDTYPE__

#include <hotplace/sdk/io/asn.1/basic/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ReferencedType ::= DefinedType | UsefulType | SelectionType | TypeFromObject | ValueSetFromObjects
 * @example
 *          // sketch
 *
 *          // definitions
 *          // Type1 ::= VisibleString
 *          auto type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
 *          // Type2 ::= [Application 3] implicit Type1
 *          auto type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, type1->clone()));
 *          // Type3 ::= [2] Type2
 *          auto type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, type2->clone()));
 *          // Type4 ::= [Application 7] implicit Type3
 *          auto type4 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, type3->clone()));
 *          // Type5 ::= [2] implicit Type2
 *          auto type5 = asn1_referenced_type::define("Type5", new asn1_tagged_type(asn1_class_context, 2, asn1_implicit, type2->clone()));
 *
 *          // reference
 *          // Type1
 *          auto type = new asn1_referenced_type("Type1");  // using context pool (asn1 class)
 */
class asn1_referenced_type : public asn1_type {
   public:
    /**
     * reference
     */
    asn1_referenced_type(const std::string& name);
    virtual ~asn1_referenced_type();

    virtual asn1_referenced_type* clone();
    virtual asn1_referenced_type* addref();

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
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);
};

}  // namespace io
}  // namespace hotplace

#endif
