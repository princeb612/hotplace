/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_tagged_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1TAGGEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1TAGGEDTYPE__

#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
 * @remarks
 *          // type assignment
 *          // Type1 ::= VisibleString
 *
 *          // tagged type
 *          // Type2 ::= [Application 3] implicit Type1
 *          // Type3 ::= [2] Type2
 *          // Type4 ::= [Application 7] implicit Type3
 *          // Type5 ::= [2] implicit Type2
 */
class asn1_tagged_type : public asn1_type {
   public:
    asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_entity_t entity);
    asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_object* object);
    asn1_tagged_type(asn1_tag* tag, asn1_entity_t entity);
    asn1_tagged_type(asn1_tag* tag, asn1_object* object);
    virtual ~asn1_tagged_type();

    virtual asn1_tagged_type* clone();
    virtual asn1_tagged_type* addref();

    asn1_tag* get_tag() const;

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual void represent(uint32 depth, binary_t* b, asn1_value* value = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
