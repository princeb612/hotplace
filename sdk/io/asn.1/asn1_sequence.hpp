/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1SEQUENCE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1SEQUENCE__

#include <sdk/io/asn.1/asn1_container.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceType
 * @example
 *          // snippet 1
 *          auto seq = new asn1_sequence;
 *          *seq << new asn1_object("name", asn1_type_ia5string) << new asn1_object("ok", asn1_type_boolean);
 *
 *          // snippet 2
 *          auto seq = new asn1_sequence(2, new asn1_object("name", asn1_type_ia5string), new asn1_object("ok", asn1_type_boolean));
 */
class asn1_sequence : public asn1_container {
   public:
    asn1_sequence(asn1_tag* tag = nullptr);
    asn1_sequence(const std::string& name, asn1_tag* tag = nullptr);
    asn1_sequence(const asn1_sequence& rhs);
    asn1_sequence(int count, ...);
    asn1_sequence(asn1_tag* tag, int count, ...);

    virtual asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

/**
 * @brief   SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 */
class asn1_sequence_of : public asn1_container {
   public:
    asn1_sequence_of(asn1_tag* tag = nullptr);
    asn1_sequence_of(const std::string& name, asn1_tag* tag = nullptr);
    asn1_sequence_of(const asn1_sequence_of& rhs);

    virtual asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
