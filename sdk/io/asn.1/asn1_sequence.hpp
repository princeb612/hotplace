/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_sequence.hpp
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

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceType
 * @example
 *          // snippet 1
 *          auto seq = new asn1_sequence;
 *          *seq << new asn1_builtin_type("name", asn1_entity_ia5string) << new asn1_builtin_type("ok", asn1_entity_boolean);
 *
 *          // snippet 2
 *          auto seq = new asn1_sequence(2, new asn1_builtin_type("name", asn1_entity_ia5string), new asn1_builtin_type("ok", asn1_entity_boolean));
 */
class asn1_sequence : public asn1_container {
   public:
    asn1_sequence();
    asn1_sequence(const std::string& name);
    asn1_sequence(const asn1_sequence& other);
    asn1_sequence(const std::initializer_list<asn1_entity_t>& items);
    asn1_sequence(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_sequence(const std::initializer_list<asn1_object*>& items);
    asn1_sequence(const std::string& name, const std::initializer_list<asn1_entity_t>& items);
    asn1_sequence(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_sequence(const std::string& name, const std::initializer_list<asn1_object*>& items);
    virtual ~asn1_sequence();

    asn1_sequence* clone();

   protected:
};

/**
 * @brief   SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 */
class asn1_sequence_of : public asn1_container {
   public:
    asn1_sequence_of();
    asn1_sequence_of(const std::string& name);
    asn1_sequence_of(const asn1_sequence_of& other);

    asn1_sequence_of* clone();

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
