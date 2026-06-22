/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_sequence_of.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1SEQUENCEOF__
#define __HOTPLACE_SDK_IO_ASN1_ASN1SEQUENCEOF__

#include <hotplace/sdk/io/asn.1/asn1_container_of.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 * @example
 *          // sketch
 *          auto type = asn1_referenced_type::define("Numbers", new asn1_sequence_of(asn1_entity_integer));
 *          type->publish(&bs);
 *          // Numbers ::= SEQUENCE OF INTEGER
 *          value = type->instantiate();
 *          (*value).set({1, 2, 3});
 *          // 30 09 02 01 01 02 01 02 02 01 03
 *          value->release();
 *          type->release();
 */
class asn1_sequence_of : public asn1_container_of {
   public:
    asn1_sequence_of(asn1_entity_t entity);
    asn1_sequence_of(asn1_object* object);
    asn1_sequence_of(const std::string& name, asn1_entity_t entity);
    asn1_sequence_of(const std::string& name, asn1_object* object);
    virtual ~asn1_sequence_of();

    virtual asn1_sequence_of* clone();
    virtual asn1_sequence_of* addref();

    virtual asn1_entity_t get_component_entity() const;

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
