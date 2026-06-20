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

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
