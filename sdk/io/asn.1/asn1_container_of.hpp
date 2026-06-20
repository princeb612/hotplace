/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_container_of.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINEROF__
#define __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINEROF__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

class asn1_container_of : public asn1_type {
   public:
    virtual ~asn1_container_of();

    virtual asn1_container_of* clone();
    virtual asn1_container_of* addref();
    virtual void release();

   protected:
    asn1_container_of(asn1_entity_t entity, const std::string& name, asn1_entity_t item);
    asn1_container_of(asn1_entity_t entity, const std::string& name, asn1_object* object);

    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    // SET OF : Lexicographical encoded octet stream
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

   private:
};

}  // namespace io
}  // namespace hotplace

#endif
