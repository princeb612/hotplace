/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_container.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINER__
#define __HOTPLACE_SDK_IO_ASN1_ASN1CONTAINER__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceType, SequenceOfType, SetType, SetOfType
 */
class asn1_container : public asn1_type {
   public:
    virtual ~asn1_container();
    asn1_container& operator=(const asn1_container& other);

    virtual asn1_container* clone();
    virtual asn1_container* addref();
    virtual void release();

    asn1_container& operator<<(asn1_object* other);
    asn1_container& add(std::function<asn1_object*(asn1_container*)> func);

   protected:
    asn1_container(asn1_entity_t entity, const std::string& name, asn1_object* object);
    asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<asn1_entity_t>& items);
    asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<asn1_object*>& items);
    asn1_container(const asn1_container& other);

    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual void represent(uint32 depth, binary_t* b, asn1_value* value = nullptr);

   private:
    std::list<asn1_object*> _list;
    std::map<size_t, asn1_object*> _map;
};

}  // namespace io
}  // namespace hotplace

#endif
