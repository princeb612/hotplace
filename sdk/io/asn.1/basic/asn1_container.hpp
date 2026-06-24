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

#ifndef __HOTPLACE_SDK_IO_ASN1_BNASIC_ASN1CONTAINER__
#define __HOTPLACE_SDK_IO_ASN1_BNASIC_ASN1CONTAINER__

#include <hotplace/sdk/io/asn.1/basic/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SequenceType, SequenceOfType, SetType, SetOfType
 * @remarks
 *          // sketch
 *          asn1_named_type is removed
 *          instead asn1_object::is_named_type must be true
 */
class asn1_container : public asn1_type {
   public:
    virtual ~asn1_container();
    asn1_container& operator=(const asn1_container& other);

    virtual asn1_container* clone();
    virtual asn1_container* addref();
    virtual void release();

    // named type
    asn1_container& operator<<(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_container& add(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    // is_named_type MUST be true
    asn1_container& operator<<(const std::initializer_list<asn1_object*>& items);
    asn1_container& add(const std::initializer_list<asn1_object*>& items);
    asn1_container& operator<<(asn1_object* other);
    asn1_container& add(asn1_object* other);

   protected:
    asn1_container(asn1_entity_t entity, const std::string& name, asn1_object* object);
    asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<asn1_object*>& items);
    asn1_container(const asn1_container& other);

    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    /**
     * @remarks It returns true in most cases, but the CHOICE returns true only if processed.
     */
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

   private:
    std::list<asn1_object*> _list;             // 1..*
    std::multimap<size_t, asn1_object*> _map;  // SET, CHOICE : Lexicographical (order by tag)
};

}  // namespace io
}  // namespace hotplace

#endif
