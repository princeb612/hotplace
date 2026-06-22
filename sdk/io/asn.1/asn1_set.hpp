/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_set.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1SET__
#define __HOTPLACE_SDK_IO_ASN1_ASN1SET__

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SetType
 * @sample
 *          auto type = new asn1_set({{"z", asn1_entity_boolean}, {"a", asn1_entity_integer}});;
 *          type->publish(&bs);
 *          // SET {z BOOLEAN, a INTEGER}
 *          auto value = type->instantiate();
 *          (*value).set("z", true).set("a", 5);
 *          value->publish(&bin);
 *          // 31 06 01 01 FF 02 01 05
 *          value->release();
 *          type->release();
 */
class asn1_set : public asn1_container {
   public:
    asn1_set();
    asn1_set(const std::string& name);
    asn1_set(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_set(const std::initializer_list<asn1_object*>& items);
    asn1_set(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_set(const std::string& name, const std::initializer_list<asn1_object*>& items);
    virtual ~asn1_set();

    virtual asn1_set* clone();
    virtual asn1_set* addref();

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
