/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_enum.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1ENUM__
#define __HOTPLACE_SDK_IO_ASN1_ASN1ENUM__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   EnumeratedType ::= ENUMERATED "{" Enumerations "}"
 * @example
 *          // sketch
 *          auto type = asn1_referenced_type::define("Color", new asn1_enum({{"red", 0}, {"green", 1}, {"blue", 2}}));
 *          type->publish(&bs);  // Color ::= ENUMERATED {red(0), green(1), blue(2)}
 *          auto value = type->instantiate();
 *          value->set("green");   // 1
 *          value->publish(&bin);  // 0A 01 01
 *          value->release();
 *          type->release();
 */
class asn1_enum : public asn1_type {
   public:
    asn1_enum();
    asn1_enum(const std::string& name);
    asn1_enum(const std::initializer_list<std::pair<std::string, int>>& items);
    asn1_enum(const std::string& name, const std::initializer_list<std::pair<std::string, int>>& items);
    virtual ~asn1_enum();

    virtual asn1_enum* clone();
    virtual asn1_enum* addref();

    asn1_enum& add(const std::string& en, int value);
    asn1_enum& operator<<(const std::initializer_list<std::pair<std::string, int>>& items);
    asn1_enum& add(const std::initializer_list<std::pair<std::string, int>>& items);

    virtual asn1_entity_t get_component_entity() const;

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

   private:
    std::map<std::string, int> _enum;
    std::map<int, std::string> _reverse;
};

}  // namespace io
}  // namespace hotplace

#endif
