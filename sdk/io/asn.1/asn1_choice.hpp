/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_choice.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1CHOICE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1CHOICE__

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   CHOICE
 * @example
 *          auto type = asn1_referenced_type::define("Person",
 *                          new asn1_sequence(new asn1_choice("id", {{"num", asn1_entity_integer}, {"name", asn1_entity_visiblestring}})));
 *          type->publish(&bs);  // Person ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}}
 *          auto value = type->instantiate();
 *          (*value).set("id.name", "Jones");
 *          value->publish(&bin);  // 30 07 1A 05 4A 6F 6E 65 73
 *          value->release();
 *          type->release();
 */
class asn1_choice : public asn1_container {
   public:
    asn1_choice();
    asn1_choice(const std::string& name);
    asn1_choice(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_choice(const std::initializer_list<asn1_object*>& items);
    asn1_choice(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_choice(const std::string& name, const std::initializer_list<asn1_object*>& items);
    virtual ~asn1_choice();

    virtual asn1_choice* clone();
    virtual asn1_choice* addref();

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
