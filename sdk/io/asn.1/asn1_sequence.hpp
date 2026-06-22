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
 *          // sketch
 *          auto type = asn1_referenced_type::define("Type1", new asn1_sequence({{"name", asn1_entity_visiblestring}, {"ok", asn1_entity_boolean}}));
 *          type->publish(&bs);
 *          // Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}
 *          value = type->instantiate();
 *          (*value).set("name", "Jones").set("ok", true);
 *          value->publish(&bin);
 *          // 30 0A 1A 05 4A 6F 6E 65 73 01 01 FF
 *          value->release();
 *          type->release();
 */
class asn1_sequence : public asn1_container {
   public:
    asn1_sequence();
    asn1_sequence(const std::string& name);
    asn1_sequence(asn1_object* inner);
    asn1_sequence(const std::string& name, asn1_object* inner);
    asn1_sequence(const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_sequence(const std::initializer_list<asn1_object*>& items);
    asn1_sequence(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items);
    asn1_sequence(const std::string& name, const std::initializer_list<asn1_object*>& items);
    virtual ~asn1_sequence();

    virtual asn1_sequence* clone();
    virtual asn1_sequence* addref();

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
