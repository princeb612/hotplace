/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_integer.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_DETAIL_ASN1INTEGER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_DETAIL_ASN1INTEGER__

#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>

namespace hotplace {
namespace io {

/**
 * IntegerType ::= INTEGER | INTEGER "{" NamedNumberList "}"
 * @example
 *              // sketch
 *              auto type = asn1_referenced_type::define("Number", new asn1_integer);
 *              // Number ::= INTEGER
 *              type->release();
 *
 *              // sketch - NamedNumberList
 *              auto type = asn1_referenced_type::define("Location", new asn1_integer({{"homeOffice", 0}, {"fieldOffice", 1}, {"roving", 2}}));
 *              type->publish(&bs);  // Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)}
 *              auto value = type->instantiate();
 *              value->set("homeOffice");
 *              value->publish(&bin);
 *              value->set(0);
 *              value->publish(&bin);
 *              value->set(30);
 *              value->publish(&bin);
 *              value->release();
 *              type->release();
 */
class asn1_integer : public asn1_builtin_type {
   public:
    // INTEGER
    asn1_integer();
    asn1_integer(const std::string& name);
    // INTEGER "{" NamedNumberList "}"
    asn1_integer(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items);
    asn1_integer(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items);
    virtual ~asn1_integer();

    virtual asn1_integer* clone();
    virtual asn1_integer* addref();

    asn1_integer& operator<<(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items);
    asn1_integer& add(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items);

   protected:
    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

   private:
    std::map<std::string, asn1_native_int_t> _nnl;
    std::map<asn1_native_int_t, std::string> _reverse;
};

}  // namespace io
}  // namespace hotplace

#endif
