/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_bitstring.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_DETAIL_ASN1BITSTRING__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_DETAIL_ASN1BITSTRING__

#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief
 * @example
 *          auto type1 = asn1_referenced_type::define("Flags", new asn1_bitstring);
 *          // Flags ::= BIT STRING
 *          (*value).set("10101010");
 *          // 03 02 00 AA
 *
 *          auto type2 = asn1_referenced_type::define("Flags", new asn1_bitstring({{"read", 0}, {"write", 1}, {"execute", 2}}));
 *          // Flags ::= BIT STRING {read(0), write(1), execute(2)}
 *          (*value).set("read").set("execute");
 *          // 03 02 05 A0
 */
class asn1_bitstring : public asn1_builtin_type {
   public:
    asn1_bitstring();
    asn1_bitstring(const std::string& name);
    asn1_bitstring(const std::initializer_list<std::pair<std::string, int>> items);
    asn1_bitstring(const std::string& name, const std::initializer_list<std::pair<std::string, int>> items);
    virtual ~asn1_bitstring();

    virtual asn1_bitstring* clone();
    virtual asn1_bitstring* addref();

    asn1_bitstring& operator<<(const std::initializer_list<std::pair<std::string, int>> items);
    asn1_bitstring& add(const std::initializer_list<std::pair<std::string, int>> items);

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

   private:
    std::map<std::string, int> _nbl;
    std::map<int, std::string> _reverse;
};

}  // namespace io
}  // namespace hotplace

#endif
