/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1ENCODE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1ENCODE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_encode {
   public:
    asn1_encode();

    asn1_encode& null(binary_t& bin);
    asn1_encode& primitive(binary_t& bin, bool value);
    asn1_encode& primitive(binary_t& bin, int8 value);
    asn1_encode& primitive(binary_t& bin, uint8 value);
    asn1_encode& primitive(binary_t& bin, int16 value);
    asn1_encode& primitive(binary_t& bin, uint16 value);
    asn1_encode& primitive(binary_t& bin, int32 value);
    asn1_encode& primitive(binary_t& bin, uint32 value);
    asn1_encode& primitive(binary_t& bin, int64 value);
    asn1_encode& primitive(binary_t& bin, uint64 value);
#if defined __SIZEOF_INT128__
    asn1_encode& primitive(binary_t& bin, int128 value);
    asn1_encode& primitive(binary_t& bin, uint128 value);
#endif
    asn1_encode& primitive(binary_t& bin, float value);
    asn1_encode& primitive(binary_t& bin, double value);
    asn1_encode& primitive(binary_t& bin, asn1_type_t type, const std::string& value);
    asn1_encode& primitive(binary_t& bin, asn1_tag_t type, const std::string& value);
    asn1_encode& oid(binary_t& bin, const std::string& value);
    asn1_encode& reloid(binary_t& bin, const std::string& value);
    asn1_encode& encode(binary_t& bin, asn1_type_t type, const binary_t& value);
    asn1_encode& encode(binary_t& bin, asn1_type_t type, const variant& value);
    asn1_encode& encode(binary_t& bin, int tag, int class_number);

    asn1_encode& bitstring(binary_t& bin, const std::string& value);
    asn1_encode& generalstring(binary_t& bin, const std::string& value);
    asn1_encode& ia5string(binary_t& bin, const std::string& value);
    asn1_encode& octstring(binary_t& bin, const std::string& value);
    asn1_encode& printablestring(binary_t& bin, const std::string& value);
    asn1_encode& t61string(binary_t& bin, const std::string& value);
    asn1_encode& visiblestring(binary_t& bin, const std::string& value);

    asn1_encode& generalized_time(binary_t& bin, const datetime_t& dt);
    asn1_encode& generalized_time(basic_stream& bs, const datetime_t& dt);
    asn1_encode& utctime(binary_t& bin, const datetime_t& dt, int tzoffset = 0);
    asn1_encode& utctime(basic_stream& bs, const datetime_t& dt, int tzoffset = 0);

    asn1_encode& indef(binary_t& bin);
    asn1_encode& end_contents(binary_t& bin);

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
