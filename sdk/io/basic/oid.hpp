
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_OID__
#define __HOTPLACE_SDK_IO_BASIC_OID__

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/types.hpp>

namespace hotplace {
namespace io {

// ITU-T X.660 ISO/IEC 9834-1, ISO/IEC 6523 Structure for the identification of organizations and organization parts
// object identifier - node1 0..2, node2 0..39, nodeN positive
// relative object identifier - nodeN positive
struct oid_elem {
    uint32 arc;
    std::string name;
    bool operator==(const oid_elem& other) const { return (arc == other.arc) && (name == other.name); }
};
typedef std::vector<uint32> oid_t;
typedef std::vector<oid_elem> asn1oid_t;

// dot notation         2.16.840.1.101.3.4.2.3
// ASN.1 text notation  {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashalgs(2) SHA-512(3)}
// URN notation         urn:oid:2.16.840.1.101.3.4.2.3
// OID-IRI / URI        /Joint-ISO-ITU-T/Country/Us/Organization/Gov/Csor/nistAlgorithm/hashalgs/Sha512

HOTPLACE_IO_API void str_to_oid(const std::string& value, oid_t& oid);
HOTPLACE_IO_API void str_to_oid(const char* value, size_t size, oid_t& oid);
HOTPLACE_IO_API void asn1text_to_oid(const char* value, size_t size, oid_t& oid);
HOTPLACE_IO_API void asn1text_to_oid(const char* value, size_t size, asn1oid_t& oid);
HOTPLACE_IO_API void oid_to_str(const oid_t& value, basic_stream& oid);

}  // namespace io
}  // namespace hotplace

#endif
