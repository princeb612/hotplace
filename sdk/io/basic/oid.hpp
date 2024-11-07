
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_OID__
#define __HOTPLACE_SDK_IO_BASIC_OID__

#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

// ITU-T X.660 ISO/IEC 9834-1, ISO/IEC 6523 Structure for the identification of organizations and organization parts
// object identifier - node1 0..2, node2 0..39, nodeN positive
// relative object identifier - nodeN positive
typedef std::vector<unsigned> oid_t;

void str_to_oid(const std::string& value, oid_t& oid);
void str_to_oid(const char* value, size_t size, oid_t& oid);
void oid_to_str(const oid_t& value, basic_stream& oid);

}  // namespace io
}  // namespace hotplace

#endif
