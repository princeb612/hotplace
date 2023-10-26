/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

void binary_load(binary_t& bn, uint32 bnlen, byte_t* data, uint32 len) {
    bn.clear();
    bn.resize(bnlen);
    if (data) {
        if (len > bnlen) {
            len = bnlen;
        }
        memcpy(&bn[0] + (bnlen - len), data, len);
    }
}

}  // namespace io
}  // namespace hotplace
