/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/endian.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {

uint64 hton64(uint64 value) {
    uint64 ret_value = 0;

    if (is_little_endian()) {
        ret_value = convert_endian(value);
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint64 ntoh64(uint64 value) { return hton64(value); /* wo htonl operations */ }

#if defined __SIZEOF_INT128__

uint128 hton128(uint128 value) {
    uint128 ret_value = 0;

    if (is_little_endian()) {
        ret_value = convert_endian(value);
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint128 ntoh128(uint128 value) { return hton128(value); }

#endif

}  // namespace hotplace
