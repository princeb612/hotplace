/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/types.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {
namespace io {

uint64 hton64(uint64 value) {
    uint64 ret_value = 0;

    if (is_little_endian()) {
        const uint32 high_part = htonl(static_cast<uint32>(value >> 32));
        const uint32 low_part = htonl(static_cast<uint32>(value & 0xFFFFFFFF));

        ret_value = (static_cast<uint64>(low_part) << 32) | high_part;
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint64 ntoh64(uint64 value) { return hton64(value); /* wo htonl operations */ }

#if defined __SIZEOF_INT128__
int128 atoi128(std::string const& in) { return t_atoi<int128>(in); }

uint128 atou128(std::string const& in) { return t_atoi<uint128>(in); }

uint128 hton128(uint128 value) {
    uint128 ret_value = 0;

    if (is_little_endian()) {
        ipaddr_byteorder lhs;
        ipaddr_byteorder rhs;
        rhs.t128 = value;
        lhs.t32[0] = htonl(rhs.t32[3]);
        lhs.t32[1] = htonl(rhs.t32[2]);
        lhs.t32[2] = htonl(rhs.t32[1]);
        lhs.t32[3] = htonl(rhs.t32[0]);
        ret_value = lhs.t128;
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint128 ntoh128(uint128 value) { return hton128(value); }

#endif

}  // namespace io
}  // namespace hotplace
