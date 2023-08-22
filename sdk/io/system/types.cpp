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

uint64 htonll (uint64 value)
{
    uint64 ret_value = 0;

    if (is_little_endian ()) {
        const uint32 high_part = htonl (static_cast<uint32>(value >> 32));
        const uint32 low_part = htonl (static_cast<uint32>(value & 0xFFFFFFFF));

        ret_value = (static_cast<uint64>(low_part) << 32) | high_part;
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint64 ntohll (uint64 value)
{
    return htonll (value); /* wo htonl operations */
}

#if defined __SIZEOF_INT128__
int128 atoi128 (std::string const & in)
{
    return_t ret = errorcode_t::success;
    int128 res = 0;

    __try2
    {
        size_t i = 0;
        int sign = 0;

        if (in[i] == '-') {
            ++i;
            sign = -1;
        }

        if (in[i] == '+') {
            ++i;
        }

        for (; i < in.size (); ++i) {
            const char c = in[i];
            if (not std::isdigit (c)) {
                ret = errorcode_t::bad_data;
                break;
            }
            res *= 10;
            res += (c - '0');
        }

        if (errorcode_t::success != ret) {
            res = 0;
            __leave2;
        }

        if (sign < 0) {
            res = -res;
        }
    }
    __finally2
    {
    }
    return res;
}

uint128 hton128 (uint128 value)
{
    uint128 ret_value = 0;

    if (is_little_endian ()) {
        ipaddr_byteorder lhs;
        ipaddr_byteorder rhs;
        rhs.t128 = value;
        lhs.t32[0] = htonl (rhs.t32[3]);
        lhs.t32[1] = htonl (rhs.t32[2]);
        lhs.t32[2] = htonl (rhs.t32[1]);
        lhs.t32[3] = htonl (rhs.t32[0]);
        ret_value = lhs.t128;
    } else {
        ret_value = value;
    }

    return ret_value;
}

uint128 ntoh128 (uint128 value)
{
    return hton128 (value);
}

#endif


}
}  // namespace
