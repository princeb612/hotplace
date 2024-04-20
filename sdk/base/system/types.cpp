/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/system/types.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {

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

return_t b24_i32(byte_t const* p, uint8 len, uint32& value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == p) || (len < 3)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 value_n = 0;
        byte_t* value_p = (byte_t*)&value_n;
        memcpy(value_p + 1, p, 3);
        value = ntoh32(value_n);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t i32_b24(byte_t* p, uint8 len, uint32 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == p) || (len < 3)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (value > 0x00ffffff) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        uint32 value_n = hton32(value);
        byte_t* value_p = (byte_t*)&value_n;
        memcpy(p, value_p + 1, 3);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t b24_i32(uint24_t const& u, uint32& value) { return b24_i32(u.data, RTL_FIELD_SIZE(uint24_t, data), value); }

return_t i32_b24(uint24_t& u, uint32 value) { return i32_b24(u.data, RTL_FIELD_SIZE(uint24_t, data), value); }

}  // namespace hotplace
