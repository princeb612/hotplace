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
#include <hotplace/sdk/base/system/uint.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {

return_t b48_i64(const byte_t* p, uint8 len, uint64& value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == p) || (len < 6)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint64 value_n = 0;
        byte_t* value_p = (byte_t*)&value_n;
        memcpy(value_p + 2, p, 6);
        value = ntoh64(value_n);
    }
    __finally2 {}

    return ret;
}

return_t i64_b48(byte_t* p, uint8 len, uint64 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == p) || (len < 6)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (value > 0x0000ffffffffffff) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        uint64 value_n = hton64(value);
        byte_t* value_p = (byte_t*)&value_n;
        memcpy(p, value_p + 2, 6);
    }
    __finally2 {}

    return ret;
}

uint48_t::uint48_t() : t_uint_custom_t<uint64, 6>() {}

uint48_t::uint48_t(const uint48_t& rhs) : t_uint_custom_t<uint64, 6>(rhs) {}

uint48_t::uint48_t(const byte_t* p, size_t size) : t_uint_custom_t<uint64, 6>(p, size) {}

uint48_t::uint48_t(uint64 v) : t_uint_custom_t<uint64, 6>() { set(v); }

return_t uint48_t::hton(byte_t* p, uint8 len, const uint64& value) { return i64_b48(p, len, value); }

return_t uint48_t::ntoh(const byte_t* p, uint8 len, uint64& value) { return b48_i64(p, len, value); }

return_t b48_i64(const uint48_t& u, uint64& value) { return b48_i64(u.data, RTL_FIELD_SIZE(uint48_t, data), value); }

return_t i64_b48(uint48_t& u, uint64 value) { return i64_b48(u.data, RTL_FIELD_SIZE(uint48_t, data), value); }

}  // namespace hotplace
