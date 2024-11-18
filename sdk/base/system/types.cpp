/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/types.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {

return_t b24_i32(const byte_t* p, uint8 len, uint32& value) {
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

return_t b24_i32(const uint24_t& u, uint32& value) { return b24_i32(u.data, RTL_FIELD_SIZE(uint24_t, data), value); }

return_t i32_b24(uint24_t& u, uint32 value) { return i32_b24(u.data, RTL_FIELD_SIZE(uint24_t, data), value); }

}  // namespace hotplace
