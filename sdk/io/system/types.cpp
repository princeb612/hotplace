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
namespace io {

#if defined __SIZEOF_INT128__

int128 atoi128(std::string const& in) { return t_atoi<int128>(in); }

uint128 atou128(std::string const& in) { return t_atoi<uint128>(in); }

#endif

uint32_24_t::uint32_24_t() { memset(_value.data, 0, RTL_FIELD_SIZE(uint24_t, data)); }

uint32_24_t::uint32_24_t(byte_t* p, size_t size) {
    size_t len = RTL_FIELD_SIZE(uint24_t, data);
    if (size >= len) {
        memcpy(_value.data, p, len);
    } else {
        memset(_value.data, 0, len);
    }
}

uint32_24_t::uint32_24_t(uint32 value) { set(value); }

uint32 uint32_24_t::get() {
    uint32 value = 0;
    b24_i32(_value, value);
    return value;
}

return_t uint32_24_t::set(uint32 value) { return i32_b24(_value, value); }

uint32_24_t& uint32_24_t::operator=(uint32 value) {
    set(value);
    return *this;
}

}  // namespace io
}  // namespace hotplace
