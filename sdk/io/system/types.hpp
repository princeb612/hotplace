/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_TYPES__
#define __HOTPLACE_SDK_IO_SYSTEM_TYPES__

#include <sdk/base.hpp>

namespace hotplace {
namespace io {

/**
 * host order to network order (64bits)
 */
uint64 hton64(uint64 value);
uint64 ntoh64(uint64 value);

#if defined __SIZEOF_INT128__

/**
 * atoi (int128)
 */
template <typename TYPE>
TYPE t_atoi(std::string const& in) {
    return_t ret = errorcode_t::success;
    TYPE res = 0;

    __try2 {
        size_t i = 0;
        int sign = 0;

        if (in[i] == '-') {
            ++i;
            sign = -1;
        }

        if (in[i] == '+') {
            ++i;
        }

        for (; i < in.size(); ++i) {
            const char c = in[i];
            if (not std::isdigit(c)) {
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
    __finally2 {
        // do nothing
    }
    return res;
}

template <typename T>
T t_htoi(const char* hex) {
    T value = 0;
    const char* p = hex;
    char c = 0;
    int i = 0;
    while (c = *p++) {
        value <<= 4;
        if ('0' <= c && c <= '9') {
            i = c - '0';
        } else if ('A' <= c && c <= 'F') {
            i = c - 'A' + 10;
        } else if ('a' <= c && c <= 'f') {
            i = c - 'a' + 10;
        }
        value += i;
    }
    return value;
}

int128 atoi128(std::string const& in);
uint128 atou128(std::string const& in);

typedef union _ipaddr_byteorder {
    uint128 t128;
    uint32 t32[4];
} ipaddr_byteorder;
/**
 * host order to network order (128bits)
 */
uint128 hton128(uint128 value);
uint128 ntoh128(uint128 value);

#endif

template <typename T, typename function_hton>
void t_to_binary(T i, binary_t& bin) {
    i = function_hton(i);
    byte_t* b = (byte_t*)&i;
    bin.insert(bin.end(), b, b + sizeof(i));
}

}  // namespace io
}  // namespace hotplace

#endif
