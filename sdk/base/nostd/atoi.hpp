/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   atoi.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_ATOI__
#define __HOTPLACE_SDK_BASE_NOSTD_ATOI__

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <limits>

namespace hotplace {

/**
 * @brief   atoi (int128)
 * @sample
 *          int128 i = 170141183460469231731687303715884105727; // warning
 *          i = t_atoi<int128>("170141183460469231731687303715884105727");
 *          i = t_atoi<int128>("-170141183460469231731687303715884105728");
 *
 *          basic_stream bs;
 *          bs.printf("%40I128i %032I128x", i, i);
 *
 *          //  170141183460469231731687303715884105727 7fffffffffffffffffffffffffffffff
 *          // -170141183460469231731687303715884105728 80000000000000000000000000000000
 */
template <typename TYPE>
TYPE t_atoi_n(const char* value, size_t size) {
    return_t ret = errorcode_t::success;
    TYPE res = 0;

    __try2 {
        if (nullptr == value || 0 == size) {
            __leave2;
        }

        size_t i = 0;
        bool is_negative = false;

        if (value[i] == '-') {
            is_negative = true;
            ++i;
        } else if (value[i] == '+') {
            ++i;
        }

        for (; i < size; ++i) {
            const char c = value[i];
            if (0 == std::isdigit(static_cast<unsigned char>(c))) {
                ret = errorcode_t::bad_data;
                break;
            }

            int digit = c - '0';

            res = res * 10 - digit;
        }

        if (errorcode_t::bad_data == ret) {
            res = 0;
            __leave2;
        }

        if (!is_negative) {
            res = -res;
        }
    }
    __finally2 {}
    return res;
}

template <typename TYPE>
TYPE t_atoi(const std::string& value) {
    return t_atoi_n<TYPE>(value.c_str(), value.size());
}

/**
 * @return  unsigned integer value
 * @sa      t_atoi for signed/unsigned
 */
template <typename T>
T t_htoi(const char* hex) {
    T value = 0;
    const char* p = hex;
    char c = 0;
    int i = 0;
    while (0 != (c = *p++)) {
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

}  // namespace hotplace

#endif
