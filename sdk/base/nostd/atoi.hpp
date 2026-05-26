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
 *
 *          // c++ standard overflow
 *          auto i0 = t_atoi<int8>("-1");
 *          _logger->writeln("%i", i0);
 *          _test_case.assert(i0 == int8(-1), __FUNCTION__, "atoi #0");
 *          auto i1 = t_atoi<int8>("-129");  // int8 -128..127
 *          _logger->writeln("%i", i1);
 *          _test_case.assert(i1 == int8(-129), __FUNCTION__, "atoi #1");
 *          auto i2 = t_atoi<int8>("-128");
 *          _logger->writeln("%i", i2);
 *          _test_case.assert(i2 == int8(-128), __FUNCTION__, "atoi #2");
 *          auto i3 = t_atoi<int16>("-129");
 *          _logger->writeln("%i", i3);
 *          _test_case.assert(i3 == int16(-129), __FUNCTION__, "atoi #3");
 *          auto i4 = t_atoi<uint8>("-1");
 *          _logger->writeln("%u", i4);
 *          _test_case.assert(i4 == uint8(-1), __FUNCTION__, "atoi #4");
 *          auto i5 = t_atoi<uint8>("129");
 *          _logger->writeln("%i", i5);
 *          _test_case.assert(i5 == uint8(129), __FUNCTION__, "atoi #5");
 *
 */
template <typename TYPE>
TYPE t_atoi_n(const char* value, size_t size) {
    if (value == nullptr || size == 0) return 0;

    size_t i = 0;
    bool invert_sign = true;

    if (value[i] == '-') {
        invert_sign = false;
        ++i;
    } else if (value[i] == '+') {
        ++i;
    }

    TYPE res = 0;

    for (; i < size; ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (std::isdigit(c) == 0) return 0;

        const TYPE digit = static_cast<TYPE>(c - '0');
        res = static_cast<TYPE>(res * 10 - digit);
    }

    if (invert_sign) {
        res = static_cast<TYPE>(0 - res);
    }

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
