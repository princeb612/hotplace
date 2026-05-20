/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   capacity.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_CAPACITY__
#define __HOTPLACE_SDK_BASE_NOSTD_CAPACITY__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

/**
 * @brief   byte capacity for signed integer
 * @sa      byte_capacity for unsigned integer
 * @remarks
 *          min -(1 << (8 * n - 1))
 *          max (1 << (8 * n - 1)) - 1
 *
 *          e.g. if n = 1, -2^7 ~ 2^7 - 1
 *
 *          1 bytes : -128 ~ 127
 *          2 bytes : -32768 ~ 32767 (exclude -128 ~ 127)
 *          3 bytes : -8388608 ~ 8388607 (exclude -32768 ~ 32767)
 *          4 bytes : -2147483648 ~ 2147483647 (exclude -8388608 ~ 8388607)
 *          5 bytes : -549755813888 ~ 549755813887 (exclude -2147483648 ~ 2147483647)
 *          6 bytes : -140737488355328 ~ 140737488355327 (exclude -549755813888 ~ 549755813887)
 *          7 bytes : -36028797018963968 ~ 36028797018963967 (exclude -140737488355328 ~ 140737488355327)
 *          8 bytes : -9223372036854775808 ~ 9223372036854775807 (exclude -36028797018963968 ~ 36028797018963967)
 *          ...
 * @example
 *          int byte_size = t_byte_capacity_signed<int128>(t_atoi<int128>("170141183460469231731687303715884105727"));
 */
template <typename signed_type>
int t_byte_capacity_signed(signed_type v) {
    int len = 1;
    if (v < 0) {
        v = ~v;  // 2's complement
    }
    while (v >>= 1) {
        len++;
    }
    return (len + 8) / 8;
}

static inline int byte_capacity(int16 v) { return t_byte_capacity_signed<int16>(v); }

static inline int byte_capacity(int32 v) { return t_byte_capacity_signed<int32>(v); }

static inline int byte_capacity(int64 v) { return t_byte_capacity_signed<int64>(v); }

#if defined __SIZEOF_INT128__
static inline int byte_capacity(int128 v) { return t_byte_capacity_signed<int128>(v); }
#endif

}  // namespace hotplace

#endif
