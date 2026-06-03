/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   endian.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_ENDIAN__
#define __HOTPLACE_SDK_BASE_SYSTEM_ENDIAN__

#include <hotplace/sdk/base/nostd/traits.hpp>

namespace hotplace {

#if defined __GNUC__

#if defined __MINGW32__ || defined __MINGW64__

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN__
#define __BIG_ENDIAN
#define BIG_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN
#define LITTLE_ENDIAN
#else
//
#endif

#else

#include <endian.h>

#endif  // __MINGW32__

#else  // _MSC_VER

#define LITTLE_ENDIANESS 0x41424344UL
#define BIG_ENDIANESS 0x44434241UL
#define PDP_ENDIANESS 0x42414443UL
#define ENDIAN_ORDER ('ABCD')

#define __ORDER_LITTLE_ENDIAN__ LITTLE_ENDIANESS
#define __ORDER_BIG_ENDIAN__ BIG_ENDIANESS

#if ENDIAN_ORDER == LITTLE_ENDIANESS
#define __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN
#define LITTLE_ENDIAN
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#elif ENDIAN_ORDER == BIG_ENDIANESS
#define __BIG_ENDIAN__
#define __BIG_ENDIAN
#define BIG_ENDIAN
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
#elif ENDIAN_ORDER == PDP_ENDIANESS
#define __PDP_ENDIAN__
#define __PDP_ENDIAN
#define PDP_ENDIAN
#else
#endif

#endif

static inline bool is_big_endian(void) {
    union {
        uint32 i;
        char c[4];
    } bint = {0x01020304};

    return bint.c[0] == 1;
}

static inline bool is_little_endian(void) {
    union {
        uint32 i;
        char c[4];
    } bint = {0x01020304};

    return bint.c[0] != 1;
}

/*
 * @brief   convert byte order
 */

namespace detail {

template <typename T, size_t SIZE = sizeof(T)>
struct endian_transformer {
    static inline T transform(T value) {
        T res = 0;
        if (is_little_endian()) {
            using half_type = typename custom::half_type_traits<SIZE>::type;

            half_type mask = ~half_type(0);
            half_type low = static_cast<half_type>(value & mask);
            half_type high = static_cast<half_type>((value >> (SIZE << 2)) & mask);

            half_type conv_low = endian_transformer<half_type>::transform(high);
            half_type conv_high = endian_transformer<half_type>::transform(low);

            res = ((T)conv_high << (SIZE << 2)) | conv_low;
        } else {
            res = value;
        }
        return res;
    }
};

template <typename T>
struct endian_transformer<T, 1> {
    static inline T transform(T value) { return value; }
};

}  // namespace detail

inline uint16 hton16(uint16 value) { return detail::endian_transformer<uint16>::transform(value); }
inline uint32 hton32(uint32 value) { return detail::endian_transformer<uint32>::transform(value); }
inline uint64 hton64(uint64 value) { return detail::endian_transformer<uint64>::transform(value); }
#if defined __SIZEOF_INT128__
inline uint128 hton128(uint128 value) { return detail::endian_transformer<uint128>::transform(value); }
#endif

inline uint16 ntoh16(uint16 value) { return detail::endian_transformer<uint16>::transform(value); }
inline uint32 ntoh32(uint32 value) { return detail::endian_transformer<uint32>::transform(value); }
inline uint64 ntoh64(uint64 value) { return detail::endian_transformer<uint64>::transform(value); }
#if defined __SIZEOF_INT128__
inline uint128 ntoh128(uint128 value) { return detail::endian_transformer<uint128>::transform(value); }
#endif

template <typename T>
T convert_endian(T value) {
    return detail::endian_transformer<T>::transform(value);
}

}  // namespace hotplace

#endif
