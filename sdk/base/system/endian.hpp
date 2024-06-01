/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_ENDIAN__
#define __HOTPLACE_SDK_BASE_SYSTEM_ENDIAN__

#include <sdk/base/types.hpp>

namespace hotplace {

#if defined __GNUC__

#if defined __MINGW32__

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

#else  // __GNUC__

#define LITTLE_ENDIANESS 0x41424344UL
#define BIG_ENDIANESS 0x44434241UL
#define PDP_ENDIANESS 0x42414443UL
#define ENDIAN_ORDER ('ABCD')

#if ENDIAN_ORDER == LITTLE_ENDIANESS
#define __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN
#define LITTLE_ENDIAN
#elif ENDIAN_ORDER == BIG_ENDIANESS
#define __BIG_ENDIAN__
#define __BIG_ENDIAN
#define BIG_ENDIAN
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
 * readability
 */
#define hton16 htons
#define ntoh16 ntohs

#define hton32 htonl
#define ntoh32 ntohl

/**
 * host order to network order (64bits)
 */
uint64 hton64(uint64 value);
uint64 ntoh64(uint64 value);

#if defined __SIZEOF_INT128__

/**
 * host order to network order (128bits)
 */
uint128 hton128(uint128 value);
uint128 ntoh128(uint128 value);

#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define static_inline_convert_endian(T) \
    static inline T convert_endian(T value) { return value; }
static_inline_convert_endian(uint32);
static_inline_convert_endian(uint64);
static_inline_convert_endian(uint128);
static_inline_convert_endian(int32);
static_inline_convert_endian(int64);
static_inline_convert_endian(int128);

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline uint16 convert_endian(uint16 value) { return (((((uint16)(value)&0xFF)) << 8) | (((uint16)(value)&0xFF00) >> 8)); }
static inline uint16 convert_endian(int16 value) { return (((((int16)(value)&0xFF)) << 8) | (((int16)(value)&0xFF00) >> 8)); }

#define static_inline_convert_endian(T1, T2)    \
    static inline T1 convert_endian(T1 value) { \
        union temp {                            \
            T1 value;                           \
            struct {                            \
                T2 high;                        \
                T2 low;                         \
            } p;                                \
        };                                      \
        union temp x, y;                        \
        x.value = value;                        \
        y.p.high = convert_endian(x.p.low);     \
        y.p.low = convert_endian(x.p.high);     \
        return y.value;                         \
    }

static_inline_convert_endian(uint32, uint16);
static_inline_convert_endian(uint64, uint32);
static_inline_convert_endian(uint128, uint64);
static_inline_convert_endian(int32, int16);
static_inline_convert_endian(int64, int32);
static_inline_convert_endian(int128, int64);

#else
//
#endif

}  // namespace hotplace

#endif
