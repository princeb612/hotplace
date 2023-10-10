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

namespace hotplace {

#if defined __GNUC__

#if defined __MINGW32__

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN__
#define __BIG_ENDIAN
#define BIG_ENDIAN
#else
#define __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN
#define LITTLE_ENDIAN
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

}  // namespace hotplace

#endif
