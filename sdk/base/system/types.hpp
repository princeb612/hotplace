/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TYPES__
#define __HOTPLACE_SDK_BASE_SYSTEM_TYPES__

#include <sdk/base/error.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

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

/**
 * @brief   uint24 utility function (0 to 0x00ffffff)
 * @see     RFC 7540 4. HTTP Frames, Figure 1: Frame Layout
 *          b24_i32 - from 24bits byte stream to 32 bit integer
 *          i32_b24 - from 32 bit integer to 24bits byte stream
 */
return_t b24_i32(byte_t const* p, uint8 len, uint32& value);
return_t i32_b24(byte_t* p, uint8 len, uint32 value);

typedef struct _uint24_t {
    byte_t data[3];
} uint24_t;

return_t b24_i32(uint24_t const& u, uint32& value);
return_t i32_b24(uint24_t& u, uint32 value);

}  // namespace hotplace

#endif
