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

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

/*
 * host order to network order (64bits)
 */
uint64 htonll (uint64 value);
uint64 ntohll (uint64 value);

#if defined __SIZEOF_INT128__

/*
 * atoi (int128)
 */
int128 atoi128 (std::string const & in);

typedef union _ipaddr_byteorder {
    uint128 t128;
    uint32 t32[4];
} ipaddr_byteorder;
/*
 * host order to network order (128bits)
 */
uint128 hton128 (uint128 value);
uint128 ntoh128 (uint128 value);

#endif

}
}  // namespace

#endif
