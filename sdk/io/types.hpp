
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_TYPES__
#define __HOTPLACE_SDK_IO_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {
namespace io {

#if defined __linux__
typedef int socket_t;
#elif defined _WIN32 || defined _WIN64
typedef SOCKET socket_t;
#endif

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_storage sockaddr_storage_t;
typedef struct linger linger_t;

#define NET_DEFAULT_TIMEOUT 10
typedef struct linger linger_t;

}  // namespace io
}  // namespace hotplace

#endif
