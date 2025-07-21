/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TYPES__
#define __HOTPLACE_SDK_NET_TYPES__

#if defined __linux__

#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#if __GLIBC_MINOR__ >= 3
#include <sys/epoll.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#elif defined _WIN32 || defined _WIN64

#include <sdk/base/system/windows/types.hpp>

#endif

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/nostd/range.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/io/system/socket.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

//

}  // namespace net
}  // namespace hotplace

#endif
