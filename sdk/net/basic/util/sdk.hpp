/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_UTIL_SDK__
#define __HOTPLACE_SDK_NET_BASIC_UTIL_SDK__

#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   dtls cookie
 * @remarks hmac("sha256", app_instance_nonce, (sockaddr*)&address, sizeof(address));
 */
return_t generate_cookie_sockaddr(binary_t& cookie, const sockaddr* addr, socklen_t addrlen);

}  // namespace net
}  // namespace hotplace

#endif
