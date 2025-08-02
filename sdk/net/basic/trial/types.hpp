/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      insecure simple implementation to understand TLS
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TYPES__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TYPES__

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

struct socket_buffer_t {
    basic_stream buffer;
    sockaddr_storage_t addr;  // UDP

    socket_buffer_t() { memset(&addr, 0, sizeof(addr)); }
};

}  // namespace net
}  // namespace hotplace

#endif
