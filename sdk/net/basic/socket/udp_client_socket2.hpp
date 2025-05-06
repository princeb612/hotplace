/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_UDPCLIENTSOCKET2__
#define __HOTPLACE_SDK_NET_BASIC_UDPCLIENTSOCKET2__

#include <sdk/net/basic/socket/async_client_socket.hpp>

namespace hotplace {
namespace net {

class udp_client_socket2 : public async_client_socket {
   public:
    udp_client_socket2();
    virtual int socket_type();
};

}  // namespace net
}  // namespace hotplace

#endif
