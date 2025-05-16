/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SDK_UDPCLIENTSOCKET2__
#define __HOTPLACE_SDK_NET_BASIC_SDK_UDPCLIENTSOCKET2__

#include <sdk/net/basic/sdk/client_socket_prosumer.hpp>

namespace hotplace {
namespace net {

class udp_client_socket2 : public client_socket_prosumer {
   public:
    udp_client_socket2();
    virtual int socket_type();
};

}  // namespace net
}  // namespace hotplace

#endif
