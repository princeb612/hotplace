/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTCPCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTCPCLIENTSOCKET__

#include <hotplace/sdk/net/basic/trial/client_socket_prosumer.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TCP client socket
 */
class trial_tcp_client_socket : public client_socket_prosumer {
   public:
    trial_tcp_client_socket();
    virtual ~trial_tcp_client_socket();

    virtual int socket_type();
};

}  // namespace net
}  // namespace hotplace

#endif
