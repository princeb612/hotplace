/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALQUICCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALQUICCLIENTSOCKET__

#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   QUIC server socket
 */
class trial_quic_client_socket : public secure_client_socket {
   public:
    trial_quic_client_socket();
    virtual ~trial_quic_client_socket();

    virtual uint32 get_scheme();

   protected:
   private:
};

}  // namespace net
}  // namespace hotplace

#endif
