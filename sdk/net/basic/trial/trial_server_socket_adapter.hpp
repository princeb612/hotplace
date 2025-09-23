/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALSERVERSOCKETADAPTER__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALSERVERSOCKETADAPTER__

#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS server socket adapter
 * @sa      http_server_builder
 */
class trial_server_socket_adapter : public server_socket_adapter {
   public:
    trial_server_socket_adapter();
    virtual ~trial_server_socket_adapter();

    virtual uint32 get_adapter_scheme(uint32 scheme, return_t& retcode);

    virtual return_t enable_alpn(const char* prot);

   protected:
   private:
};

}  // namespace net
}  // namespace hotplace

#endif
