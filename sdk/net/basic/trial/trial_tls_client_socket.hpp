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

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALTLSCLIENTSOCKET__

#include <sdk/net/basic/trial/secure_client_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client
 * @sample
 *          // sketch
 *          trial_tls_client_socket cli;
 *          ret = cli.connect(addr, port, tmo);
 *          if (success == ret) {
 *              ret = cli.send(msg.c_str(), msg.size(), &cbsent);
 *              if (success == ret) {
 *                  cli.read(buf, bufsize, &cbread);
 *              }
 *          }
 */
class trial_tls_client_socket : public secure_client_socket {
   public:
    trial_tls_client_socket(tls_version_t version = tls_13);

    virtual return_t send(const char *ptr_data, size_t size_data, size_t *cbsent);

    virtual int socket_type();

   protected:
    virtual return_t do_send(binary_t &bin);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
