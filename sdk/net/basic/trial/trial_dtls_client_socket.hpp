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

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALDTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALDTLSCLIENTSOCKET__

#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   DTLS client socket
 * @sample
 *          trial_dtls_client_socket cli;
 *          ret = cli.open(&addr, addr, port)
 *          if (success == ret) {
 *              ret = cli.sendto(msg.c_str(), msg.size(), &cbsent, , (sockaddr*)&addr, sizeof(addr));
 *              if (success == ret) {
 *                  cli.recvfrom(buf, bufsize, &cbread, (sockaddr*)&addr, &addrlen);
 *              }
 *          }
 */
class trial_dtls_client_socket : public secure_client_socket {
   public:
    trial_dtls_client_socket(tls_version_t spec = dtls_12);
    virtual ~trial_dtls_client_socket();

    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual int socket_type();

    virtual uint32 get_scheme();

   protected:
    virtual return_t do_send(binary_t& bin);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
