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

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_SECURECLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_SECURECLIENTSOCKET__

#include <hotplace/sdk/net/basic/trial/client_socket_prosumer.hpp>
#include <hotplace/sdk/net/basic/trial/secure_prosumer.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client
 * @sample
 */
class secure_client_socket : public client_socket_prosumer {
   public:
    virtual ~secure_client_socket();

    tls_session* get_session();
    tls_version_t get_version();
    virtual bool support_tls();
    secure_prosumer* get_secure_prosumer();

   protected:
    secure_client_socket(tls_version_t spec = tls_12);

    virtual return_t do_handshake();
    virtual return_t do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t do_secure();
    virtual return_t do_shutdown();
    virtual return_t do_send(binary_t& bin);

    tls_session _session;
    tls_version_t _spec;

    secure_prosumer _secure;
};

}  // namespace net
}  // namespace hotplace

#endif
