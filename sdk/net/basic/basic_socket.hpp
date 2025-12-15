/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_BASICSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_BASICSOCKET__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   basic socket
 * @sa      client_socket, server_socket
 */
class basic_socket {
   public:
    virtual ~basic_socket();

    /**
     * @override
     * @return
     *          naive_tcp_server_socket, naive_udp_server_socket
     *          naive_tcp_client_socket, naive_udp_client_socket
     *            return false
     *          openssl_tls_server_socket, openssl_dtls_server_socket
     *          openssl_tls_server_socket, openssl_dtls_server_socket
     *            return true
     */
    virtual bool support_tls(); /* override */
    /**
     * @override
     * @return
     *          naive_tcp_server_socket, openssl_tls_server_socket
     *          naive_tcp_client_socket, openssl_tls_client_socket
     *            return SOCK_STREAM
     *          naive_udp_server_socket, openssl_dtls_server_socket
     *          naive_udp_client_socket, openssl_dtls_client_socket
     *            return SOCK_DGRAM
     */
    virtual int socket_type(); /* override */

    virtual int addref();
    virtual int release();

    /**
     * @sa      socket_scheme_t
     * @remarks
     *          naive_tcp_client_socket    - socket_scheme_tcp | socket_scheme_client
     *          naive_tcp_server_socket    - socket_scheme_tcp | socket_scheme_server
     *          naive_udp_client_socket    - socket_scheme_udp | socket_scheme_client
     *          naive_udp_server_socket    - socket_scheme_udp | socket_scheme_server
     *          openssl_tls_client_socket  - socket_scheme_tls | socket_scheme_openssl | socket_scheme_client
     *          openssl_tls_server_socket  - socket_scheme_tls | socket_scheme_openssl | socket_scheme_server
     *          openssl_dtls_client_socket - socket_scheme_dtls | socket_scheme_openssl | socket_scheme_client
     *          openssl_dtls_server_socket - socket_scheme_dtls | socket_scheme_openssl | socket_scheme_server
     *          trial_tcp_client_socket    - socket_scheme_tcp | socket_scheme_trial | socket_scheme_client
     *          trial_udp_client_socket    - socket_scheme_udp | socket_scheme_trial | socket_scheme_client
     *          trial_tls_client_socket    - socket_scheme_tls | socket_scheme_trial | socket_scheme_client
     *          trial_tls_server_socket    - socket_scheme_tls | socket_scheme_trial | socket_scheme_server
     *          trial_dtls_client_socket   - socket_scheme_dtls | socket_scheme_trial | socket_scheme_client
     *          trial_dtls_server_socket   - socket_scheme_dtls | socket_scheme_trial | socket_scheme_server
     */
    virtual uint32 get_scheme();

   protected:
    basic_socket();

   private:
    t_shared_reference<basic_socket> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
