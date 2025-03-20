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

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 */
class basic_socket {
   public:
    virtual ~basic_socket();

    /**
     * @override
     * @return
     *          tcp_server_socket, udp_server_socket
     *          tcp_client_socket, udp_client_socket
     *            return false
     *          tls_server_socket, dtls_server_socket
     *          tls_server_socket, dtls_server_socket
     *            return true
     */
    virtual bool support_tls(); /* override */
    /**
     * @override
     * @return
     *          tcp_server_socket, tls_server_socket
     *          tcp_client_socket, tls_client_socket
     *            return SOCK_STREAM
     *          udp_server_socket, dtls_server_socket
     *          udp_client_socket, dtls_client_socket
     *            return SOCK_DGRAM
     */
    virtual int socket_type(); /* override */

    int addref();
    int release();

   protected:
    basic_socket();

   private:
    t_shared_reference<basic_socket> _shared;
    socket_t _fd;
};

}  // namespace net
}  // namespace hotplace

#endif
