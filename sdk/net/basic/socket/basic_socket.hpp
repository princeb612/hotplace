/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SOCKET__
#define __HOTPLACE_SDK_NET_BASIC_SOCKET__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/basic/tls/types.hpp>
#include <sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 */
class basic_socket {
   public:
    basic_socket() { _shared.make_share(this); }
    virtual ~basic_socket() {}

    /**
     * @brief   close
     * @param   socket_t        sock            [IN] see connect
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @return  error code (see error.hpp)
     * @remarks
     *          tls_svr_sock.accept (listen_socket, &cli_socket, &tls_context, &sockaddr, &sockaddrlen);
     *          // client connection established...
     *          // ...
     *          // socket closed
     *          tls_svr_sock.close (cli_socket, tls_context);
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle) {
        return_t ret = errorcode_t::success;

        __try2 {
            if (INVALID_SOCKET == sock) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            ret = close_socket(sock, true, 0);
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }

    virtual bool support_tls() { return false; } /* override */
    virtual int socket_type() { return 0; }      /* override */

    int addref() { return _shared.addref(); }
    int release() { return _shared.delref(); }

   protected:
   private:
    t_shared_reference<basic_socket> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
