/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_CLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_CLIENTSOCKET__

#include <sdk/io/system/socket.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
using namespace io;
namespace net {

/**
 * @brief   client socket
 */
class client_socket {
   public:
    client_socket() : _wto(1000) {}
    virtual ~client_socket() {}

    /**
     * @brief   connect
     * @param   socket_t*       sock            [OUT]
     * @param   tls_context_t** tls_handle      [OUT] ignore, see tls_client_socket
     * @param   const char*     address         [IN]
     * @param   uint16          port            [IN]
     * @param   uint32          timeout         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) { return errorcode_t::success; }
    /**
     * @brief   close
     * @param   socket_t        sock            [IN] see connect
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @return  error code (see error.hpp)
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

    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) { return errorcode_t::success; }

    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         size_sent       [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent) { return errorcode_t::success; }

    bool support_tls() { return false; }

    void set_wto(uint32 milliseconds) {
        if (milliseconds) {
            _wto = milliseconds;
        }
    }
    uint32 get_wto() { return _wto; }

   protected:
    uint32 _wto;  // msec, default 1,000 msec (1 sec)
};

}  // namespace net
}  // namespace hotplace

#endif
