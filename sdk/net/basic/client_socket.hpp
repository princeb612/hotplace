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

#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 * @sa      class tls_client_socket : public tcp_client_socket
 */
class tcp_client_socket {
   public:
    tcp_client_socket();
    virtual ~tcp_client_socket();

    /**
     * @brief   connect
     * @param   socket_t*       sock            [OUT]
     * @param   tls_context_t** tls_handle      [OUT]
     * @param   const char*     address         [IN]
     * @param   uint16          port            [IN]
     * @param   uint32          timeout         [IN]
     * @return error code (see error.hpp)
     */
    virtual return_t connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   close
     * @param   socket_t        sock            [IN] see connect
     * @param   tls_context_t*  tls_handle      [IN]
     * @return error code (see error.hpp)
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);

    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return error code (see error.hpp)
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         size_sent       [OUT]
     * @return error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent);

    bool support_tls();

    tcp_client_socket& set_ttl(uint32 milliseconds);
    uint32 get_ttl();

   private:
    uint32 _ttl;  // msec, default 1,000 msec (1 sec)
};

}  // namespace net
}  // namespace hotplace

#endif
