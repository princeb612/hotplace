/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_UDPCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_UDPCLIENTSOCKET__

#include <sdk/io/system/socket.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 */
class udp_client_socket : public client_socket {
   public:
    udp_client_socket();

    /**
     * @brief   open
     * @param   socket_t*       sock [out]
     * @param   tls_context_t*  tls_handle [out] ignore, see tls_client_socket
     * @param   const char*     address [in]
     * @param   uint16          port [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t open(socket_t* sock, tls_context_t* tls_handle, const char* address, uint16 port);
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         size_read       [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* size_read);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] ignore, see tls_client_socket
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         size_sent       [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent);
    /**
     * @brief   sendto
     */
    virtual return_t sendto(socket_t sock, tls_context_t* tls_handle, sockaddr_storage_t* sock_storage, const char* ptr_data, size_t size_data,
                            size_t* size_sent);

    virtual int socket_type();

   private:
    sockaddr_storage_t _sock_storage;
};

}  // namespace net
}  // namespace hotplace

#endif
