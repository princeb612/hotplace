/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_TLS_DTLSCLIENTSOCKET__

#include <sdk/net/basic/udp_client_socket.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/x509.hpp>

namespace hotplace {
namespace net {

class dtls_client_socket : public udp_client_socket {
   public:
    dtls_client_socket(transport_layer_security* tls);
    virtual ~dtls_client_socket();

    /**
     * @brief   connect
     * @param   socket_t*       sock            [OUT]
     * @param   tls_context_t** tls_handle      [OUT]
     * @param   const char*     address         [IN]
     * @param   uint16          port            [IN]
     * @param   uint32          timeout         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return  error code (see error.hpp)
     *          if return errorcode_t::more_data, call more member function
     *          ret = cli.read (sock, handle, buf, sizeof (buf), &sizeread);
     *          printf ("%.*s\n", (int) sizeread, buf);
     *          while (errorcode_t::more_data == ret) {
     *              ret = cli.more (sock, handle, buf, sizeof (buf), &sizeread);
     *              printf ("%.*s\n", (int) sizeread, buf);
     *          }
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief read more
     * @param socket_t          sock
     * @param tls_context_t*    tls_handle
     * @param char*             ptr_data
     * @param size_t            size_data
     * @param size_t*           cbread
     * @return
     *      errorcode_t::pending   no data ready
     *      errorcode_t::more_data more data
     */
    virtual return_t more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual bool support_tls();

    int addref();
    int release();

   protected:
    transport_layer_security* _tls;
    t_shared_reference<dtls_client_socket> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
